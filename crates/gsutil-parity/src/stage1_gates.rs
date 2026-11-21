//! Stage 1 Production Hardening Exit Gates (`--mode stage1`):
//! 1. 200 MiB constant-memory live GCS upload + download (< 64 MiB peak RSS via `wait4` `ru_maxrss`).
//! 2. Cross-process resumable upload crash-and-resume (`fault-resume` -> real `https://` tracker -> `308` probe -> remaining bytes only).
//! 3. Live GCS resumable download recovery from partial `_.gstmp`.
//! 4. `SIGINT` graceful shutdown (`Caught CTRL-C (signal 2) - exiting`, exit 1, zero orphaned processes).

use crate::cases::seeded_random_bytes;
use crate::mock_gcs::MockGcsServer;
use crate::runner::{CaseResult, GsutilRunner, InvocationOutput, RunOptions};
use md5::{Digest, Md5};
use serde_json::json;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Result of running a child process while measuring exact peak RSS via `wait4`.
#[derive(Debug, Clone)]
pub struct MeasuredRun {
    pub output: InvocationOutput,
    pub peak_rss_mib: f64,
}

/// Run a binary and measure exact child peak RSS (`ru_maxrss`) using `libc::wait4` on Unix.
pub fn run_measured_rss(bin: &Path, opts: &RunOptions) -> Result<MeasuredRun, String> {
    let mut cmd = Command::new(bin);
    cmd.args(&opts.args);
    cmd.env("GSUTIL_NO_BANNER", "true");
    cmd.env("LC_ALL", "C.UTF-8");
    cmd.env("TZ", "UTC");
    if let Some(ref boto) = opts.boto_config {
        cmd.env("BOTO_CONFIG", boto);
        cmd.env("BOTO_PATH", boto);
    }
    for (k, v) in &opts.env {
        cmd.env(k, v);
    }
    if let Some(ref cwd) = opts.cwd {
        cmd.current_dir(cwd);
    }
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let start = Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn {}: {}", bin.display(), e))?;

    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();

    let t_out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(ref mut r) = stdout_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });
    let t_err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(ref mut r) = stderr_pipe {
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });

    let pid = child.id() as libc::pid_t;
    let mut status: libc::c_int = 0;
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::wait4(pid, &mut status, 0, &mut rusage) };
    let elapsed_ms = start.elapsed().as_millis() as u64;

    let stdout_bytes = t_out.join().unwrap_or_default();
    let stderr_bytes = t_err.join().unwrap_or_default();

    let exit_code = if rc < 0 {
        -1
    } else if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        -1
    };

    // On Linux `ru_maxrss` is in KiB; convert to MiB.
    let peak_rss_mib = (rusage.ru_maxrss as f64) / 1024.0;

    Ok(MeasuredRun {
        output: InvocationOutput {
            exit_code,
            stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
            stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
            duration_ms: elapsed_ms,
        },
        peak_rss_mib,
    })
}

/// Stream-hash a file on disk using 256 KiB chunks (constant RAM) returning `(crc32c, md5_hex)`.
fn stream_hash_file(path: &Path) -> Result<(u32, String), String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut crc: u32 = 0;
    let mut md5 = Md5::new();
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        crc = crc32c::crc32c_append(crc, &buf[..n]);
        md5.update(&buf[..n]);
    }
    let digest = md5.finalize();
    let md5_hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok((crc, md5_hex))
}

/// Stream-generate a `total_bytes` deterministic binary file without buffering it in RAM.
fn write_streaming_random_file(path: &Path, total_bytes: usize) -> Result<(u32, String), String> {
    let mut f =
        std::fs::File::create(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    let mut state: u64 = 0x57A6_E120_0000_0001;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut remaining = total_bytes;
    let mut crc: u32 = 0;
    let mut md5 = Md5::new();
    while remaining > 0 {
        let chunk_len = remaining.min(buf.len());
        let mut i = 0;
        while i < chunk_len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let bytes = state.to_le_bytes();
            let take = (chunk_len - i).min(8);
            buf[i..i + take].copy_from_slice(&bytes[..take]);
            i += take;
        }
        f.write_all(&buf[..chunk_len])
            .map_err(|e| format!("write: {e}"))?;
        crc = crc32c::crc32c_append(crc, &buf[..chunk_len]);
        md5.update(&buf[..chunk_len]);
        remaining -= chunk_len;
    }
    f.flush().map_err(|e| format!("flush: {e}"))?;
    let digest = md5.finalize();
    let md5_hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok((crc, md5_hex))
}

fn make_gate_result(
    id: &str,
    command: &str,
    args: Vec<String>,
    passed: bool,
    rust_out: Option<InvocationOutput>,
    detail: Option<String>,
) -> CaseResult {
    CaseResult {
        id: id.into(),
        category: "stage1_gates".into(),
        command: command.into(),
        args,
        passed,
        skipped: false,
        skip_reason: None,
        exit_code_match: passed,
        ref_output: None,
        rust_output: rust_out,
        stdout_cmp: None,
        stderr_cmp: None,
        side_effect_error: detail,
    }
}

/// Run all Stage 1 Production Hardening Exit Gates.
pub async fn run_stage1_gates(runner: &GsutilRunner, live_bucket: Option<&str>) -> Vec<CaseResult> {
    let mut results = Vec::new();
    results.push(run_gate_resumable_crash_resume(runner).await);
    results.push(run_gate_sigint(runner).await);
    if let Some(bucket) = live_bucket {
        results.extend(run_gate_200mib_live_rss(runner, bucket));
        results.push(run_gate_live_resumable_download(runner, bucket));
    }
    results
}

/// Gate 2: Fault-injected mid-upload crash -> real `https://` tracker -> `308` resume -> byte parity.
async fn run_gate_resumable_crash_resume(runner: &GsutilRunner) -> CaseResult {
    let id = "stage1_resumable_upload_crash_and_resume";
    let server = match MockGcsServer::start_tls().await {
        Ok(s) => s,
        Err(e) => {
            return make_gate_result(
                id,
                "cp",
                vec![],
                false,
                None,
                Some(format!("failed to start TLS mock: {e}")),
            );
        }
    };
    server.seed_bucket("fault-resume");

    let tmp = TempDir::new().expect("tmpdir");
    let boto = tmp.path().join("resume.boto");
    server.write_boto_config(&boto).expect("write boto");
    let ca_path = tmp.path().join("mock_ca.pem");
    let fake_home = tmp.path().join("home");
    std::fs::create_dir_all(&fake_home).unwrap();
    let adc_path = tmp.path().join("adc.json");
    std::fs::write(
        &adc_path,
        json!({
            "type": "authorized_user",
            "client_id": "mock",
            "client_secret": "mock",
            "refresh_token": "mock",
            "token_uri": format!("{}/oauth2/token", server.base_url()),
        })
        .to_string(),
    )
    .unwrap();

    // 600 KiB payload with 256 KiB chunks -> chunk 1 (256 KiB) commits, chunk 2 hits 503!
    let payload = seeded_random_bytes(0x3080_3080, 600 * 1024);
    let src_file = tmp.path().join("resumable_600k.bin");
    std::fs::write(&src_file, &payload).unwrap();

    let args = vec![
        "-o".into(),
        "GSUtil:resumable_threshold=1K".into(),
        "-o".into(),
        "GSUtil:json_resumable_chunk_size=262144".into(),
        "-o".into(),
        "Boto:num_retries=0".into(),
        "cp".into(),
        src_file.to_string_lossy().into_owned(),
        "gs://fault-resume/resumed.bin".into(),
    ];
    let opts = RunOptions::new(args.clone())
        .with_boto_config(&boto)
        .with_env("GOOGLE_APPLICATION_CREDENTIALS", adc_path.to_string_lossy())
        .with_env("SSL_CERT_FILE", ca_path.to_string_lossy())
        .with_env("CLOUDSDK_CORE_PASS_CREDENTIALS_TO_GSUTIL", "False")
        .with_env("CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE", "false")
        .with_env("CLOUDSDK_CONFIG", fake_home.to_string_lossy())
        .with_env("HOME", fake_home.to_string_lossy());

    // Run 1: must fail mid-upload with exit 1
    let run1 = match runner.run_rust(&opts) {
        Ok(o) => o,
        Err(e) => return make_gate_result(id, "cp", args, false, None, Some(e)),
    };
    if run1.exit_code == 0 {
        return make_gate_result(
            id,
            "cp",
            args,
            false,
            Some(run1),
            Some(
                "expected first run against fault-resume to fail mid-upload (exit 1), got 0".into(),
            ),
        );
    }

    // Check tracker file contains a REAL https://127.0.0.1:... upload URI (NOT "resumable://")!
    let tracker_dir = tmp.path().join("tracker-files");
    let mut found_real_uri = false;
    let mut tracker_contents = String::new();
    if let Ok(entries) = std::fs::read_dir(&tracker_dir) {
        for entry in entries.flatten() {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                tracker_contents.push_str(&text);
                if (text.contains("https://127.0.0.1:") || text.contains("http://127.0.0.1:"))
                    && !text.contains("resumable://")
                {
                    found_real_uri = true;
                }
            }
        }
    }
    if !found_real_uri {
        return make_gate_result(
            id,
            "cp",
            args,
            false,
            Some(run1),
            Some(format!(
                "tracker file in {} did not contain real https://127.0.0.1 upload URI (contents={:?})",
                tracker_dir.display(),
                tracker_contents
            )),
        );
    }

    // Run 2: must query `bytes */614400` -> `308`, upload ONLY remaining bytes (offset >= 262144), and succeed!
    let run2 = match runner.run_rust(&opts) {
        Ok(o) => o,
        Err(e) => return make_gate_result(id, "cp", args, false, None, Some(e)),
    };
    if run2.exit_code != 0 {
        return make_gate_result(
            id,
            "cp",
            args,
            false,
            Some(run2),
            Some("resumed second run failed".into()),
        );
    }

    let st = server.state.lock().expect("lock");
    let saw_probe = st
        .resumable_put_ranges
        .iter()
        .any(|r| r.starts_with("bytes */"));
    let saw_resumed_chunk = st
        .resumable_put_ranges
        .iter()
        .any(|r| r.starts_with("bytes 262144-"));
    let stored = st
        .buckets
        .get("fault-resume")
        .and_then(|b| {
            b.objects
                .iter()
                .find(|o| o.name == "resumed.bin" && !o.deleted)
        })
        .map(|o| o.data.as_slice());

    if !saw_probe || !saw_resumed_chunk {
        return make_gate_result(
            id,
            "cp",
            args,
            false,
            Some(run2),
            Some(format!(
                "server did not observe 308 probe + resumed chunk at 262144; ranges={:?}",
                st.resumable_put_ranges
            )),
        );
    }
    if stored != Some(payload.as_slice()) {
        return make_gate_result(
            id,
            "cp",
            args,
            false,
            Some(run2),
            Some("final resumed object bytes do not match 600 KiB source".into()),
        );
    }

    make_gate_result(id, "cp", args, true, Some(run2), None)
}

/// Gate 4: SIGINT on slow download -> exit 1, exact `Caught CTRL-C (signal 2) - exiting`.
async fn run_gate_sigint(runner: &GsutilRunner) -> CaseResult {
    let id = "stage1_sigint_graceful_exit";
    let server = match MockGcsServer::start_tls().await {
        Ok(s) => s,
        Err(e) => {
            return make_gate_result(
                id,
                "cp",
                vec![],
                false,
                None,
                Some(format!("failed to start TLS mock: {e}")),
            );
        }
    };
    server.seed_bucket("slow-bkt");
    server.seed_object("slow-bkt", "slow.bin", &vec![0x5Au8; 4096 * 100]);

    let tmp = TempDir::new().expect("tmpdir");
    let boto = tmp.path().join("slow.boto");
    server.write_boto_config(&boto).expect("write boto");
    let ca_path = tmp.path().join("mock_ca.pem");
    let fake_home = tmp.path().join("home");
    std::fs::create_dir_all(&fake_home).unwrap();
    let adc_path = tmp.path().join("adc.json");
    std::fs::write(
        &adc_path,
        json!({
            "type": "authorized_user",
            "client_id": "mock",
            "client_secret": "mock",
            "refresh_token": "mock",
            "token_uri": format!("{}/oauth2/token", server.base_url()),
        })
        .to_string(),
    )
    .unwrap();

    let dst = tmp.path().join("slow_dl.bin");
    let args = vec![
        "cp".into(),
        "gs://slow-bkt/slow.bin".into(),
        dst.to_string_lossy().into_owned(),
    ];

    let mut cmd = Command::new(&runner.rust_bin);
    cmd.args(&args)
        .env("GSUTIL_NO_BANNER", "true")
        .env("BOTO_CONFIG", &boto)
        .env("BOTO_PATH", &boto)
        .env("GOOGLE_APPLICATION_CREDENTIALS", &adc_path)
        .env("SSL_CERT_FILE", &ca_path)
        .env("CLOUDSDK_CORE_PASS_CREDENTIALS_TO_GSUTIL", "False")
        .env("CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE", "false")
        .env("CLOUDSDK_CONFIG", &fake_home)
        .env("HOME", &fake_home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let start = Instant::now();
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return make_gate_result(id, "cp", args, false, None, Some(e.to_string())),
    };

    // Wait for download to be in-flight, then send SIGINT.
    tokio::time::sleep(Duration::from_millis(450)).await;
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return make_gate_result(id, "cp", args, false, None, Some(e.to_string())),
    };
    let exit_code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let inv = InvocationOutput {
        exit_code,
        stdout,
        stderr: stderr.clone(),
        duration_ms: start.elapsed().as_millis() as u64,
    };

    let ok = exit_code == 1 && stderr.contains("Caught CTRL-C (signal 2) - exiting");
    let detail = if ok {
        None
    } else {
        Some(format!(
            "expected exit=1 and 'Caught CTRL-C (signal 2) - exiting' on stderr; got exit={}, stderr={:?}",
            exit_code, stderr
        ))
    };
    make_gate_result(id, "cp", args, ok, Some(inv), detail)
}

/// Gate 1: 200 MiB constant-memory live GCS upload + download (< 64 MiB peak RSS).
fn run_gate_200mib_live_rss(runner: &GsutilRunner, bucket: &str) -> Vec<CaseResult> {
    let mut out = Vec::new();
    let bucket_clean = bucket.trim_start_matches("gs://").trim_end_matches('/');
    let run_id = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    let remote = format!("gs://{bucket_clean}/stage1-200m-{run_id}/payload200m.bin");

    let tmp = TempDir::new().expect("tmpdir");
    let src_path = tmp.path().join("payload200m.bin");
    let dl_path = tmp.path().join("payload200m_dl.bin");

    let (src_crc, src_md5) = match write_streaming_random_file(&src_path, 200 * 1024 * 1024) {
        Ok(h) => h,
        Err(e) => {
            out.push(make_gate_result(
                "stage1_200mib_upload_rss",
                "cp",
                vec![],
                false,
                None,
                Some(e),
            ));
            return out;
        }
    };

    // Pre-warm gcloud token cache so `wait4` measures Rust `gsutil`'s own RSS
    // rather than a one-time 72 MiB Python `gcloud auth print-access-token` child.
    let _ = runner.run_rust(&RunOptions::new([
        "-q",
        "ls",
        "-b",
        &format!("gs://{bucket_clean}"),
    ]));

    // Upload 200 MiB & assert peak RSS < 64 MiB
    let up_args = vec![
        "cp".into(),
        src_path.to_string_lossy().into_owned(),
        remote.clone(),
    ];
    let up_res = match run_measured_rss(&runner.rust_bin, &RunOptions::new(up_args.clone())) {
        Ok(m) => {
            eprintln!(
                "[stage1] 200 MiB live upload: exit={}, peak_rss={:.1} MiB (limit < 64.0 MiB), duration={} ms",
                m.output.exit_code, m.peak_rss_mib, m.output.duration_ms
            );
            let ok = m.output.exit_code == 0 && m.peak_rss_mib < 64.0;
            let detail = if ok {
                None
            } else {
                Some(format!(
                    "200 MiB upload failed gate: exit={}, peak_rss={:.1} MiB (limit 64.0 MiB), stderr={:?}",
                    m.output.exit_code, m.peak_rss_mib, m.output.stderr
                ))
            };
            make_gate_result(
                "stage1_200mib_upload_rss",
                "cp",
                up_args,
                ok,
                Some(m.output),
                detail,
            )
        }
        Err(e) => make_gate_result(
            "stage1_200mib_upload_rss",
            "cp",
            up_args,
            false,
            None,
            Some(e),
        ),
    };
    let up_ok = up_res.passed;
    out.push(up_res);

    // Download 200 MiB & assert peak RSS < 64 MiB + exact CRC32C/MD5 match
    let dl_args = vec![
        "cp".into(),
        remote.clone(),
        dl_path.to_string_lossy().into_owned(),
    ];
    let dl_res = if !up_ok {
        make_gate_result(
            "stage1_200mib_download_rss",
            "cp",
            dl_args,
            false,
            None,
            Some("skipped download because 200 MiB upload failed".into()),
        )
    } else {
        match run_measured_rss(&runner.rust_bin, &RunOptions::new(dl_args.clone())) {
            Ok(m) => {
                let hash_ok = stream_hash_file(&dl_path)
                    .map(|(c, md)| c == src_crc && md == src_md5)
                    .unwrap_or(false);
                eprintln!(
                    "[stage1] 200 MiB live download: exit={}, peak_rss={:.1} MiB (limit < 64.0 MiB), hash_ok={}, duration={} ms",
                    m.output.exit_code, m.peak_rss_mib, hash_ok, m.output.duration_ms
                );
                let ok = m.output.exit_code == 0 && m.peak_rss_mib < 64.0 && hash_ok;
                let detail = if ok {
                    None
                } else {
                    Some(format!(
                        "200 MiB download failed gate: exit={}, peak_rss={:.1} MiB (limit 64.0 MiB), hash_ok={}, stderr={:?}",
                        m.output.exit_code, m.peak_rss_mib, hash_ok, m.output.stderr
                    ))
                };
                make_gate_result(
                    "stage1_200mib_download_rss",
                    "cp",
                    dl_args,
                    ok,
                    Some(m.output),
                    detail,
                )
            }
            Err(e) => make_gate_result(
                "stage1_200mib_download_rss",
                "cp",
                dl_args,
                false,
                None,
                Some(e),
            ),
        }
    };
    out.push(dl_res);

    // Cleanup remote 200 MiB object
    let _ = runner.run_rust(&RunOptions::new(["rm", "-f", &remote]));

    out
}

/// Gate 3: Live GCS resumable download recovery from pre-seeded partial `_.gstmp`.
fn run_gate_live_resumable_download(runner: &GsutilRunner, bucket: &str) -> CaseResult {
    let id = "stage1_live_resumable_download_recovery";
    let bucket_clean = bucket.trim_start_matches("gs://").trim_end_matches('/');
    let run_id = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    let remote = format!("gs://{bucket_clean}/stage1-dl-resume-{run_id}/one_mib.bin");

    let tmp = TempDir::new().expect("tmpdir");
    let payload = seeded_random_bytes(0xD00D_1024, 1024 * 1024);
    let src_path = tmp.path().join("one_mib.bin");
    let dl_path = tmp.path().join("one_mib_dl.bin");
    std::fs::write(&src_path, &payload).unwrap();

    // Upload 1 MiB object
    if let Err(e) = runner.run_rust(&RunOptions::new([
        "cp",
        &src_path.to_string_lossy(),
        &remote,
    ])) {
        return make_gate_result(id, "cp", vec![], false, None, Some(e));
    }

    // Pre-seed partial `_.gstmp` with first 256 KiB
    let gstmp_path = tmp.path().join("one_mib_dl.bin_.gstmp");
    std::fs::write(&gstmp_path, &payload[..256 * 1024]).unwrap();

    let args = vec![
        "-o".into(),
        "GSUtil:resumable_threshold=1K".into(),
        "cp".into(),
        remote.clone(),
        dl_path.to_string_lossy().into_owned(),
    ];
    let run = match runner.run_rust(&RunOptions::new(args.clone())) {
        Ok(o) => o,
        Err(e) => {
            let _ = runner.run_rust(&RunOptions::new(["rm", "-f", &remote]));
            return make_gate_result(id, "cp", args, false, None, Some(e));
        }
    };
    let _ = runner.run_rust(&RunOptions::new(["rm", "-f", &remote]));

    let bytes_ok = std::fs::read(&dl_path)
        .map(|b| b == payload)
        .unwrap_or(false);
    let ok = run.exit_code == 0 && bytes_ok;
    let detail = if ok {
        None
    } else {
        Some(format!(
            "live resumable download recovery failed: exit={}, bytes_ok={}, stderr={:?}",
            run.exit_code, bytes_ok, run.stderr
        ))
    };
    make_gate_result(id, "cp", args, ok, Some(run), detail)
}
