//! Differential test case definitions for offline, mock-GCS, and live-GCS modes.

use crate::normalize::{CompareRule, NormalizeContext};
use crate::runner::{CaseResult, GsutilRunner, RunOptions};
use std::collections::BTreeMap;
use std::path::Path;
use tempfile::TempDir;

pub use crate::live_cases::run_live_gcs_suite;
pub use crate::mock_cases::run_mock_gcs_suite;

pub(crate) fn matches_filter(
    filter: Option<&str>,
    id: &str,
    category: &str,
    command: &str,
) -> bool {
    let Some(f) = filter else {
        return true;
    };
    let f = f.to_ascii_lowercase();
    id.to_ascii_lowercase().contains(&f)
        || category.to_ascii_lowercase().contains(&f)
        || command.to_ascii_lowercase().contains(&f)
}

/// Snapshot entry capturing regular files (bytes + mode), directories, and symlinks.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DirEntrySnapshot {
    Dir,
    File { bytes: Vec<u8>, mode: u32 },
    Symlink { target: String },
}

/// Snapshot all files, directories, symlinks, and POSIX modes under `root`.
fn snapshot_dir(root: &Path) -> Result<BTreeMap<String, DirEntrySnapshot>, String> {
    let mut map = BTreeMap::new();
    collect_dir(root, root, &mut map)?;
    Ok(map)
}

fn collect_dir(
    base: &Path,
    cur: &Path,
    out: &mut BTreeMap<String, DirEntrySnapshot>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(cur)
        .map_err(|e| format!("failed to read dir {}: {}", cur.display(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("dir entry error: {}", e))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("failed to stat {}: {}", path.display(), e))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            let target = std::fs::read_link(&path)
                .map_err(|e| format!("failed to readlink {}: {}", path.display(), e))?
                .to_string_lossy()
                .into_owned();
            out.insert(rel, DirEntrySnapshot::Symlink { target });
        } else if ft.is_dir() {
            out.insert(rel, DirEntrySnapshot::Dir);
            collect_dir(base, &path, out)?;
        } else if ft.is_file() {
            let bytes = std::fs::read(&path)
                .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o777
            };
            #[cfg(not(unix))]
            let mode = 0o644;
            out.insert(rel, DirEntrySnapshot::File { bytes, mode });
        }
    }
    Ok(())
}

/// Deterministic seeded PRNG (xorshift64) for non-UTF-8 realistic binary test payloads.
pub(crate) fn seeded_random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    };
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        for b in state.to_le_bytes() {
            if out.len() < len {
                out.push(b);
            }
        }
    }
    out
}

/// Run all offline / hermetic differential tests (no network required).
pub fn run_offline_suite(runner: &GsutilRunner, filter: Option<&str>) -> Vec<CaseResult> {
    let mut results = Vec::new();
    let tmp = TempDir::new().expect("create temp dir");
    let empty_boto = tmp.path().join("empty.boto");
    std::fs::write(&empty_boto, "[GSUtil]\nstate_dir = /tmp\n").expect("write boto");

    // Helper for simple stateless CLI cases.
    let mut run_simple = |id: &str,
                          cat: &str,
                          cmd: &str,
                          args: &[&str],
                          stdout_rule: CompareRule,
                          stderr_rule: CompareRule| {
        if !matches_filter(filter, id, cat, cmd) {
            return;
        }
        let opts = RunOptions::new(args.iter().copied()).with_boto_config(&empty_boto);
        let ctx = NormalizeContext::default().with_temp_path(tmp.path().to_string_lossy());
        results.push(runner.run_diff(id, cat, cmd, &opts, &opts, &stdout_rule, &stderr_rule, &ctx));
    };

    // -------------------------------------------------------------------------
    // 1. CLI dispatch, version, global flags, invalid commands & fuzzy matches
    // -------------------------------------------------------------------------
    run_simple(
        "bare_no_args_help",
        "cli_dispatch",
        "dispatch",
        &[],
        CompareRule::ContainsAll(vec!["Available commands:".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "global_help_short_qmark",
        "cli_dispatch",
        "dispatch",
        &["-?"],
        CompareRule::ContainsAll(vec!["Usage:".into()]),
        CompareRule::Ignore,
    );
    run_simple(
        "global_help_double_dash",
        "cli_dispatch",
        "dispatch",
        &["--help"],
        CompareRule::ContainsAll(vec!["Usage:".into()]),
        CompareRule::Ignore,
    );
    run_simple(
        "invalid_o_missing_colon",
        "cli_dispatch",
        "dispatch",
        &["-o", "bad", "version"],
        CompareRule::ContainsAll(vec!["Usage:".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "invalid_o_empty_section",
        "cli_dispatch",
        "dispatch",
        &["-o", ":k=v", "version"],
        CompareRule::ContainsAll(vec!["Usage:".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "invalid_o_empty_key",
        "cli_dispatch",
        "dispatch",
        &["-o", "s:=v", "version"],
        CompareRule::ContainsAll(vec!["Usage:".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "invalid_h_empty_header_name",
        "cli_dispatch",
        "dispatch",
        &["-h", ":v", "version"],
        CompareRule::ContainsAll(vec!["Usage:".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "fuzzy_deprecated_alias_typo",
        "cli_dispatch",
        "dispatch",
        &["getac"],
        CompareRule::Exact,
        CompareRule::ContainsAll(vec![
            "CommandException: Invalid command \"getac\".".into(),
            "Did you mean this?".into(),
            "acl".into(),
        ]),
    );
    run_simple(
        "version_cmd",
        "cli_dispatch",
        "version",
        &["version"],
        CompareRule::Exact,
        CompareRule::Exact,
    );
    run_simple(
        "version_flag_long",
        "cli_dispatch",
        "version",
        &["--version"],
        CompareRule::Exact,
        CompareRule::Exact,
    );
    run_simple(
        "version_flag_short",
        "cli_dispatch",
        "version",
        &["-v"],
        CompareRule::Exact,
        CompareRule::Exact,
    );
    run_simple(
        "version_long_details",
        "cli_dispatch",
        "version",
        &["version", "-l"],
        CompareRule::ContainsAll(vec![
            "gsutil version:".into(),
            "config path(s):".into(),
            "gsutil path:".into(),
        ]),
        CompareRule::Exact,
    );
    run_simple(
        "invalid_command",
        "cli_dispatch",
        "dispatch",
        &["boguscmd"],
        CompareRule::Exact,
        CompareRule::Exact,
    );
    run_simple(
        "invalid_command_fuzzy_suggestion",
        "cli_dispatch",
        "dispatch",
        &["versin"],
        CompareRule::Exact,
        CompareRule::ContainsAll(vec![
            "CommandException: Invalid command \"versin\".".into(),
            "Did you mean this?".into(),
            "version".into(),
        ]),
    );
    run_simple(
        "invalid_global_flag",
        "cli_dispatch",
        "dispatch",
        &["-z", "ls"],
        CompareRule::Exact,
        CompareRule::Exact,
    );
    run_simple(
        "missing_args_cp",
        "cli_dispatch",
        "cp",
        &["cp"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Usage:".into(), "gsutil help cp".into()],
        },
    );
    run_simple(
        "missing_args_mb",
        "cli_dispatch",
        "mb",
        &["mb"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Usage:".into(), "gsutil help mb".into()],
        },
    );
    run_simple(
        "missing_args_rm",
        "cli_dispatch",
        "rm",
        &["rm"],
        CompareRule::Exact,
        CompareRule::Exact,
    );
    run_simple(
        "missing_args_stat",
        "cli_dispatch",
        "stat",
        &["stat"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Usage:".into(), "gsutil help stat".into()],
        },
    );
    run_simple(
        "missing_args_cat",
        "cli_dispatch",
        "cat",
        &["cat"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Usage:".into(), "gsutil help cat".into()],
        },
    );
    run_simple(
        "missing_args_hash",
        "cli_dispatch",
        "hash",
        &["hash"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Usage:".into(), "gsutil help hash".into()],
        },
    );
    run_simple(
        "missing_args_mv",
        "cli_dispatch",
        "mv",
        &["mv"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Usage:".into(), "gsutil help mv".into()],
        },
    );
    run_simple(
        "missing_args_rsync",
        "cli_dispatch",
        "rsync",
        &["rsync"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Usage:".into(), "gsutil help rsync".into()],
        },
    );

    // -------------------------------------------------------------------------
    // 2. Help system (top-level, command, subcommand, aliases, invalid topics)
    // -------------------------------------------------------------------------
    run_simple(
        "help_noargs",
        "help",
        "help",
        &["help"],
        CompareRule::ContainsAll(vec!["Available commands:".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "help_ls",
        "help",
        "help",
        &["help", "ls"],
        CompareRule::ContainsAll(vec!["ls - List providers, buckets".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "ls_double_dash_help",
        "help",
        "help",
        &["ls", "--help"],
        CompareRule::ContainsAll(vec!["ls - List providers, buckets".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "cp_args_with_help",
        "help",
        "help",
        &["cp", "foo", "bar", "--help"],
        CompareRule::ContainsAll(vec!["cp - Copy files and objects".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "help_web_set_subcommand",
        "help",
        "help",
        &["help", "web", "set"],
        CompareRule::ContainsAll(vec!["gsutil web set".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "web_set_double_dash_help",
        "help",
        "help",
        &["web", "set", "--help"],
        CompareRule::ContainsAll(vec!["gsutil web set".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "help_invalid_subcommand",
        "help",
        "help",
        &["help", "web", "asdf"],
        CompareRule::ContainsAll(vec!["help about one of the subcommands".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "help_no_subcommands",
        "help",
        "help",
        &["help", "ls", "asdf"],
        CompareRule::Exact,
        CompareRule::Exact,
    );
    run_simple(
        "help_nonexistent_topic",
        "help",
        "help",
        &["help", "nonexistent-command-xyz"],
        CompareRule::Exact,
        CompareRule::Exact,
    );
    run_simple(
        "help_deprecated_alias_chacl",
        "help",
        "help",
        &["help", "chacl"],
        CompareRule::ContainsAll(vec![
            "DEPRECATION WARNING".into(),
            "alias is deprecated".into(),
        ]),
        CompareRule::Exact,
    );
    run_simple(
        "help_deprecated_alias_getwebcfg",
        "help",
        "help",
        &["help", "getwebcfg"],
        CompareRule::ContainsAll(vec!["DEPRECATION WARNING".into(), "web".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "help_deprecated_alias_enablelogging",
        "help",
        "help",
        &["help", "enablelogging"],
        CompareRule::ContainsAll(vec!["DEPRECATION WARNING".into(), "logging".into()]),
        CompareRule::Exact,
    );
    run_simple(
        "help_deprecated_alias_setversioning",
        "help",
        "help",
        &["help", "setversioning"],
        CompareRule::ContainsAll(vec!["DEPRECATION WARNING".into(), "versioning".into()]),
        CompareRule::Exact,
    );

    // -------------------------------------------------------------------------
    // 3. Offline argument validation
    // -------------------------------------------------------------------------
    run_simple(
        "ls_file_url_rejected",
        "validation_offline",
        "ls",
        &["ls", "file:///tmp/foo"],
        CompareRule::Exact,
        CompareRule::Exact,
    );
    run_simple(
        "ls_invalid_flag",
        "validation_offline",
        "ls",
        &["ls", "-z"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec![
                "Incorrect option(s) specified".into(),
                "gsutil help ls".into(),
            ],
        },
    );
    run_simple(
        "ls_non_ascii_project_id",
        "validation_offline",
        "ls",
        &["ls", "-p", "proj-é", "gs://bucket"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Invalid non-ASCII".into()],
        },
    );
    run_simple(
        "stat_file_url_rejected",
        "validation_offline",
        "stat",
        &["stat", "file:///tmp/abc"],
        CompareRule::Exact,
        CompareRule::Exact,
    );
    run_simple(
        "stat_provider_url_rejected",
        "validation_offline",
        "stat",
        &["stat", "gs://"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec![],
        },
    );
    run_simple(
        "mb_invalid_retention",
        "validation_offline",
        "mb",
        &["mb", "--retention", "1second", "gs://test-bkt-xyz"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Incorrect retention period specified".into()],
        },
    );
    run_simple(
        "mb_invalid_rpo",
        "validation_offline",
        "mb",
        &[
            "mb",
            "-l",
            "nam4",
            "--rpo",
            "incorrect_value",
            "gs://test-bkt-xyz",
        ],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Invalid value for --rpo".into()],
        },
    );
    run_simple(
        "mb_non_ascii_project",
        "validation_offline",
        "mb",
        &["mb", "-p", "ã", "gs://test-bkt-xyz"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Invalid non-ASCII".into()],
        },
    );
    run_simple(
        "rsync_too_few_args",
        "validation_offline",
        "rsync",
        &["rsync", "gs://bucket"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["requires at least 2 arguments".into()],
        },
    );
    run_simple(
        "rsync_too_many_args",
        "validation_offline",
        "rsync",
        &["rsync", "gs://b1", "gs://b2", "gs://b3"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["accepts at most 2 arguments".into()],
        },
    );
    run_simple(
        "rsync_blank_exclude",
        "validation_offline",
        "rsync",
        &["rsync", "-x", "", "gs://b1", "gs://b2"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Invalid blank exclude filter".into()],
        },
    );
    run_simple(
        "rsync_invalid_regex_exclude",
        "validation_offline",
        "rsync",
        &["rsync", "-x", "[", "gs://b1", "gs://b2"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["Invalid exclude filter".into()],
        },
    );
    run_simple(
        "rsync_p_and_a_conflict",
        "validation_offline",
        "rsync",
        &["rsync", "-p", "-a", "public-read", "gs://b1", "gs://b2"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec![
                "Specifying both the -p and -a options together is invalid.".into()
            ],
        },
    );
    run_simple(
        "rsync_j_and_J_conflict",
        "validation_offline",
        "rsync",
        &["rsync", "-j", "html", "-J", "gs://b1", "gs://b2"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec![
                "Specifying both the -j and -J options together is invalid.".into()
            ],
        },
    );

    // -------------------------------------------------------------------------
    // 4. Local `hash` command (exact byte-for-byte parity!)
    // -------------------------------------------------------------------------
    let hash_dir = tmp.path().join("hash_fixtures");
    std::fs::create_dir_all(&hash_dir).expect("mkdir hash_fixtures");
    let f1 = hash_dir.join("sample.txt");
    let f2 = hash_dir.join("empty.txt");
    std::fs::write(&f1, b"123456\n").expect("write sample.txt");
    std::fs::write(&f2, b"").expect("write empty.txt");

    let f1_s = f1.to_string_lossy().into_owned();
    let f2_s = f2.to_string_lossy().into_owned();
    let glob_s = format!("{}/*", hash_dir.display());

    run_simple(
        "hash_default_base64",
        "hash",
        "hash",
        &["hash", &f1_s],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_simple(
        "hash_hex_uppercase_crc_lowercase_md5",
        "hash",
        "hash",
        &["hash", "-h", &f1_s],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_simple(
        "hash_crc32c_only",
        "hash",
        "hash",
        &["hash", "-c", &f1_s],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_simple(
        "hash_md5_only",
        "hash",
        "hash",
        &["hash", "-m", &f1_s],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_simple(
        "hash_both_flags",
        "hash",
        "hash",
        &["hash", "-c", "-m", &f1_s],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_simple(
        "hash_empty_file",
        "hash",
        "hash",
        &["hash", &f2_s],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_simple(
        "hash_wildcard",
        "hash",
        "hash",
        &["hash", &glob_s],
        CompareRule::ContainsAll(vec![
            "Hashes [base64]".into(),
            "Hash (crc32c):".into(),
            "Hash (md5):".into(),
        ]),
        CompareRule::Ignore,
    );
    run_simple(
        "hash_nonexistent_file",
        "hash",
        "hash",
        &["hash", "/nonexistent-gsutil-parity-file-9999"],
        CompareRule::Exact,
        CompareRule::Exact,
    );

    // -------------------------------------------------------------------------
    // 5. Local-to-local cp / mv / rsync with side-effect verification
    // -------------------------------------------------------------------------
    results.extend(run_local_side_effect_cases(runner, &empty_boto, filter));

    // -------------------------------------------------------------------------
    // 6. Security (-D credential redaction) & EPIPE handling
    // -------------------------------------------------------------------------
    if matches_filter(filter, "debug_redacts_proxy_pass", "cli_dispatch", "debug") {
        let secret_boto = tmp.path().join("secret.boto");
        let secret_val = "super_secret_proxy_pw_98765";
        std::fs::write(
            &secret_boto,
            format!("[Boto]\nproxy = proxy.example.com\nproxy_pass = {secret_val}\n[GSUtil]\nstate_dir = /tmp\n"),
        )
        .expect("write secret boto");
        let opts = RunOptions::new(["-D", "version"]).with_boto_config(&secret_boto);
        let ctx = NormalizeContext::default().with_temp_path(tmp.path().to_string_lossy());
        let mut res = runner.run_diff(
            "debug_redacts_proxy_pass",
            "cli_dispatch",
            "debug",
            &opts,
            &opts,
            &CompareRule::ContainsAll(vec!["gsutil version:".into()]),
            &CompareRule::Ignore,
            &ctx,
        );
        if !res.skipped {
            if let Some(ref rust_out) = res.rust_output {
                let combined = format!("{}\n{}", rust_out.stdout, rust_out.stderr);
                if combined.contains(secret_val) {
                    res.passed = false;
                    res.side_effect_error =
                        Some("SECURITY VIOLATION: proxy_pass leaked in -D output!".into());
                } else if !combined.contains("REDACTED") {
                    res.passed = false;
                    res.side_effect_error =
                        Some("expected proxy_pass to appear as REDACTED in -D output".into());
                }
            }
        }
        results.push(res);
    }

    if matches_filter(filter, "epipe_help_exits_zero", "cli_dispatch", "epipe") {
        results.push(run_epipe_case(runner, &empty_boto));
    }

    results
}

fn run_epipe_case(runner: &GsutilRunner, boto_path: &Path) -> CaseResult {
    let id = "epipe_help_exits_zero".to_string();
    let category = "cli_dispatch".to_string();
    let command = "epipe".to_string();
    let args = vec!["help".to_string()];

    if !runner.ref_available() || !runner.rust_available() {
        return CaseResult {
            id,
            category,
            command,
            args,
            passed: false,
            skipped: true,
            skip_reason: Some("ref or rust binary unavailable".into()),
            exit_code_match: false,
            ref_output: None,
            rust_output: None,
            stdout_cmp: None,
            stderr_cmp: None,
            side_effect_error: None,
        };
    }

    let run_closed_pipe = |bin: &Path| -> Result<crate::runner::InvocationOutput, String> {
        use std::io::Read;
        use std::process::{Command, Stdio};
        use std::time::Instant;
        let start = Instant::now();
        let mut child = Command::new(bin)
            .arg("help")
            .env("GSUTIL_NO_BANNER", "true")
            .env("BOTO_CONFIG", boto_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn {}: {}", bin.display(), e))?;
        if let Some(mut stdout) = child.stdout.take() {
            let mut one = [0u8; 1];
            let _ = stdout.read(&mut one);
            drop(stdout); // Immediately close pipe to trigger EPIPE on writer.
        }
        let mut stderr_str = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut stderr_str);
        }
        let status = child
            .wait()
            .map_err(|e| format!("wait {}: {}", bin.display(), e))?;
        Ok(crate::runner::InvocationOutput {
            exit_code: status.code().unwrap_or(-1),
            stdout: String::new(),
            stderr: stderr_str,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    };

    let ref_out = run_closed_pipe(&runner.ref_bin).ok();
    let rust_out = run_closed_pipe(&runner.rust_bin).ok();
    let (exit_match, side_err) = match (&ref_out, &rust_out) {
        (Some(r), Some(u)) => {
            let ec_ok = r.exit_code == u.exit_code && u.exit_code == 0;
            let err = if u.stderr.contains("panicked") || u.stderr.contains("Broken pipe") {
                Some(format!(
                    "rust printed panic/broken-pipe on EPIPE: {:?}",
                    u.stderr
                ))
            } else {
                None
            };
            (ec_ok, err)
        }
        _ => (false, Some("failed to run EPIPE probe".into())),
    };
    let passed = exit_match && side_err.is_none();
    CaseResult {
        id,
        category,
        command,
        args,
        passed,
        skipped: false,
        skip_reason: None,
        exit_code_match: exit_match,
        ref_output: ref_out,
        rust_output: rust_out,
        stdout_cmp: None,
        stderr_cmp: None,
        side_effect_error: side_err,
    }
}

fn run_local_side_effect_cases(
    runner: &GsutilRunner,
    boto_path: &Path,
    filter: Option<&str>,
) -> Vec<CaseResult> {
    let mut out = Vec::new();

    // Case A: local-to-local cp single file
    if matches_filter(filter, "local_cp_single_file", "local_ops", "cp") {
        let ref_dir = TempDir::new().expect("ref dir");
        let rust_dir = TempDir::new().expect("rust dir");
        for d in [&ref_dir, &rust_dir] {
            std::fs::write(d.path().join("src.txt"), b"hello gsutil-rs\n").unwrap();
        }
        let ref_opts = RunOptions::new([
            "cp",
            &ref_dir.path().join("src.txt").to_string_lossy(),
            &ref_dir.path().join("dst.txt").to_string_lossy(),
        ])
        .with_boto_config(boto_path);
        let rust_opts = RunOptions::new([
            "cp",
            &rust_dir.path().join("src.txt").to_string_lossy(),
            &rust_dir.path().join("dst.txt").to_string_lossy(),
        ])
        .with_boto_config(boto_path);
        let ctx = NormalizeContext::default()
            .with_temp_path(ref_dir.path().to_string_lossy())
            .with_temp_path(rust_dir.path().to_string_lossy())
            .strip_ui();
        let mut res = runner.run_diff(
            "local_cp_single_file",
            "local_ops",
            "cp",
            &ref_opts,
            &rust_opts,
            &CompareRule::Exact,
            &CompareRule::Ignore,
            &ctx,
        );
        if !res.skipped && res.passed {
            verify_dir_parity(&mut res, ref_dir.path(), rust_dir.path());
        }
        out.push(res);
    }

    // Case B: local-to-local cp -r directory tree
    if matches_filter(filter, "local_cp_recursive", "local_ops", "cp") {
        let ref_dir = TempDir::new().expect("ref dir");
        let rust_dir = TempDir::new().expect("rust dir");
        for d in [&ref_dir, &rust_dir] {
            std::fs::create_dir_all(d.path().join("src/sub")).unwrap();
            std::fs::write(d.path().join("src/a.txt"), b"alpha").unwrap();
            std::fs::write(d.path().join("src/sub/b.txt"), b"beta").unwrap();
            std::fs::create_dir_all(d.path().join("dst")).unwrap();
        }
        let ref_opts = RunOptions::new([
            "cp",
            "-r",
            &ref_dir.path().join("src").to_string_lossy(),
            &ref_dir.path().join("dst").to_string_lossy(),
        ])
        .with_boto_config(boto_path);
        let rust_opts = RunOptions::new([
            "cp",
            "-r",
            &rust_dir.path().join("src").to_string_lossy(),
            &rust_dir.path().join("dst").to_string_lossy(),
        ])
        .with_boto_config(boto_path);
        let ctx = NormalizeContext::default()
            .with_temp_path(ref_dir.path().to_string_lossy())
            .with_temp_path(rust_dir.path().to_string_lossy())
            .strip_ui();
        let mut res = runner.run_diff(
            "local_cp_recursive",
            "local_ops",
            "cp",
            &ref_opts,
            &rust_opts,
            &CompareRule::Exact,
            &CompareRule::Ignore,
            &ctx,
        );
        if !res.skipped && res.passed {
            verify_dir_parity(&mut res, ref_dir.path(), rust_dir.path());
        }
        out.push(res);
    }

    // Case C: local-to-local rsync -r -d
    if matches_filter(filter, "local_rsync_recursive_delete", "local_ops", "rsync") {
        let ref_dir = TempDir::new().expect("ref dir");
        let rust_dir = TempDir::new().expect("rust dir");
        for d in [&ref_dir, &rust_dir] {
            std::fs::create_dir_all(d.path().join("src/nested")).unwrap();
            std::fs::create_dir_all(d.path().join("dst")).unwrap();
            std::fs::write(d.path().join("src/keep.txt"), b"keep-data").unwrap();
            std::fs::write(d.path().join("src/nested/new.txt"), b"new-data").unwrap();
            std::fs::write(d.path().join("dst/extra.txt"), b"should-be-deleted").unwrap();
        }
        let ref_opts = RunOptions::new([
            "rsync",
            "-r",
            "-d",
            &ref_dir.path().join("src").to_string_lossy(),
            &ref_dir.path().join("dst").to_string_lossy(),
        ])
        .with_boto_config(boto_path);
        let rust_opts = RunOptions::new([
            "rsync",
            "-r",
            "-d",
            &rust_dir.path().join("src").to_string_lossy(),
            &rust_dir.path().join("dst").to_string_lossy(),
        ])
        .with_boto_config(boto_path);
        let ctx = NormalizeContext::default()
            .with_temp_path(ref_dir.path().to_string_lossy())
            .with_temp_path(rust_dir.path().to_string_lossy())
            .strip_ui();
        let mut res = runner.run_diff(
            "local_rsync_recursive_delete",
            "local_ops",
            "rsync",
            &ref_opts,
            &rust_opts,
            &CompareRule::Exact,
            &CompareRule::Ignore,
            &ctx,
        );
        if !res.skipped && res.passed {
            verify_dir_parity(&mut res, ref_dir.path(), rust_dir.path());
        }
        out.push(res);
    }

    out
}

fn verify_dir_parity(res: &mut CaseResult, ref_root: &Path, rust_root: &Path) {
    match (snapshot_dir(ref_root), snapshot_dir(rust_root)) {
        (Ok(ref_snap), Ok(rust_snap)) => {
            if ref_snap != rust_snap {
                res.passed = false;
                let ref_keys: Vec<&String> = ref_snap.keys().collect();
                let rust_keys: Vec<&String> = rust_snap.keys().collect();
                res.side_effect_error = Some(format!(
                    "local filesystem state mismatch:\n  ref files : {:?}\n  rust files: {:?}",
                    ref_keys, rust_keys
                ));
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            res.passed = false;
            res.side_effect_error = Some(e);
        }
    }
}
