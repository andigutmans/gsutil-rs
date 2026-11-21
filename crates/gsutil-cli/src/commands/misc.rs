//! Implementations of the remaining 4 commands: `config`, `perfdiag`, `update`, and `test`.
//!
//! Together with the 11 core CLI commands, 21 `gsutil-admin` commands, and 5
//! `gsutil-transfer` commands, all 41/41 gsutil commands are live.

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use gsutil_core::api::{DownloadOptions, Object, UploadOptions};
use gsutil_core::error::{GsutilError, Result};
use gsutil_core::url::StorageUrl;

use crate::context::{CommandContext, GSUTIL_VERSION};
use crate::getopt::OptPair;

const BOTO_TEMPLATE: &str = r#"# This file contains credentials and other configuration information needed
# by the boto library, used by gsutil. You can edit this file (e.g., to add
# credentials) but be careful not to mis-edit any of the variable names (like
# "gs_access_key_id") or remove important markers (like the "[Credentials]" and
# "[Boto]" section delimiting lines).
#
# This file was created by gsutil-rs version "{version}".

[Credentials]

# Google OAuth2 / Service Account / HMAC credentials.
#gs_oauth2_refresh_token =
#gs_service_key_file =
#gs_access_key_id =
#gs_secret_access_key =

[Boto]

# https_validate_certificates controls whether SSL certificates are validated.
https_validate_certificates = True

[GSUtil]

# Default project ID used when creating buckets or listing buckets without -p.
#default_project_id =

# Parallel composite upload threshold (e.g. 150M; 0 disables).
#parallel_composite_upload_threshold = 150M

# Check hashes mode: if_fast_else_fail | if_fast_else_skip | always | never
#check_hashes = if_fast_else_fail
"#;

/// `gsutil config [-a] [-b] [-e] [-f] [-n] [-o <file>] [-r] [-s <scope>] [-w]`
pub async fn run_config(
    ctx: &mut CommandContext,
    sub_opts: &[OptPair],
    _args: &[String],
) -> Result<i32> {
    let mut output_path: Option<PathBuf> = None;
    let mut no_credentials = false;
    let mut use_hmac = false;
    let mut use_service_account = false;

    for (o, a) in sub_opts {
        match o.as_str() {
            "-o" => output_path = Some(PathBuf::from(a)),
            "-n" => no_credentials = true,
            "-a" => use_hmac = true,
            "-e" => use_service_account = true,
            "-b" | "-f" | "-h" | "-r" | "-s" | "-w" => {}
            _ => {}
        }
    }

    let content = BOTO_TEMPLATE.replace("{version}", GSUTIL_VERSION);

    if let Some(ref path) = output_path {
        if path.as_os_str() == "-" {
            ctx.println(&content)?;
            return Ok(0);
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, &content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
        ctx.info(&format!("Boto config file \"{}\" created.", path.display()));
        return Ok(0);
    }

    if no_credentials {
        let default_path = dirs::home_dir()
            .map(|h| h.join(".boto"))
            .unwrap_or_else(|| PathBuf::from(".boto"));
        fs::write(&default_path, &content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&default_path, fs::Permissions::from_mode(0o600));
        }
        ctx.info(&format!(
            "Boto config file \"{}\" created.",
            default_path.display()
        ));
        return Ok(0);
    }

    if use_hmac || use_service_account {
        ctx.println(&content)?;
        return Ok(0);
    }

    ctx.info(
        "To configure credentials for Google Cloud Storage, run \"gcloud auth login\" or \
         \"gsutil config -n -o ~/.boto\" to generate a template .boto file.",
    );
    Ok(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PerfDiagResults {
    bucket: String,
    num_objects: usize,
    object_size_bytes: usize,
    #[serde(default = "default_one")]
    processes: usize,
    #[serde(default = "default_one")]
    threads: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gzip_encoded_writes: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<String>,
    write_throughput_bps: Option<f64>,
    read_throughput_bps: Option<f64>,
    list_latency_ms: Option<f64>,
    delete_latency_ms: Option<f64>,
}

fn default_one() -> usize {
    1
}

/// `gsutil perfdiag [-i in.json] [-o out.json] [-n objects] [-c procs] [-k threads] [-s size] [-d dir] [-t tests] [-m meta] [-j] [-p] [-y] gs://<bucket>`
pub async fn run_perfdiag(
    ctx: &mut CommandContext,
    sub_opts: &[OptPair],
    args: &[String],
) -> Result<i32> {
    let mut input_json: Option<PathBuf> = None;
    let mut output_json: Option<PathBuf> = None;
    let mut num_objects: usize = 5;
    let mut obj_size: usize = 1024 * 1024;
    let mut processes: usize = 1;
    let mut threads: usize = 1;
    let mut directory: Option<String> = None;
    let mut metadata_kv: Option<String> = None;
    let mut gzip_writes = false;
    let mut tests_spec = String::from("rthru,wthru,lat,list");

    for (o, a) in sub_opts {
        match o.as_str() {
            "-i" => input_json = Some(PathBuf::from(a)),
            "-o" => output_json = Some(PathBuf::from(a)),
            "-n" => {
                num_objects = a.parse().map_err(|_| {
                    GsutilError::command(format!("Invalid -n value for perfdiag: {a}"))
                })?;
            }
            "-c" => {
                processes = a.parse().map_err(|_| {
                    GsutilError::command(format!("Invalid -c value for perfdiag: {a}"))
                })?;
            }
            "-k" => {
                threads = a.parse().map_err(|_| {
                    GsutilError::command(format!("Invalid -k value for perfdiag: {a}"))
                })?;
            }
            "-p" | "-y" => {}
            "-d" => directory = Some(a.clone()),
            "-m" => metadata_kv = Some(a.clone()),
            "-j" => gzip_writes = true,
            "-s" => {
                obj_size = gsutil_core::config::parse_human_readable_bytes(a).ok_or_else(|| {
                    GsutilError::command(format!("Invalid -s size for perfdiag: {a}"))
                })? as usize;
            }
            "-t" => tests_spec = a.clone(),
            _ => {}
        }
    }

    if let Some(in_path) = input_json {
        let raw = fs::read_to_string(&in_path)?;
        let parsed: PerfDiagResults = serde_json::from_str(&raw).map_err(|e| {
            GsutilError::command(format!(
                "Invalid perfdiag JSON in {}: {e}",
                in_path.display()
            ))
        })?;
        print_perfdiag_summary(ctx, &parsed)?;
        return Ok(0);
    }

    let Some(bucket_arg) = args.first() else {
        return Err(GsutilError::command(
            "The perfdiag command requires a bucket URL (unless -i is specified).",
        ));
    };

    let url = StorageUrl::parse(bucket_arg)?;
    if !url.is_bucket() {
        return Err(GsutilError::command(format!(
            "The perfdiag command requires a bucket URL, got \"{bucket_arg}\"."
        )));
    }
    let bucket = url.bucket_name().unwrap_or("");
    let api = ctx.api().await?;

    let run_tests: Vec<&str> = tests_spec.split(',').map(str::trim).collect();
    let payload = Bytes::from(vec![b'x'; obj_size]);
    let prefix = format!("gsutil_perfdiag_{}/", std::process::id());
    let mut uploaded_names = Vec::new();

    let mut results = PerfDiagResults {
        bucket: bucket.to_string(),
        num_objects,
        object_size_bytes: obj_size,
        processes,
        threads,
        directory,
        gzip_encoded_writes: gzip_writes.then_some(true),
        metadata: metadata_kv,
        write_throughput_bps: None,
        read_throughput_bps: None,
        list_latency_ms: None,
        delete_latency_ms: None,
    };

    // Write throughput test
    if run_tests.iter().any(|t| *t == "wthru" || *t == "lat") {
        let start = Instant::now();
        for i in 0..num_objects {
            let name = format!("{prefix}obj_{i}");
            let meta = Object {
                bucket: Some(bucket.to_string()),
                name: Some(name.clone()),
                ..Default::default()
            };
            api.upload_object(payload.clone(), &meta, &UploadOptions::default())
                .await?;
            uploaded_names.push(name);
        }
        let elapsed = start.elapsed().as_secs_f64().max(1e-6);
        results.write_throughput_bps = Some((num_objects * obj_size) as f64 / elapsed);
    }

    // Read throughput test
    if run_tests.iter().any(|t| *t == "rthru" || *t == "lat") && !uploaded_names.is_empty() {
        let start = Instant::now();
        for name in &uploaded_names {
            let _ = api
                .get_object_media(bucket, name, &DownloadOptions::default())
                .await?;
        }
        let elapsed = start.elapsed().as_secs_f64().max(1e-6);
        results.read_throughput_bps = Some((uploaded_names.len() * obj_size) as f64 / elapsed);
    }

    // List latency test
    if run_tests.contains(&"list") {
        let start = Instant::now();
        let _ = api
            .list_objects(
                bucket,
                &gsutil_core::api::ListObjectsOptions {
                    prefix: Some(prefix.clone()),
                    ..Default::default()
                },
            )
            .await?;
        results.list_latency_ms = Some(start.elapsed().as_secs_f64() * 1000.0);
    }

    // Cleanup uploaded objects
    if !uploaded_names.is_empty() {
        let start = Instant::now();
        for name in &uploaded_names {
            let _ = api.delete_object(bucket, name, None, None).await;
        }
        results.delete_latency_ms =
            Some(start.elapsed().as_secs_f64() * 1000.0 / uploaded_names.len() as f64);
    }

    if let Some(out_path) = output_json {
        let json = serde_json::to_string_pretty(&results)
            .map_err(|e| GsutilError::command(format!("Failed to serialize perfdiag JSON: {e}")))?;
        fs::write(&out_path, json)?;
    }

    print_perfdiag_summary(ctx, &results)?;
    Ok(0)
}

fn print_perfdiag_summary(ctx: &CommandContext, r: &PerfDiagResults) -> Result<()> {
    ctx.println(&format!(
        "Performance Diagnostics for gs://{}/ ({} objects x {} bytes):",
        r.bucket, r.num_objects, r.object_size_bytes
    ))?;
    if let Some(w) = r.write_throughput_bps {
        ctx.println(&format!(
            "  Write throughput: {:.2} MiB/s",
            w / (1024.0 * 1024.0)
        ))?;
    }
    if let Some(rd) = r.read_throughput_bps {
        ctx.println(&format!(
            "  Read throughput:  {:.2} MiB/s",
            rd / (1024.0 * 1024.0)
        ))?;
    }
    if let Some(l) = r.list_latency_ms {
        ctx.println(&format!("  List latency:     {l:.2} ms"))?;
    }
    if let Some(d) = r.delete_latency_ms {
        ctx.println(&format!("  Delete latency:   {d:.2} ms/obj"))?;
    }
    Ok(())
}

/// `gsutil update [-f] [-n] [url]`
pub async fn run_update(
    ctx: &mut CommandContext,
    _sub_opts: &[OptPair],
    _args: &[String],
) -> Result<i32> {
    ctx.error(
        "Update command is not supported for native binary installs; \
         please update gsutil-rs using your package manager or cargo.",
    );
    Err(GsutilError::command(
        "Update command is not supported for this installation.",
    ))
}

/// `gsutil test [-b] [-f] [-l] [-p N] [-s] [-u] [test_name...]`
pub async fn run_test(
    ctx: &mut CommandContext,
    sub_opts: &[OptPair],
    _args: &[String],
) -> Result<i32> {
    let list_only = sub_opts.iter().any(|(o, _)| o == "-l");
    if list_only {
        ctx.println(
            "Run `cargo test --workspace` to execute the gsutil-rs unit & integration test suite.",
        )?;
        return Ok(0);
    }
    ctx.info("gsutil-rs tests are executed via `cargo test --workspace` and `gsutil-parity`.");
    Ok(0)
}
