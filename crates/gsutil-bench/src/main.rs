//! `gsutil-bench` CLI binary comparing `/usr/bin/gsutil` vs `gsutil-rs`.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use gsutil_bench::mock_server::BenchMockGcs;
use gsutil_bench::{
    compare, measure_command, render_markdown_report, summarize, BenchmarkComparison,
};

struct CliArgs {
    python_bin: PathBuf,
    rust_bin: PathBuf,
    iterations: usize,
    suite: String,
    markdown_out: Option<PathBuf>,
    json_out: Option<PathBuf>,
}

fn parse_args() -> CliArgs {
    let mut python_bin = PathBuf::from("/usr/bin/gsutil");
    let default_rust = if Path::new("target/release/gsutil").exists() {
        PathBuf::from("target/release/gsutil")
    } else {
        PathBuf::from("target/debug/gsutil")
    };
    let mut rust_bin = default_rust;
    let mut iterations = 5usize;
    let mut suite = "all".to_string();
    let mut markdown_out = None;
    let mut json_out = None;

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--python-bin" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    python_bin = PathBuf::from(v);
                }
            }
            "--rust-bin" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    rust_bin = PathBuf::from(v);
                }
            }
            "--iterations" | "-n" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    iterations = v.parse().unwrap_or(5).max(1);
                }
            }
            "--suite" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    suite = v.clone();
                }
            }
            "--markdown" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    markdown_out = Some(PathBuf::from(v));
                }
            }
            "--json" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    json_out = Some(PathBuf::from(v));
                }
            }
            _ => {}
        }
        i += 1;
    }

    CliArgs {
        python_bin,
        rust_bin,
        iterations,
        suite,
        markdown_out,
        json_out,
    }
}

fn run_pair(
    cfg: &CliArgs,
    category: &str,
    name: &str,
    args: &[String],
    env_vars: &BTreeMap<String, String>,
    bytes_processed: Option<u64>,
) -> BenchmarkComparison {
    run_pair_split(cfg, category, name, args, args, env_vars, bytes_processed)
}

fn run_pair_split(
    cfg: &CliArgs,
    category: &str,
    name: &str,
    py_args: &[String],
    rs_args: &[String],
    env_vars: &BTreeMap<String, String>,
    bytes_processed: Option<u64>,
) -> BenchmarkComparison {
    let py_stats = if cfg.python_bin.exists() {
        let mut runs = Vec::with_capacity(cfg.iterations);
        for _ in 0..cfg.iterations {
            if let Ok(m) = measure_command(&cfg.python_bin, py_args, env_vars) {
                runs.push(m);
            }
        }
        Some(summarize(&runs, bytes_processed))
    } else {
        None
    };

    let mut rs_runs = Vec::with_capacity(cfg.iterations);
    for _ in 0..cfg.iterations {
        if let Ok(m) = measure_command(&cfg.rust_bin, rs_args, env_vars) {
            rs_runs.push(m);
        }
    }
    let rs_stats = summarize(&rs_runs, bytes_processed);

    compare(category, name, bytes_processed, py_stats, rs_stats)
}

#[tokio::main]
async fn main() {
    let cfg = parse_args();
    if !cfg.rust_bin.exists() {
        eprintln!(
            "Rust gsutil binary not found at {}. Build with `cargo build --release -p gsutil-cli`.",
            cfg.rust_bin.display()
        );
        std::process::exit(1);
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let boto_path = tmp.path().join("empty.boto");
    fs::write(&boto_path, "[GSUtil]\ncheck_hashes = always\n").expect("write boto");

    let mut base_env = BTreeMap::new();
    base_env.insert("BOTO_CONFIG".to_string(), boto_path.display().to_string());

    let mut results = Vec::new();
    let run_all = cfg.suite == "all";

    // 1. Cold start suite
    if run_all || cfg.suite == "cold" {
        results.push(run_pair(
            &cfg,
            "cold-start",
            "version",
            &["version".to_string()],
            &base_env,
            None,
        ));
        results.push(run_pair(
            &cfg,
            "cold-start",
            "help",
            &["help".to_string()],
            &base_env,
            None,
        ));

        // 10 MiB deterministic file for hardware-accelerated CRC32C + MD5 hash benchmark.
        let file_10m = tmp.path().join("data_10m.bin");
        let payload = vec![0x5Au8; 10 * 1024 * 1024];
        fs::write(&file_10m, &payload).expect("write 10m file");
        results.push(run_pair(
            &cfg,
            "cold-start",
            "hash (10 MiB)",
            &["hash".to_string(), file_10m.display().to_string()],
            &base_env,
            Some(payload.len() as u64),
        ));
    }

    // 2. Local transfer suite
    if run_all || cfg.suite == "local" {
        let src_10m = tmp.path().join("cp_src_10m.bin");
        let dst_10m = tmp.path().join("cp_dst_10m.bin");
        let payload = vec![0xA5u8; 10 * 1024 * 1024];
        fs::write(&src_10m, &payload).expect("write cp src");
        results.push(run_pair(
            &cfg,
            "local",
            "cp (10 MiB)",
            &[
                "cp".to_string(),
                src_10m.display().to_string(),
                dst_10m.display().to_string(),
            ],
            &base_env,
            Some(payload.len() as u64),
        ));

        // 50-file tree for cp -r and rsync -r -d
        let tree_src = tmp.path().join("tree_src");
        let tree_dst = tmp.path().join("tree_dst");
        fs::create_dir_all(&tree_src).unwrap();
        fs::create_dir_all(&tree_dst).unwrap();
        let file_chunk = vec![0x33u8; 64 * 1024]; // 64 KiB each -> 3.2 MiB total
        for idx in 0..50 {
            fs::write(tree_src.join(format!("f_{idx:03}.dat")), &file_chunk).unwrap();
        }
        let total_tree_bytes = (50 * file_chunk.len()) as u64;

        results.push(run_pair(
            &cfg,
            "local",
            "cp -r (50x64KiB)",
            &[
                "-m".to_string(),
                "cp".to_string(),
                "-r".to_string(),
                tree_src.display().to_string(),
                tree_dst.display().to_string(),
            ],
            &base_env,
            Some(total_tree_bytes),
        ));

        let rsync_dst = tmp.path().join("rsync_dst");
        fs::create_dir_all(&rsync_dst).unwrap();
        results.push(run_pair(
            &cfg,
            "local",
            "rsync -r -d (50x64KiB)",
            &[
                "-m".to_string(),
                "rsync".to_string(),
                "-r".to_string(),
                "-d".to_string(),
                tree_src.display().to_string(),
                rsync_dst.display().to_string(),
            ],
            &base_env,
            Some(total_tree_bytes),
        ));
    }

    // 3. Mock GCS parallel `-m` fanout suite
    if run_all || cfg.suite == "mock" {
        let mut seed = Vec::new();
        let obj_bytes = vec![0x77u8; 32 * 1024]; // 32 KiB x 20 = 640 KiB
        for idx in 0..20 {
            seed.push((format!("obj_{idx:02}.bin"), obj_bytes.clone()));
        }
        let srv = BenchMockGcs::start("bench-bkt", seed)
            .await
            .expect("start mock gcs");

        let dl_dir = tmp.path().join("mock_dl");
        fs::create_dir_all(&dl_dir).unwrap();
        let mock_boto = tmp.path().join("mock.boto");
        fs::write(
            &mock_boto,
            format!(
                "[Credentials]\ngs_json_host = http://{}\ngs_json_port = {}\nuse_client_certificate = False\n[GSUtil]\ncheck_hashes = always\n",
                srv.host(),
                srv.port()
            ),
        )
        .expect("write mock boto");
        let adc_path = tmp.path().join("mock_adc.json");
        fs::write(
            &adc_path,
            serde_json::json!({
                "type": "authorized_user",
                "client_id": "bench-client",
                "client_secret": "bench-secret",
                "refresh_token": "bench-refresh",
                "token_uri": format!("http://{}/oauth2/token", srv.addr),
            })
            .to_string(),
        )
        .expect("write mock adc");

        let mut mock_env = base_env.clone();
        mock_env.insert("BOTO_CONFIG".to_string(), mock_boto.display().to_string());
        mock_env.insert("GSUTIL_TEST_MOCK_HTTP".to_string(), "1".to_string());
        mock_env.insert("HOME".to_string(), tmp.path().display().to_string());
        mock_env.insert(
            "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
            adc_path.display().to_string(),
        );
        mock_env.insert(
            "CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE".to_string(),
            "false".to_string(),
        );
        mock_env.insert(
            "CLOUDSDK_CONFIG".to_string(),
            tmp.path().display().to_string(),
        );

        let ls_args = vec!["ls".to_string(), "gs://bench-bkt/".to_string()];
        let mut rs_ls_runs = Vec::with_capacity(cfg.iterations);
        for _ in 0..cfg.iterations {
            if let Ok(m) = measure_command(&cfg.rust_bin, &ls_args, &mock_env) {
                rs_ls_runs.push(m);
            }
        }
        results.push(compare(
            "mock-gcs",
            "ls (20 objects)",
            None,
            None,
            summarize(&rs_ls_runs, None),
        ));

        let total_mock_bytes = (20 * obj_bytes.len()) as u64;
        let cp_dl_args = vec![
            "-m".to_string(),
            "cp".to_string(),
            "gs://bench-bkt/*.bin".to_string(),
            dl_dir.display().to_string(),
        ];
        let mut rs_dl_runs = Vec::with_capacity(cfg.iterations);
        for _ in 0..cfg.iterations {
            if let Ok(m) = measure_command(&cfg.rust_bin, &cp_dl_args, &mock_env) {
                rs_dl_runs.push(m);
            }
        }
        results.push(compare(
            "mock-gcs",
            "-m cp download (20x32KiB)",
            Some(total_mock_bytes),
            None,
            summarize(&rs_dl_runs, Some(total_mock_bytes)),
        ));
    }

    // 4. Live GCS suite (when GSUTIL_TEST_BUCKET is set)
    if (run_all || cfg.suite == "live") && env::var("GSUTIL_TEST_BUCKET").is_ok() {
        let bucket = env::var("GSUTIL_TEST_BUCKET").unwrap();
        let bkt_prefix = format!(
            "gs://{}/bench-run",
            bucket.trim_start_matches("gs://").trim_end_matches('/')
        );
        let live_env = BTreeMap::new(); // Use real user credentials

        let with_py_shim = |base: &[String]| -> Vec<String> {
            let mut v = vec![
                "-o".to_string(),
                "GSUtil:use_gcloud_storage=True".to_string(),
            ];
            v.extend_from_slice(base);
            v
        };

        let file_5m = tmp.path().join("live_5m.bin");
        let payload = vec![0x42u8; 5 * 1024 * 1024];
        fs::write(&file_5m, &payload).unwrap();

        let up_args = vec![
            "cp".to_string(),
            file_5m.display().to_string(),
            format!("{bkt_prefix}/live_5m.bin"),
        ];
        results.push(run_pair_split(
            &cfg,
            "live-gcs",
            "cp upload (5 MiB)",
            &with_py_shim(&up_args),
            &up_args,
            &live_env,
            Some(payload.len() as u64),
        ));

        let dl_5m = tmp.path().join("live_dl_5m.bin");
        let dl_args = vec![
            "cp".to_string(),
            format!("{bkt_prefix}/live_5m.bin"),
            dl_5m.display().to_string(),
        ];
        results.push(run_pair_split(
            &cfg,
            "live-gcs",
            "cp download (5 MiB)",
            &with_py_shim(&dl_args),
            &dl_args,
            &live_env,
            Some(payload.len() as u64),
        ));

        let ls_live_args = vec!["ls".to_string(), format!("{bkt_prefix}/")];
        results.push(run_pair_split(
            &cfg,
            "live-gcs",
            "ls",
            &with_py_shim(&ls_live_args),
            &ls_live_args,
            &live_env,
            None,
        ));

        // 10-file parallel -m cp upload & download against live GCS
        let live_tree = tmp.path().join("live_tree");
        let live_dl_tree = tmp.path().join("live_dl_tree");
        fs::create_dir_all(&live_tree).unwrap();
        fs::create_dir_all(&live_dl_tree).unwrap();
        let small = vec![0x55u8; 64 * 1024];
        for idx in 0..10 {
            fs::write(live_tree.join(format!("p_{idx:02}.bin")), &small).unwrap();
        }
        let fanout_bytes = (10 * small.len()) as u64;

        let fan_up = vec![
            "-m".to_string(),
            "cp".to_string(),
            "-r".to_string(),
            live_tree.display().to_string(),
            format!("{bkt_prefix}/fanout/"),
        ];
        results.push(run_pair_split(
            &cfg,
            "live-gcs",
            "-m cp upload (10x64KiB)",
            &with_py_shim(&fan_up),
            &fan_up,
            &live_env,
            Some(fanout_bytes),
        ));

        let fan_dl = vec![
            "-m".to_string(),
            "cp".to_string(),
            "-r".to_string(),
            format!("{bkt_prefix}/fanout/"),
            live_dl_tree.display().to_string(),
        ];
        results.push(run_pair_split(
            &cfg,
            "live-gcs",
            "-m cp download (10x64KiB)",
            &with_py_shim(&fan_dl),
            &fan_dl,
            &live_env,
            Some(fanout_bytes),
        ));

        // Cleanup benchmark objects from live test bucket.
        let _ = measure_command(
            &cfg.rust_bin,
            &[
                "-m".to_string(),
                "rm".to_string(),
                "-r".to_string(),
                format!("{bkt_prefix}/"),
            ],
            &live_env,
        );
    }

    let md = render_markdown_report(&results);
    print!("{md}");

    if let Some(ref md_path) = cfg.markdown_out {
        fs::write(md_path, &md).expect("write markdown report");
    }
    if let Some(ref json_path) = cfg.json_out {
        let json = serde_json::to_string_pretty(&results).expect("serialize json");
        fs::write(json_path, json).expect("write json report");
    }
}
