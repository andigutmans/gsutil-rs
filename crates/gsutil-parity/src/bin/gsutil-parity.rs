//! CLI runner for the `gsutil-parity` differential compatibility & benchmark suite.

use gsutil_parity::cases::{run_live_gcs_suite, run_mock_gcs_suite, run_offline_suite};
use gsutil_parity::mock_gcs::MockGcsServer;
use gsutil_parity::runner::GsutilRunner;
use gsutil_parity::scorecard::ParityScorecard;
use gsutil_parity::stage1_gates::run_stage1_gates;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Offline,
    Mock,
    Live,
    Stage1,
    All,
    ServeMockTls { port: u16, ca_out: Option<PathBuf> },
}

#[derive(Debug, PartialEq, Eq)]
enum Format {
    Markdown,
    Json,
    Both,
}

fn parse_args() -> (Mode, Format, Option<String>, Option<PathBuf>, GsutilRunner) {
    let mut mode = Mode::Offline;
    let mut serve_mock_tls = false;
    let mut serve_port: u16 = 0;
    let mut serve_ca_out: Option<PathBuf> = None;
    let mut format = Format::Markdown;
    let mut filter: Option<String> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut runner = GsutilRunner::discover();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--serve-mock-tls" => {
                serve_mock_tls = true;
            }
            "--port" => {
                if let Some(p) = args.next() {
                    serve_port = p.parse().unwrap_or_else(|_| {
                        eprintln!("Invalid --port: {p}");
                        std::process::exit(2);
                    });
                }
            }
            "--ca-out" => {
                serve_ca_out = args.next().map(PathBuf::from);
            }
            "--mode" => {
                if let Some(m) = args.next() {
                    mode = match m.as_str() {
                        "offline" => Mode::Offline,
                        "mock" => Mode::Mock,
                        "live" => Mode::Live,
                        "stage1" => Mode::Stage1,
                        "all" => Mode::All,
                        other => {
                            eprintln!(
                                "Unknown --mode: {other} (expected offline|mock|live|stage1|all)"
                            );
                            std::process::exit(2);
                        }
                    };
                }
            }
            "--format" => {
                if let Some(f) = args.next() {
                    format = match f.as_str() {
                        "markdown" | "md" => Format::Markdown,
                        "json" => Format::Json,
                        "both" => Format::Both,
                        other => {
                            eprintln!("Unknown --format: {other} (expected markdown|json|both)");
                            std::process::exit(2);
                        }
                    };
                }
            }
            "--filter" => {
                filter = args.next();
            }
            "--out-dir" => {
                out_dir = args.next().map(PathBuf::from);
            }
            "--ref-bin" => {
                if let Some(p) = args.next() {
                    runner.ref_bin = PathBuf::from(p);
                }
            }
            "--rust-bin" => {
                if let Some(p) = args.next() {
                    runner.rust_bin = PathBuf::from(p);
                }
            }
            "--help" | "-h" => {
                println!(
                    "gsutil-parity - Differential compatibility test harness for gsutil-rs\n\n\
                     USAGE:\n  gsutil-parity [--mode offline|mock|live|all] [--format markdown|json|both]\n\
                                    [--filter <substr>] [--out-dir <dir>] [--ref-bin <path>] [--rust-bin <path>]\n\n\
                     ENV:\n  GSUTIL_REF_BIN      Path to Python gsutil (default: /usr/bin/gsutil)\n\
                       GSUTIL_RUST_BIN     Path to Rust gsutil (default: target/debug/gsutil)\n\
                       GSUTIL_TEST_BUCKET  Live GCS bucket for --mode live/all\n"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("Unrecognized argument: {other}");
                std::process::exit(2);
            }
        }
    }

    if serve_mock_tls {
        mode = Mode::ServeMockTls {
            port: serve_port,
            ca_out: serve_ca_out,
        };
    }

    (mode, format, filter, out_dir, runner)
}

#[tokio::main]
async fn main() {
    let (mode, format, filter, out_dir, runner) = parse_args();
    if let Mode::ServeMockTls { port, ca_out } = mode {
        let server = MockGcsServer::start_tls_on_port(port)
            .await
            .unwrap_or_else(|e| {
                eprintln!("Failed to start TLS mock GCS server on port {port}: {e}");
                std::process::exit(1);
            });
        if let Some(ca_path) = ca_out {
            if let Some(parent) = ca_path.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            if let Some(ref pem) = server.ca_cert_pem {
                std::fs::write(&ca_path, pem).unwrap_or_else(|e| {
                    eprintln!("Failed to write CA PEM to {}: {e}", ca_path.display());
                    std::process::exit(1);
                });
            }
        }
        println!("READY {}", server.base_url());
        let _ = std::io::stdout().flush();

        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        drop(server);
        return;
    }

    let mut all_results = Vec::new();

    match mode {
        Mode::Offline => {
            all_results.extend(run_offline_suite(&runner, filter.as_deref()));
        }
        Mode::Mock => {
            all_results.extend(run_mock_gcs_suite(&runner, filter.as_deref()).await);
        }
        Mode::Live => {
            let bucket = std::env::var("GSUTIL_TEST_BUCKET").unwrap_or_else(|_| {
                eprintln!("GSUTIL_TEST_BUCKET must be set for --mode live");
                std::process::exit(2);
            });
            all_results.extend(run_live_gcs_suite(&runner, &bucket, filter.as_deref()));
        }
        Mode::Stage1 => {
            let bucket = std::env::var("GSUTIL_TEST_BUCKET")
                .ok()
                .filter(|s| !s.trim().is_empty());
            all_results.extend(run_stage1_gates(&runner, bucket.as_deref()).await);
        }
        Mode::All => {
            all_results.extend(run_offline_suite(&runner, filter.as_deref()));
            all_results.extend(run_mock_gcs_suite(&runner, filter.as_deref()).await);
            if let Ok(bucket) = std::env::var("GSUTIL_TEST_BUCKET") {
                if !bucket.trim().is_empty() {
                    all_results.extend(run_live_gcs_suite(&runner, &bucket, filter.as_deref()));
                }
            }
        }
        Mode::ServeMockTls { .. } => unreachable!(),
    }

    let scorecard = ParityScorecard::from_results(all_results);
    let md = scorecard.to_markdown();
    let json = scorecard.to_json_pretty().expect("serialize scorecard");

    if let Some(dir) = out_dir {
        std::fs::create_dir_all(&dir).expect("create out dir");
        if matches!(format, Format::Markdown | Format::Both) {
            std::fs::write(dir.join("scorecard.md"), &md).expect("write scorecard.md");
        }
        if matches!(format, Format::Json | Format::Both) {
            std::fs::write(dir.join("scorecard.json"), &json).expect("write scorecard.json");
        }
    }

    match format {
        Format::Markdown => print!("{}", md),
        Format::Json => println!("{}", json),
        Format::Both => {
            print!("{}", md);
            println!("\n---\n```json\n{}\n```", json);
        }
    }

    if scorecard.summary.failed > 0 {
        std::process::exit(1);
    }
}
