//! `gsutil` binary entrypoint.

#[tokio::main]
async fn main() {
    let code = gsutil_cli::run_from_env().await;
    std::process::exit(code);
}
