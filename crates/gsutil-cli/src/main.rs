//! `gsutil` binary entrypoint with `SIGINT` / `SIGTERM` graceful cleanup.

use std::io::{self, Write};

fn install_signal_handlers() {
    tokio::spawn(async move {
        #[cfg(unix)]
        let sig_num: i32 = {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).ok();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => 2,
                _ = async {
                    if let Some(ref mut s) = sigterm {
                        s.recv().await
                    } else {
                        std::future::pending().await
                    }
                } => 15,
            }
        };

        #[cfg(not(unix))]
        let sig_num: i32 = {
            let _ = tokio::signal::ctrl_c().await;
            2
        };

        gsutil_core::signals::run_all_cleanups();
        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "Caught CTRL-C (signal {sig_num}) - exiting");
        let _ = stderr.flush();
        std::process::exit(1);
    });
}

#[tokio::main]
async fn main() {
    install_signal_handlers();
    let code = gsutil_cli::run_from_env().await;
    gsutil_core::signals::run_all_cleanups();
    std::process::exit(code);
}
