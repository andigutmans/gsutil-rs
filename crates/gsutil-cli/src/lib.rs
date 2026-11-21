//! gsutil CLI library: global option parsing, command dispatch, error/signal
//! formatting, and command implementations.

pub mod commands;
pub mod context;
pub mod difflib;
pub mod dispatch;
pub mod encryption;
pub mod format;
pub mod getopt;
pub mod global_opts;
pub mod help_topics;
pub mod wildcard_iter;

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use gsutil_core::api::CloudApi;
use gsutil_core::config::BotoConfig;
use gsutil_core::error::GsutilError;

use crate::context::CommandContext;
use crate::dispatch::run_named_command;
use crate::global_opts::{parse_global_options, DEBUGLEVEL_DUMP_REQUESTS};

const DEBUG_WARNING: &str = "\
***************************** WARNING *****************************
*** You are running gsutil with debug output enabled.
*** Be aware that debug output includes authentication credentials.
*** Make sure to remove the value of the Authorization header for
*** each HTTP request printed to the console prior to posting to
*** a public medium such as a forum post or Stack Overflow.
***************************** WARNING *****************************
";

const TRACE_WARNING: &str = "\
***************************** WARNING *****************************
*** You are running gsutil with trace output enabled.
*** Be aware that trace output includes authentication credentials
*** and may include the contents of any files accessed during the trace.
***************************** WARNING *****************************
";

const HTTP_WARNING: &str = "\
***************************** WARNING *****************************
*** You are running gsutil with the \"https_validate_certificates\" config
*** variable set to False. This option should always be set to True in
*** production environments to protect against man-in-the-middle attacks,
*** and leaking of user data.
***************************** WARNING *****************************
";

const DEPRECATION_BANNER: &str = "\
Google recommends using Gcloud storage CLI \
(https://docs.cloud.google.com/storage/docs/discover-object-storage-gcloud) \
instead of gsutil. Please refer to migration guide \
(https://docs.cloud.google.com/storage/docs/gsutil-transition-to-gcloud) \
for assistance.
";

/// Run gsutil from process `std::env::args()` with no cloud client wired yet
/// (or with an injected `CloudApi` once `gsutil-gcs` is ready).
pub async fn run_from_env() -> i32 {
    let raw_argv: Vec<String> = std::env::args().collect();
    run_cli_with_api(&raw_argv, None).await
}

/// Captured output from [`run_cli_captured`] for unit & integration tests.
#[derive(Debug, Clone)]
pub struct CliOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run gsutil with an optional `CloudApi` and capture stdout/stderr in memory.
pub async fn run_cli_captured(raw_argv: &[String], api: Option<Arc<dyn CloudApi>>) -> CliOutput {
    let stdout_buf = Arc::new(Mutex::new(Vec::new()));
    let stderr_buf = Arc::new(Mutex::new(Vec::new()));
    let mut config = BotoConfig::load_default();
    let cli_args = if raw_argv.len() > 1 {
        &raw_argv[1..]
    } else {
        &[]
    };

    let (global, remaining) = match parse_global_options(cli_args, &mut config) {
        Ok(res) => res,
        Err(e) => {
            if let Some(msg) = e.cli_message() {
                let _ = writeln!(stderr_buf.lock().unwrap(), "{msg}");
            }
            return CliOutput {
                exit_code: e.exit_code(),
                stdout: String::new(),
                stderr: String::from_utf8_lossy(&stderr_buf.lock().unwrap()).into_owned(),
            };
        }
    };

    let debug_level = global.debug_level;
    let test_exception_traces = global.test_exception_traces;
    let show_usage_and_exit = global.show_usage_and_exit;

    let mut ctx =
        CommandContext::with_capture(config, global, api, stdout_buf.clone(), stderr_buf.clone());

    if show_usage_and_exit {
        let _ = run_named_command(&mut ctx, "help", &[]).await;
        return CliOutput {
            exit_code: 1,
            stdout: String::from_utf8_lossy(&stdout_buf.lock().unwrap()).into_owned(),
            stderr: String::from_utf8_lossy(&stderr_buf.lock().unwrap()).into_owned(),
        };
    }

    let (command_name, cmd_args): (String, Vec<String>) = if ctx.global.version {
        let rest = if remaining.len() > 1 {
            remaining[1..].to_vec()
        } else {
            Vec::new()
        };
        ("version".to_string(), rest)
    } else if remaining.is_empty() {
        ("help".to_string(), Vec::new())
    } else {
        (remaining[0].clone(), remaining[1..].to_vec())
    };

    let exit_code = match run_named_command(&mut ctx, &command_name, &cmd_args).await {
        Ok(code) => code,
        Err(e) => {
            if let Some(msg) = e.cli_message() {
                if debug_level >= DEBUGLEVEL_DUMP_REQUESTS || test_exception_traces {
                    ctx.error(&format!("DEBUG: Exception stack trace:\n    {e:?}\n{msg}"));
                } else {
                    ctx.error(&msg);
                }
            }
            e.exit_code()
        }
    };

    let stdout = String::from_utf8_lossy(&stdout_buf.lock().unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_buf.lock().unwrap()).into_owned();
    CliOutput {
        exit_code,
        stdout,
        stderr,
    }
}

/// Core CLI entrypoint matching `gslib/__main__.py::main()`.
///
/// `raw_argv` includes `argv[0]` (the binary name). Returns the process exit code (0 or 1).
pub async fn run_cli_with_api(raw_argv: &[String], api: Option<Arc<dyn CloudApi>>) -> i32 {
    let mut config = BotoConfig::load_default();
    let cli_args = if raw_argv.len() > 1 {
        &raw_argv[1..]
    } else {
        &[]
    };

    let (global, remaining) = match parse_global_options(cli_args, &mut config) {
        Ok(res) => res,
        Err(e) => return output_error_and_exit(&e, 0, false),
    };

    if !config.is_secure() {
        let err = GsutilError::command(
            "Your boto configuration has is_secure = False. Gsutil cannot be\nrun this way, for security reasons.",
        );
        return output_error_and_exit(&err, global.debug_level, global.test_exception_traces);
    }

    let debug_level = global.debug_level;
    let test_exception_traces = global.test_exception_traces;
    let show_usage_and_exit = global.show_usage_and_exit;

    let mut ctx = CommandContext::new(config, global, api);

    if show_usage_and_exit {
        let _ = run_named_command(&mut ctx, "help", &[]).await;
        return 1;
    }

    if ctx.global.trace_token.is_some() {
        let _ = io::stderr().write_all(TRACE_WARNING.as_bytes());
    }

    if debug_level >= DEBUGLEVEL_DUMP_REQUESTS {
        let _ = io::stderr().write_all(DEBUG_WARNING.as_bytes());
        let _ = run_named_command(&mut ctx, "ver", &["-l".to_string()]).await;
        let config_paths = ctx.config.friendly_config_file_paths();
        let redacted = ctx.config.redacted_debug_items();
        let _ = writeln!(io::stderr(), "Command being run: {}", raw_argv.join(" "));
        let _ = writeln!(io::stderr(), "config_file_list: {config_paths:?}");
        let _ = writeln!(io::stderr(), "config: {redacted:?}");
    }

    if !ctx.config.https_validate_certificates() {
        let _ = io::stderr().write_all(HTTP_WARNING.as_bytes());
    }

    // Determine command name and command args.
    let (command_name, cmd_args): (String, Vec<String>) = if ctx.global.version {
        let rest = if remaining.len() > 1 {
            remaining[1..].to_vec()
        } else {
            Vec::new()
        };
        ("version".to_string(), rest)
    } else if remaining.is_empty() {
        ("help".to_string(), Vec::new())
    } else {
        (remaining[0].clone(), remaining[1..].to_vec())
    };

    // Deprecation banner matching gslib/__main__.py lines 437-458.
    let no_banner = std::env::var("GSUTIL_NO_BANNER")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1"))
        .unwrap_or(false);
    let force_banner = std::env::var("GSUTIL_TEST_FORCE_BANNER")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1"))
        .unwrap_or(false);
    if !ctx.global.quiet && !no_banner && (ctx.is_tty || force_banner) {
        let _ = io::stderr().write_all(DEPRECATION_BANNER.as_bytes());
    }

    match run_named_command(&mut ctx, &command_name, &cmd_args).await {
        Ok(code) => code,
        Err(e) => output_error_and_exit(&e, debug_level, test_exception_traces),
    }
}

fn output_error_and_exit(err: &GsutilError, debug_level: u8, test_exception_traces: bool) -> i32 {
    if let Some(msg) = err.cli_message() {
        if debug_level >= DEBUGLEVEL_DUMP_REQUESTS || test_exception_traces {
            let _ = writeln!(
                io::stderr(),
                "DEBUG: Exception stack trace:\n    {err:?}\n{msg}"
            );
        } else {
            let _ = writeln!(io::stderr(), "{msg}");
        }
    }
    err.exit_code()
}
