//! Global CLI option parsing matching `gslib/utils/arg_helper.py` and `gslib/__main__.py`.

use std::collections::BTreeMap;

use gsutil_core::config::BotoConfig;
use gsutil_core::error::Result;

use crate::getopt::{getopt, OptPair};

pub const DEBUGLEVEL_DUMP_REQUESTS: u8 = 2;
pub const DEBUGLEVEL_DUMP_REQUESTS_AND_PAYLOADS: u8 = 3;

const GLOBAL_SHORT_OPTS: &str = "dDvo:?h:i:u:mq";
const GLOBAL_LONG_OPTS: &[&str] = &[
    "debug",
    "detailedDebug",
    "version",
    "option",
    "help",
    "header",
    "impersonate-service-account=",
    "multithreaded",
    "quiet",
    "testexceptiontraces",
    "trace-token=",
    "perf-trace-token=",
];

/// Parsed global gsutil flags (before the command name).
#[derive(Debug, Clone, Default)]
pub struct GlobalOptions {
    pub debug_level: u8,
    pub headers: BTreeMap<String, String>,
    pub parallel_operations: bool,
    pub quiet: bool,
    pub version: bool,
    pub user_project: Option<String>,
    pub impersonate_service_account: Option<String>,
    pub trace_token: Option<String>,
    pub perf_trace_token: Option<String>,
    pub test_exception_traces: bool,
    pub show_usage_and_exit: bool,
    pub raw_opts: Vec<OptPair>,
}

/// Parse global options from `argv` (excluding `argv[0]`), applying `-o` overrides to `config`.
///
/// Returns `(GlobalOptions, remaining_args)`.
pub fn parse_global_options(
    args: &[String],
    config: &mut BotoConfig,
) -> Result<(GlobalOptions, Vec<String>)> {
    let (opts, remaining) = getopt(args, GLOBAL_SHORT_OPTS, GLOBAL_LONG_OPTS)?;
    let mut global = GlobalOptions {
        raw_opts: opts.clone(),
        ..Default::default()
    };

    for (o, a) in opts {
        match o.as_str() {
            "-d" | "--debug" => {
                global.debug_level = DEBUGLEVEL_DUMP_REQUESTS;
            }
            "-D" | "--detailedDebug" => {
                if global.debug_level == DEBUGLEVEL_DUMP_REQUESTS {
                    global.debug_level = DEBUGLEVEL_DUMP_REQUESTS_AND_PAYLOADS;
                } else {
                    global.debug_level = DEBUGLEVEL_DUMP_REQUESTS;
                }
            }
            "-?" | "--help" => {
                global.show_usage_and_exit = true;
                return Ok((global, remaining));
            }
            "-h" | "--header" => {
                let (hdr_name, hdr_val) = match a.split_once(':') {
                    Some((k, v)) => (k, v),
                    None => (a.as_str(), ""),
                };
                if hdr_name.is_empty() {
                    global.show_usage_and_exit = true;
                    return Ok((global, remaining));
                }
                global
                    .headers
                    .insert(hdr_name.to_ascii_lowercase(), hdr_val.to_string());
            }
            "-m" | "--multithreaded" => {
                global.parallel_operations = true;
            }
            "-q" | "--quiet" => {
                global.quiet = true;
            }
            "-u" => {
                global.user_project = Some(a);
            }
            "-v" | "--version" => {
                global.version = true;
            }
            "-i" | "--impersonate-service-account" => {
                global.impersonate_service_account = Some(a);
            }
            "--perf-trace-token" => {
                global.perf_trace_token = Some(a);
            }
            "--trace-token" => {
                global.trace_token = Some(a);
            }
            "--testexceptiontraces" => {
                global.test_exception_traces = true;
            }
            "-o" | "--option" => {
                let (opt_section_name, opt_value) = match a.split_once('=') {
                    Some((k, v)) => (k, v),
                    None => (a.as_str(), ""),
                };
                if opt_section_name.is_empty() {
                    global.show_usage_and_exit = true;
                    return Ok((global, remaining));
                }
                let (opt_section, opt_name) = match opt_section_name.split_once(':') {
                    Some((s, n)) => (s, n),
                    None => ("", ""),
                };
                if opt_section.is_empty() || opt_name.is_empty() {
                    global.show_usage_and_exit = true;
                    return Ok((global, remaining));
                }
                config.set(opt_section, opt_name, opt_value);
            }
            _ => {}
        }
    }

    Ok((global, remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn test_parse_global_options_full() {
        let mut cfg = BotoConfig::new();
        let (g, rest) = parse_global_options(
            &s(&[
                "-DD",
                "-m",
                "-q",
                "-u",
                "billing-proj",
                "-h",
                "Cache-Control:public",
                "-o",
                "GSUtil:default_project_id=test-proj",
                "-i",
                "sa@test.iam.gserviceaccount.com",
                "--trace-token=tok1",
                "--perf-trace-token=tok2",
                "--testexceptiontraces",
                "ls",
                "-l",
                "gs://my-bucket",
            ]),
            &mut cfg,
        )
        .unwrap();

        assert_eq!(g.debug_level, DEBUGLEVEL_DUMP_REQUESTS_AND_PAYLOADS);
        assert!(g.parallel_operations);
        assert!(g.quiet);
        assert_eq!(g.user_project.as_deref(), Some("billing-proj"));
        assert_eq!(
            g.headers.get("cache-control").map(String::as_str),
            Some("public")
        );
        assert_eq!(cfg.default_project_id(), Some("test-proj"));
        assert_eq!(
            g.impersonate_service_account.as_deref(),
            Some("sa@test.iam.gserviceaccount.com")
        );
        assert_eq!(g.trace_token.as_deref(), Some("tok1"));
        assert_eq!(g.perf_trace_token.as_deref(), Some("tok2"));
        assert!(g.test_exception_traces);
        assert!(!g.show_usage_and_exit);
        assert_eq!(rest, s(&["ls", "-l", "gs://my-bucket"]));
    }

    #[test]
    fn test_help_flag_sets_usage_and_exit() {
        let mut cfg = BotoConfig::new();
        let (g, _) = parse_global_options(&s(&["-?"]), &mut cfg).unwrap();
        assert!(g.show_usage_and_exit);

        let (g2, _) = parse_global_options(&s(&["--help"]), &mut cfg).unwrap();
        assert!(g2.show_usage_and_exit);
    }

    #[test]
    fn test_bad_option_triggers_usage_and_exit() {
        let mut cfg = BotoConfig::new();
        let (g, _) = parse_global_options(&s(&["-o", "missing_colon"]), &mut cfg).unwrap();
        assert!(g.show_usage_and_exit);
    }
}
