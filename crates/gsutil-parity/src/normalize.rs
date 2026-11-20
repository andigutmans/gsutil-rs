//! Output normalization and comparison rules for differential testing.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// How stdout or stderr should be compared between Python gsutil and Rust gsutil.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompareRule {
    /// Byte-for-byte exact match after optional path replacement.
    Exact,
    /// Match after normalizing dynamic tokens (temp paths, timestamps, generations,
    /// spinners/progress lines, trailing CR/LF differences).
    Normalized,
    /// Require that every listed substring is present in BOTH outputs (or in the
    /// Rust output when reference output is checked separately).
    ContainsAll(Vec<String>),
    /// Match the gsutil error class / prefix (e.g., `CommandException:`,
    /// `NotFoundException:`, `AccessDeniedException:`, `No URLs matched`,
    /// `ServiceException: 403`) plus any required substrings.
    ErrorClass { required_substrings: Vec<String> },
    /// Ignore this stream (e.g., progress output on stderr when checking stdout).
    Ignore,
}

/// Dynamic replacements applied before comparison.
#[derive(Debug, Clone, Default)]
pub struct NormalizeContext {
    /// Temp directory paths to replace with `<TMPDIR>`.
    pub temp_paths: Vec<String>,
    /// Test bucket names to replace with `<TEST_BUCKET>`.
    pub test_buckets: Vec<String>,
    /// Strip interactive progress/spinner lines from stderr.
    pub strip_ui_progress: bool,
}

impl NormalizeContext {
    pub fn with_temp_path(mut self, path: impl Into<String>) -> Self {
        self.temp_paths.push(path.into());
        self
    }

    pub fn with_test_bucket(mut self, bucket: impl Into<String>) -> Self {
        self.test_buckets.push(bucket.into());
        self
    }

    pub fn strip_ui(mut self) -> Self {
        self.strip_ui_progress = true;
        self
    }
}

fn re_iso_ts() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z").expect("valid regex")
    })
}

fn re_rfc2822_ts() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT")
            .expect("valid regex")
    })
}

fn re_url_generation() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"#\d{10,}").expect("valid regex"))
}

fn re_stat_generation() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)(Generation:\s+)\d+").expect("valid regex"))
}

fn re_ui_progress() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?m)^(?:[^\n\r]*\[\d+(?:/\d+)?\s+(?:files|objects)\][^\n\r]*|Operation completed over[^\n]*|[/\\|\-]\r?)$")
            .expect("valid regex")
    })
}

/// Apply path/bucket replacements only (used for `Exact` comparisons when temp paths differ).
pub fn replace_paths(input: &str, ctx: &NormalizeContext) -> String {
    let mut out = input.replace("\r\n", "\n");
    for p in &ctx.temp_paths {
        if !p.is_empty() {
            out = out.replace(p, "<TMPDIR>");
        }
    }
    for b in &ctx.test_buckets {
        if !b.is_empty() {
            out = out.replace(b, "<TEST_BUCKET>");
        }
    }
    out
}

/// Normalize dynamic tokens in gsutil output for stable differential comparison.
pub fn normalize_output(input: &str, ctx: &NormalizeContext) -> String {
    let mut out = replace_paths(input, ctx);
    out = re_iso_ts().replace_all(&out, "<TIMESTAMP>").into_owned();
    out = re_rfc2822_ts()
        .replace_all(&out, "<TIMESTAMP>")
        .into_owned();
    out = re_url_generation().replace_all(&out, "#<GEN>").into_owned();
    out = re_stat_generation()
        .replace_all(&out, "${1}<GEN>")
        .into_owned();
    if ctx.strip_ui_progress {
        out = re_ui_progress().replace_all(&out, "").into_owned();
        // Collapse blank lines introduced by stripped UI lines.
        let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
        out = if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        };
    }
    out
}

/// Extract the gsutil exception class prefix from stderr, if any.
pub fn extract_error_class(stderr: &str) -> Option<String> {
    let known_prefixes = [
        "CommandException:",
        "AccessDeniedException:",
        "AuthenticationException:",
        "NotFoundException:",
        "BucketNotFoundException:",
        "NotEmptyException:",
        "BadRequestException:",
        "PreconditionException:",
        "PublishPermissionDeniedException:",
        "RetryableServiceException:",
        "ServiceException:",
        "ArgumentException:",
        "ProjectIdException:",
        "InvalidUrlError:",
        "HashMismatchException:",
        "IamChOnResourceWithConditionsException:",
        "ResumableUploadException:",
        "ResumableDownloadException:",
        "AbortException:",
        "No URLs matched",
    ];
    for line in stderr.lines() {
        let trimmed = line.trim();
        for prefix in known_prefixes {
            if trimmed.starts_with(prefix) {
                return Some(prefix.to_string());
            }
        }
    }
    None
}

/// Result of comparing one output stream (stdout or stderr).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamComparison {
    pub matched: bool,
    pub detail: Option<String>,
}

impl StreamComparison {
    pub fn ok() -> Self {
        Self {
            matched: true,
            detail: None,
        }
    }

    pub fn mismatch(detail: impl Into<String>) -> Self {
        Self {
            matched: false,
            detail: Some(detail.into()),
        }
    }
}

/// Compare reference vs rust output according to `CompareRule`.
pub fn compare_stream(
    stream_name: &str,
    reference: &str,
    rust: &str,
    rule: &CompareRule,
    ctx: &NormalizeContext,
) -> StreamComparison {
    match rule {
        CompareRule::Ignore => StreamComparison::ok(),
        CompareRule::Exact => {
            let r_ref = replace_paths(reference, ctx);
            let r_rust = replace_paths(rust, ctx);
            if r_ref == r_rust {
                StreamComparison::ok()
            } else {
                StreamComparison::mismatch(format!(
                    "{stream_name} exact mismatch:\n  ref : {:?}\n  rust: {:?}",
                    truncate(&r_ref, 400),
                    truncate(&r_rust, 400),
                ))
            }
        }
        CompareRule::Normalized => {
            let n_ref = normalize_output(reference, ctx);
            let n_rust = normalize_output(rust, ctx);
            if n_ref == n_rust {
                StreamComparison::ok()
            } else {
                StreamComparison::mismatch(format!(
                    "{stream_name} normalized mismatch:\n  ref : {:?}\n  rust: {:?}",
                    truncate(&n_ref, 400),
                    truncate(&n_rust, 400),
                ))
            }
        }
        CompareRule::ContainsAll(needles) => {
            let r_ref = replace_paths(reference, ctx);
            let r_rust = replace_paths(rust, ctx);
            let mut missing = Vec::new();
            for needle in needles {
                if !r_rust.contains(needle.as_str()) {
                    missing.push(format!("rust missing {:?}", needle));
                }
                if !r_ref.contains(needle.as_str()) {
                    missing.push(format!("ref missing {:?}", needle));
                }
            }
            if missing.is_empty() {
                StreamComparison::ok()
            } else {
                StreamComparison::mismatch(format!(
                    "{stream_name} substring check failed ({}):\n  ref : {:?}\n  rust: {:?}",
                    missing.join("; "),
                    truncate(&r_ref, 300),
                    truncate(&r_rust, 300),
                ))
            }
        }
        CompareRule::ErrorClass {
            required_substrings,
        } => {
            let r_ref = replace_paths(reference, ctx);
            let r_rust = replace_paths(rust, ctx);
            let ref_class = extract_error_class(&r_ref);
            let rust_class = extract_error_class(&r_rust);
            let mut errs = Vec::new();
            if ref_class != rust_class {
                errs.push(format!(
                    "error class mismatch (ref={:?}, rust={:?})",
                    ref_class, rust_class
                ));
            }
            for needle in required_substrings {
                if !r_rust.contains(needle.as_str()) {
                    errs.push(format!("rust missing {:?}", needle));
                }
            }
            if errs.is_empty() {
                StreamComparison::ok()
            } else {
                StreamComparison::mismatch(format!(
                    "{stream_name} error check failed ({}):\n  ref : {:?}\n  rust: {:?}",
                    errs.join("; "),
                    truncate(&r_ref, 350),
                    truncate(&r_rust, 350),
                ))
            }
        }
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut end = max_len;
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}...<truncated {}B>", &s[..end], s.len() - end)
    }
}
