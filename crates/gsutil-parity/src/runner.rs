//! Process runner for invoking both reference Python gsutil and Rust gsutil.

use crate::normalize::{compare_stream, CompareRule, NormalizeContext, StreamComparison};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Output captured from a single gsutil invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// Execution configuration for a single invocation.
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<PathBuf>,
    pub stdin: Option<Vec<u8>>,
    pub boto_config: Option<PathBuf>,
}

impl RunOptions {
    pub fn new<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            args: args.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    pub fn with_env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }

    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn with_stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    pub fn with_boto_config(mut self, path: impl Into<PathBuf>) -> Self {
        self.boto_config = Some(path.into());
        self
    }
}

/// Comparison result for one differential test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResult {
    pub id: String,
    pub category: String,
    pub command: String,
    pub args: Vec<String>,
    pub passed: bool,
    pub skipped: bool,
    pub skip_reason: Option<String>,
    pub exit_code_match: bool,
    pub ref_output: Option<InvocationOutput>,
    pub rust_output: Option<InvocationOutput>,
    pub stdout_cmp: Option<StreamComparison>,
    pub stderr_cmp: Option<StreamComparison>,
    pub side_effect_error: Option<String>,
}

/// Dual-binary runner that invokes Python `/usr/bin/gsutil` and Rust `gsutil`.
#[derive(Debug, Clone)]
pub struct GsutilRunner {
    pub ref_bin: PathBuf,
    pub rust_bin: PathBuf,
}

impl GsutilRunner {
    /// Discover reference and Rust binaries from environment or default workspace paths.
    pub fn discover() -> Self {
        let ref_bin = std::env::var("GSUTIL_REF_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/usr/bin/gsutil"));

        let rust_bin = std::env::var("GSUTIL_RUST_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| Self::default_rust_bin());

        Self { ref_bin, rust_bin }
    }

    pub fn new(ref_bin: impl Into<PathBuf>, rust_bin: impl Into<PathBuf>) -> Self {
        Self {
            ref_bin: ref_bin.into(),
            rust_bin: rust_bin.into(),
        }
    }

    fn default_rust_bin() -> PathBuf {
        // Prefer release if present, otherwise debug, walking up to workspace root.
        let candidates = [
            PathBuf::from("target/release/gsutil"),
            PathBuf::from("target/debug/gsutil"),
            PathBuf::from("../../target/release/gsutil"),
            PathBuf::from("../../target/debug/gsutil"),
        ];
        for c in &candidates {
            if c.exists() {
                return c.clone();
            }
        }
        PathBuf::from("target/debug/gsutil")
    }

    pub fn ref_available(&self) -> bool {
        self.ref_bin.exists()
    }

    pub fn rust_available(&self) -> bool {
        self.rust_bin.exists()
    }

    /// Execute a single binary with `RunOptions`.
    pub fn run_binary(&self, bin: &Path, opts: &RunOptions) -> Result<InvocationOutput, String> {
        let mut cmd = Command::new(bin);
        cmd.args(&opts.args);
        cmd.env("GSUTIL_NO_BANNER", "true");
        // Ensure consistent locale/timezone formatting.
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

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        if opts.stdin.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        let start = Instant::now();
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn {}: {}", bin.display(), e))?;

        if let Some(ref input) = opts.stdin {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input);
            }
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("failed to wait on {}: {}", bin.display(), e))?;
        let elapsed: Duration = start.elapsed();

        Ok(InvocationOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            duration_ms: elapsed.as_millis() as u64,
        })
    }

    pub fn run_ref(&self, opts: &RunOptions) -> Result<InvocationOutput, String> {
        self.run_binary(&self.ref_bin, opts)
    }

    pub fn run_rust(&self, opts: &RunOptions) -> Result<InvocationOutput, String> {
        self.run_binary(&self.rust_bin, opts)
    }

    /// Run a differential comparison on identical args/options.
    #[allow(clippy::too_many_arguments)]
    pub fn run_diff(
        &self,
        id: impl Into<String>,
        category: impl Into<String>,
        command: impl Into<String>,
        ref_opts: &RunOptions,
        rust_opts: &RunOptions,
        stdout_rule: &CompareRule,
        stderr_rule: &CompareRule,
        ctx: &NormalizeContext,
    ) -> CaseResult {
        let id = id.into();
        let category = category.into();
        let command = command.into();

        if !self.ref_available() {
            return CaseResult {
                id,
                category,
                command,
                args: rust_opts.args.clone(),
                passed: false,
                skipped: true,
                skip_reason: Some(format!(
                    "reference gsutil not found at {}",
                    self.ref_bin.display()
                )),
                exit_code_match: false,
                ref_output: None,
                rust_output: None,
                stdout_cmp: None,
                stderr_cmp: None,
                side_effect_error: None,
            };
        }

        if !self.rust_available() {
            return CaseResult {
                id,
                category,
                command,
                args: rust_opts.args.clone(),
                passed: false,
                skipped: true,
                skip_reason: Some(format!(
                    "rust gsutil binary not found at {} (run `cargo build -p gsutil-cli`)",
                    self.rust_bin.display()
                )),
                exit_code_match: false,
                ref_output: None,
                rust_output: None,
                stdout_cmp: None,
                stderr_cmp: None,
                side_effect_error: None,
            };
        }

        let ref_out = match self.run_ref(ref_opts) {
            Ok(o) => o,
            Err(e) => {
                return CaseResult {
                    id,
                    category,
                    command,
                    args: rust_opts.args.clone(),
                    passed: false,
                    skipped: false,
                    skip_reason: None,
                    exit_code_match: false,
                    ref_output: None,
                    rust_output: None,
                    stdout_cmp: None,
                    stderr_cmp: None,
                    side_effect_error: Some(e),
                };
            }
        };

        let rust_out = match self.run_rust(rust_opts) {
            Ok(o) => o,
            Err(e) => {
                return CaseResult {
                    id,
                    category,
                    command,
                    args: rust_opts.args.clone(),
                    passed: false,
                    skipped: false,
                    skip_reason: None,
                    exit_code_match: false,
                    ref_output: Some(ref_out),
                    rust_output: None,
                    stdout_cmp: None,
                    stderr_cmp: None,
                    side_effect_error: Some(e),
                };
            }
        };

        let exit_code_match = ref_out.exit_code == rust_out.exit_code;
        let stdout_cmp = compare_stream(
            "stdout",
            &ref_out.stdout,
            &rust_out.stdout,
            stdout_rule,
            ctx,
        );
        let stderr_cmp = compare_stream(
            "stderr",
            &ref_out.stderr,
            &rust_out.stderr,
            stderr_rule,
            ctx,
        );
        let passed = exit_code_match && stdout_cmp.matched && stderr_cmp.matched;

        CaseResult {
            id,
            category,
            command,
            args: rust_opts.args.clone(),
            passed,
            skipped: false,
            skip_reason: None,
            exit_code_match,
            ref_output: Some(ref_out),
            rust_output: Some(rust_out),
            stdout_cmp: Some(stdout_cmp),
            stderr_cmp: Some(stderr_cmp),
            side_effect_error: None,
        }
    }

    /// Run Rust gsutil alone against a deterministic expected contract (used for
    /// hermetic plain-HTTP Mock GCS tests where Python gsutil cannot bypass TLS).
    #[allow(clippy::too_many_arguments)]
    pub fn run_rust_contract(
        &self,
        id: impl Into<String>,
        category: impl Into<String>,
        command: impl Into<String>,
        opts: &RunOptions,
        expected_exit: i32,
        expected_stdout: &str,
        stdout_rule: &CompareRule,
        expected_stderr: &str,
        stderr_rule: &CompareRule,
        ctx: &NormalizeContext,
    ) -> CaseResult {
        let id = id.into();
        let category = category.into();
        let command = command.into();

        if !self.rust_available() {
            return CaseResult {
                id,
                category,
                command,
                args: opts.args.clone(),
                passed: false,
                skipped: true,
                skip_reason: Some(format!(
                    "rust gsutil binary not found at {}",
                    self.rust_bin.display()
                )),
                exit_code_match: false,
                ref_output: None,
                rust_output: None,
                stdout_cmp: None,
                stderr_cmp: None,
                side_effect_error: None,
            };
        }

        let rust_out = match self.run_rust(opts) {
            Ok(o) => o,
            Err(e) => {
                return CaseResult {
                    id,
                    category,
                    command,
                    args: opts.args.clone(),
                    passed: false,
                    skipped: false,
                    skip_reason: None,
                    exit_code_match: false,
                    ref_output: None,
                    rust_output: None,
                    stdout_cmp: None,
                    stderr_cmp: None,
                    side_effect_error: Some(e),
                };
            }
        };

        let ref_stub = InvocationOutput {
            exit_code: expected_exit,
            stdout: expected_stdout.to_string(),
            stderr: expected_stderr.to_string(),
            duration_ms: 0,
        };
        let exit_code_match = rust_out.exit_code == expected_exit;
        let stdout_cmp = compare_stream(
            "stdout",
            expected_stdout,
            &rust_out.stdout,
            stdout_rule,
            ctx,
        );
        let stderr_cmp = compare_stream(
            "stderr",
            expected_stderr,
            &rust_out.stderr,
            stderr_rule,
            ctx,
        );
        let passed = exit_code_match && stdout_cmp.matched && stderr_cmp.matched;

        CaseResult {
            id,
            category,
            command,
            args: opts.args.clone(),
            passed,
            skipped: false,
            skip_reason: None,
            exit_code_match,
            ref_output: Some(ref_stub),
            rust_output: Some(rust_out),
            stdout_cmp: Some(stdout_cmp),
            stderr_cmp: Some(stderr_cmp),
            side_effect_error: None,
        }
    }
}
