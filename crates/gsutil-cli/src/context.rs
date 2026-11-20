//! Execution context passed to all gsutil commands.

use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};
use std::sync::Arc;

use gsutil_core::api::{CloudApi, Preconditions};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result};

use crate::global_opts::GlobalOptions;

/// Current emulated gsutil version string (matches reference Python gsutil v5.38).
pub const GSUTIL_VERSION: &str = "5.38";

/// Shared execution context for a single gsutil command invocation.
pub struct CommandContext {
    pub config: BotoConfig,
    pub global: GlobalOptions,
    pub api: Option<Arc<dyn CloudApi>>,
    pub command_alias_used: String,
    pub is_tty: bool,
}

impl CommandContext {
    pub fn new(config: BotoConfig, global: GlobalOptions, api: Option<Arc<dyn CloudApi>>) -> Self {
        let is_tty = io::stdout().is_terminal() && io::stderr().is_terminal();
        Self {
            config,
            global,
            api,
            command_alias_used: String::new(),
            is_tty,
        }
    }

    /// Return the configured `CloudApi`, lazily constructing a `GcsJsonClient`
    /// backed by `gsutil-auth` if none was explicitly injected.
    pub async fn api(&mut self) -> Result<Arc<dyn CloudApi>> {
        if let Some(ref existing) = self.api {
            return Ok(existing.clone());
        }
        let creds = gsutil_auth::resolve_credentials(
            &self.config,
            self.global.impersonate_service_account.as_deref(),
        )
        .await?;
        let mut client_cfg = gsutil_gcs::GcsJsonClientConfig::from_boto_config(&self.config)?;
        client_cfg.user_project = self.global.user_project.clone();
        client_cfg.custom_headers = self.global.headers.clone();
        client_cfg.trace_token = self.global.trace_token.clone();
        client_cfg.perf_trace_token = self.global.perf_trace_token.clone();
        let gs_json: Arc<dyn CloudApi> = Arc::new(gsutil_gcs::GcsJsonClient::with_http_config(
            &self.config,
            client_cfg,
            creds.clone(),
        )?);
        let gs_xml: Arc<dyn CloudApi> = Arc::new(gsutil_gcs::XmlApiClient::new(
            "gs",
            &self.config,
            creds.clone(),
        ));
        let s3_xml: Arc<dyn CloudApi> =
            Arc::new(gsutil_gcs::XmlApiClient::new("s3", &self.config, creds));
        let delegator = gsutil_gcs::CloudApiDelegator::from_clients(
            &self.config,
            "gs",
            gs_json,
            gs_xml,
            s3_xml,
        );
        let arc: Arc<dyn CloudApi> = Arc::new(delegator);
        self.api = Some(arc.clone());
        Ok(arc)
    }

    /// Effective project ID: explicit flag override, else `GSUtil:default_project_id`, else `GOOGLE_CLOUD_PROJECT`.
    pub fn effective_project_id<'a>(&'a self, explicit: Option<&'a str>) -> Option<&'a str> {
        if let Some(p) = explicit {
            if !p.is_empty() {
                return Some(p);
            }
        }
        self.config.default_project_id()
    }

    /// Write a line to stdout, converting `ErrorKind::BrokenPipe` into `GsutilError::BrokenPipe`.
    pub fn println(&self, s: &str) -> Result<()> {
        let mut out = io::stdout().lock();
        if let Err(e) = writeln!(out, "{s}") {
            if e.kind() == io::ErrorKind::BrokenPipe {
                return Err(GsutilError::BrokenPipe);
            }
            return Err(GsutilError::Io(e));
        }
        Ok(())
    }

    /// Write raw bytes to stdout, converting `ErrorKind::BrokenPipe` into `GsutilError::BrokenPipe`.
    pub fn write_stdout(&self, bytes: &[u8]) -> Result<()> {
        let mut out = io::stdout().lock();
        if let Err(e) = out.write_all(bytes) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                return Err(GsutilError::BrokenPipe);
            }
            return Err(GsutilError::Io(e));
        }
        Ok(())
    }

    /// Flush stdout, converting `ErrorKind::BrokenPipe` into `GsutilError::BrokenPipe`.
    pub fn flush_stdout(&self) -> Result<()> {
        let mut out = io::stdout().lock();
        if let Err(e) = out.flush() {
            if e.kind() == io::ErrorKind::BrokenPipe {
                return Err(GsutilError::BrokenPipe);
            }
            return Err(GsutilError::Io(e));
        }
        Ok(())
    }

    /// Log an informational status message to stderr unless `-q` (`--quiet`) is set.
    pub fn info(&self, msg: &str) {
        if !self.global.quiet {
            let _ = writeln!(io::stderr(), "{msg}");
        }
    }

    /// Log a warning message to stderr.
    pub fn warn(&self, msg: &str) {
        let _ = writeln!(io::stderr(), "{msg}");
    }

    /// Log an error message to stderr.
    pub fn error(&self, msg: &str) {
        let _ = writeln!(io::stderr(), "{msg}");
    }

    /// Extract preconditions from global `-h` headers (`x-goog-if-generation-match`,
    /// `x-goog-if-metageneration-match`).
    pub fn preconditions_from_headers(&self) -> Result<Preconditions> {
        preconditions_from_headers(&self.global.headers)
    }
}

/// Parse GCS preconditions from HTTP headers map (lowercased keys).
pub fn preconditions_from_headers(headers: &BTreeMap<String, String>) -> Result<Preconditions> {
    let mut precond = Preconditions::default();
    if let Some(v) = headers.get("x-goog-if-generation-match") {
        let parsed = v.trim().parse::<i64>().map_err(|_| {
            GsutilError::command(format!("Invalid value for x-goog-if-generation-match: {v}"))
        })?;
        precond.gen_match = Some(parsed);
    }
    if let Some(v) = headers.get("x-goog-if-metageneration-match") {
        let parsed = v.trim().parse::<i64>().map_err(|_| {
            GsutilError::command(format!(
                "Invalid value for x-goog-if-metageneration-match: {v}"
            ))
        })?;
        precond.meta_gen_match = Some(parsed);
    }
    Ok(precond)
}

/// Validate that a string contains only ASCII characters.
pub fn insist_ascii(val: &str, msg: &str) -> Result<()> {
    if !val.is_ascii() {
        return Err(GsutilError::command(msg));
    }
    Ok(())
}

/// Validate that a value is `"on"` or `"off"` (case-sensitive, matching `InsistOnOrOff`).
pub fn insist_on_or_off(val: &str, msg: &str) -> Result<()> {
    if val != "on" && val != "off" {
        return Err(GsutilError::command(msg));
    }
    Ok(())
}
