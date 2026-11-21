//! `.boto` INI configuration loader, `-o section:key=val` overrides,
//! defaults, proxy resolution, and debug redaction.
//!
//! Matches `gslib/utils/boto_util.py`, `gslib/commands/config.py`, and
//! `gslib/__main__.py` in Python gsutil v5.38.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{GsutilError, Result};

pub const ONE_KIB: u64 = 1024;
pub const ONE_MIB: u64 = 1024 * ONE_KIB;
pub const ONE_GIB: u64 = 1024 * ONE_MIB;

pub const DEFAULT_GCS_JSON_API_VERSION: &str = "v1";
pub const DEFAULT_RESUMABLE_THRESHOLD: u64 = 8 * ONE_MIB;
pub const DEFAULT_JSON_RESUMABLE_CHUNK_SIZE: u64 = 100 * ONE_MIB;
pub const RESUMABLE_CHUNK_QUANTUM: u64 = 256 * ONE_KIB;
pub const DEFAULT_NUM_RETRIES: u32 = 23;
pub const DEFAULT_MAX_RETRY_DELAY: u64 = 32;
pub const DEFAULT_SSL_TIMEOUT_SEC: u64 = 60;
pub const DEFAULT_CHECK_HASHES: &str = "if_fast_else_fail";

/// Keys redacted from `gsutil -D` config output (matches `CONFIG_KEYS_TO_REDACT` in `gslib/__main__.py`).
pub const CONFIG_KEYS_TO_REDACT: &[&str] = &["proxy", "proxy_port", "proxy_user", "proxy_pass"];

/// Proxy type supported by boto / gsutil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyType {
    Http,
    Socks4,
    Socks5,
}

impl ProxyType {
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "socks4" => Self::Socks4,
            "socks5" => Self::Socks5,
            _ => Self::Http,
        }
    }

    pub fn scheme(&self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Socks4 => "socks4",
            Self::Socks5 => "socks5",
        }
    }
}

/// Resolved proxy configuration (from `.boto` or environment variables).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub rdns: bool,
}

impl ProxyConfig {
    /// Format as a URL string suitable for HTTP clients (e.g. `reqwest::Proxy`).
    pub fn to_url(&self) -> String {
        let scheme = self.proxy_type.scheme();
        match (&self.user, &self.pass) {
            (Some(u), Some(p)) => format!("{scheme}://{u}:{p}@{}:{}", self.host, self.port),
            (Some(u), None) => format!("{scheme}://{u}@{}:{}", self.host, self.port),
            _ => format!("{scheme}://{}:{}", self.host, self.port),
        }
    }
}

/// Parsed `.boto` INI configuration with `-o` overrides and loaded file tracking.
#[derive(Debug, Clone, Default)]
pub struct BotoConfig {
    /// Map of `SectionName` -> (`lowercase_key` -> `value`).
    sections: BTreeMap<String, BTreeMap<String, String>>,
    /// Readable config file paths that were discovered/loaded.
    loaded_files: Vec<PathBuf>,
}

impl BotoConfig {
    /// Create an empty configuration (with gsutil default `https_validate_certificates = true`).
    pub fn new() -> Self {
        let mut cfg = Self::default();
        cfg.set("Boto", "https_validate_certificates", "True");
        cfg
    }

    /// Load `.boto` configuration from standard locations (`BOTO_CONFIG`, `BOTO_PATH`,
    /// `/etc/boto.cfg`, `~/.boto`).
    pub fn load_default() -> Self {
        let paths = discover_boto_config_paths();
        Self::load_from_paths(&paths)
    }

    /// Load configuration by merging the given INI files in order (later overrides earlier).
    pub fn load_from_paths(paths: &[PathBuf]) -> Self {
        let mut cfg = Self::new();
        for path in paths {
            if let Ok(contents) = fs::read_to_string(path) {
                cfg.parse_ini_str(&contents);
                cfg.loaded_files.push(path.clone());
            }
        }
        cfg
    }

    /// Parse an INI string and merge its sections/keys into this config.
    pub fn parse_ini_str(&mut self, input: &str) {
        let mut current_section: Option<String> = None;
        let mut last_key: Option<String> = None;
        let mut last_key_indent: usize = 0;

        for raw_line in input.lines() {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            let indent = raw_line.len() - raw_line.trim_start().len();

            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                let sec = trimmed[1..trimmed.len() - 1].trim().to_string();
                self.sections.entry(sec.clone()).or_default();
                current_section = Some(sec);
                last_key = None;
                last_key_indent = 0;
                continue;
            }

            // Continuation line (indented strictly deeper than the key) appends to previous value.
            if indent > last_key_indent && current_section.is_some() && last_key.is_some() {
                if let (Some(sec), Some(key)) = (&current_section, &last_key) {
                    if let Some(val) = self.sections.entry(sec.clone()).or_default().get_mut(key) {
                        val.push('\n');
                        val.push_str(trimmed);
                    }
                }
                continue;
            }

            if let Some(ref sec) = current_section {
                if let Some((k, v)) = split_ini_kv(trimmed) {
                    let key_lower = k.to_ascii_lowercase();
                    self.sections
                        .entry(sec.clone())
                        .or_default()
                        .insert(key_lower.clone(), v.to_string());
                    last_key = Some(key_lower);
                    last_key_indent = indent;
                }
            }
        }
    }

    /// Apply a `-o section:key=value` CLI override.
    /// Matches Python `gslib/__main__.py` (`partition('=')` then `partition(':')`),
    /// where omitting `=value` sets the key to `""`.
    pub fn apply_override(&mut self, spec: &str) -> Result<()> {
        let (sec_key, val) = match spec.split_once('=') {
            Some((sk, v)) => (sk, v),
            None => (spec, ""),
        };
        let (sec, key) = sec_key.split_once(':').ok_or_else(|| {
            GsutilError::command(format!(
                "Invalid -o option \"{spec}\": expected section:key=value"
            ))
        })?;
        if sec.is_empty() || key.is_empty() {
            return Err(GsutilError::command(format!(
                "Invalid -o option \"{spec}\": expected section:key=value"
            )));
        }
        self.set(sec, key, val);
        Ok(())
    }

    /// Set a config option.
    pub fn set(&mut self, section: &str, key: &str, value: impl Into<String>) {
        self.sections
            .entry(section.to_string())
            .or_default()
            .insert(key.to_ascii_lowercase(), value.into());
    }

    /// Get a raw string value.
    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        self.sections
            .get(section)
            .and_then(|s| s.get(&key.to_ascii_lowercase()))
            .map(String::as_str)
    }

    /// Get a string value with a default.
    pub fn get_or<'a>(&'a self, section: &str, key: &str, default: &'a str) -> &'a str {
        self.get(section, key).unwrap_or(default)
    }

    /// Check whether an option is present.
    pub fn has_option(&self, section: &str, key: &str) -> bool {
        self.get(section, key).is_some()
    }

    /// Get a boolean value with a default (matches Python configparser/boto `getbool`).
    pub fn get_bool(&self, section: &str, key: &str, default: bool) -> bool {
        match self.get(section, key) {
            Some(v) => match v.trim().to_ascii_lowercase().as_str() {
                "1" | "yes" | "true" | "on" => true,
                "0" | "no" | "false" | "off" => false,
                _ => default,
            },
            None => default,
        }
    }

    /// Get a `u64` integer value with a default.
    pub fn get_u64(&self, section: &str, key: &str, default: u64) -> u64 {
        self.get(section, key)
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(default)
    }

    /// Get a `u32` integer value with a default.
    pub fn get_u32(&self, section: &str, key: &str, default: u32) -> u32 {
        self.get(section, key)
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(default)
    }

    /// Get a human-readable byte size (e.g. `150M`, `2GiB`, `8MiB`, `1048576`).
    pub fn get_size_bytes(&self, section: &str, key: &str, default: u64) -> u64 {
        self.get(section, key)
            .and_then(parse_human_readable_bytes)
            .unwrap_or(default)
    }

    /// Return all `(key, value)` pairs in a section.
    pub fn section_items(&self, section: &str) -> Vec<(String, String)> {
        self.sections
            .get(section)
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }

    /// Return redacted debug config items for `Boto` and `GSUtil` sections
    /// (matching `gslib/__main__.py` `-D` output).
    pub fn redacted_debug_items(&self) -> Vec<(String, String)> {
        let mut items = Vec::new();
        for section in ["Boto", "GSUtil"] {
            for (k, v) in self.section_items(section) {
                if CONFIG_KEYS_TO_REDACT.contains(&k.as_str()) {
                    items.push((k, "REDACTED".to_string()));
                } else {
                    items.push((k, v));
                }
            }
        }
        items
    }

    /// Return readable config file paths that were loaded.
    pub fn loaded_files(&self) -> &[PathBuf] {
        &self.loaded_files
    }

    /// Like `GetFriendlyConfigFilePaths` in `gslib/utils/boto_util.py`.
    pub fn friendly_config_file_paths(&self) -> Vec<String> {
        if self.loaded_files.is_empty() {
            vec!["No config found".to_string()]
        } else {
            self.loaded_files
                .iter()
                .map(|p| p.display().to_string())
                .collect()
        }
    }

    // ---- Standard gsutil typed accessors ----

    pub fn is_secure(&self) -> bool {
        self.get_bool("Boto", "is_secure", true)
    }

    pub fn https_validate_certificates(&self) -> bool {
        self.get_bool("Boto", "https_validate_certificates", true)
    }

    pub fn ca_certificates_file(&self) -> Option<&str> {
        self.get("Boto", "ca_certificates_file")
            .filter(|v| !v.is_empty() && *v != "system")
    }

    pub fn num_retries(&self) -> u32 {
        self.get_u32("Boto", "num_retries", DEFAULT_NUM_RETRIES)
    }

    pub fn max_retry_delay(&self) -> u64 {
        self.get_u64("Boto", "max_retry_delay", DEFAULT_MAX_RETRY_DELAY)
    }

    pub fn gcs_json_api_version(&self) -> &str {
        self.get_or("GSUtil", "json_api_version", DEFAULT_GCS_JSON_API_VERSION)
    }

    pub fn default_project_id(&self) -> Option<&str> {
        self.get("GSUtil", "default_project_id")
            .filter(|s| !s.trim().is_empty())
    }

    pub fn resumable_threshold(&self) -> u64 {
        self.get_size_bytes("GSUtil", "resumable_threshold", DEFAULT_RESUMABLE_THRESHOLD)
    }

    /// Resumable chunk size, rounded up to a multiple of 256 KiB (matches `GetJsonResumableChunkSize`).
    pub fn json_resumable_chunk_size(&self) -> u64 {
        let mut size = self.get_u64(
            "GSUtil",
            "json_resumable_chunk_size",
            DEFAULT_JSON_RESUMABLE_CHUNK_SIZE,
        );
        if size == 0 {
            size = RESUMABLE_CHUNK_QUANTUM;
        } else if !size.is_multiple_of(RESUMABLE_CHUNK_QUANTUM) {
            size += RESUMABLE_CHUNK_QUANTUM - (size % RESUMABLE_CHUNK_QUANTUM);
        }
        size
    }

    pub fn check_hashes(&self) -> &str {
        self.get_or("GSUtil", "check_hashes", DEFAULT_CHECK_HASHES)
    }

    pub fn state_dir(&self) -> PathBuf {
        if let Some(dir) = self.get("GSUtil", "state_dir") {
            return expand_tilde(dir);
        }
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".gsutil")
    }

    /// Default is `0` (disabled), matching Python `gslib/commands/config.py`.
    pub fn parallel_composite_upload_threshold(&self) -> u64 {
        self.get_size_bytes("GSUtil", "parallel_composite_upload_threshold", 0)
    }

    pub fn parallel_composite_upload_component_size(&self) -> u64 {
        self.get_size_bytes(
            "GSUtil",
            "parallel_composite_upload_component_size",
            50 * ONE_MIB,
        )
    }

    pub fn sliced_object_download_threshold(&self) -> u64 {
        self.get_size_bytes("GSUtil", "sliced_object_download_threshold", 150 * ONE_MIB)
    }

    pub fn sliced_object_download_max_components(&self) -> usize {
        self.get_u64("GSUtil", "sliced_object_download_max_components", 8) as usize
    }

    pub fn sliced_object_download_component_size(&self) -> u64 {
        self.get_size_bytes(
            "GSUtil",
            "sliced_object_download_component_size",
            10 * ONE_MIB,
        )
    }

    pub fn parallel_thread_count(&self) -> usize {
        self.get_u64("GSUtil", "parallel_thread_count", 24) as usize
    }

    pub fn parallel_process_count(&self) -> usize {
        self.get_u64("GSUtil", "parallel_process_count", 1) as usize
    }

    /// Returns `true` if any credential fields are configured in `[Credentials]`.
    pub fn has_configured_credentials(&self) -> bool {
        let has_goog_hmac = self.has_option("Credentials", "gs_access_key_id")
            && self.has_option("Credentials", "gs_secret_access_key");
        let has_aws_hmac = self.has_option("Credentials", "aws_access_key_id")
            && self.has_option("Credentials", "aws_secret_access_key");
        let has_oauth = self.has_option("Credentials", "gs_oauth2_refresh_token");
        let has_sa = self.has_option("Credentials", "gs_service_key_file");
        let has_external = self.has_option("Credentials", "gs_external_account_file")
            || self.has_option("Credentials", "gs_external_account_authorized_user_file");

        has_goog_hmac || has_aws_hmac || has_oauth || has_sa || has_external
    }

    /// Returns `true` if GCS HMAC credentials are configured without OAuth2/SA credentials.
    pub fn using_gs_hmac(&self) -> bool {
        let has_oauth = self.has_option("Credentials", "gs_oauth2_refresh_token");
        let has_sa = self.has_option("Credentials", "gs_service_client_id")
            && self.has_option("Credentials", "gs_service_key_file");
        let has_hmac = self.has_option("Credentials", "gs_access_key_id")
            && self.has_option("Credentials", "gs_secret_access_key");
        !has_oauth && !has_sa && has_hmac
    }

    /// Resolve proxy settings from `[Boto]` config, falling back to `http_proxy`,
    /// `https_proxy`, `HTTPS_PROXY` environment variables (matching `SetProxyInfo`).
    pub fn resolve_proxy(&self) -> Option<ProxyConfig> {
        let host = self.get("Boto", "proxy").filter(|s| !s.is_empty());
        let raw_proxy_type = self.get_or("Boto", "proxy_type", "http");
        let proxy_type = ProxyType::from_str_lossy(raw_proxy_type);
        let parsed_port = self
            .get("Boto", "proxy_port")
            .and_then(|s| s.trim().parse::<u16>().ok())
            .filter(|&p| p > 0);
        let user = self
            .get("Boto", "proxy_user")
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
        let pass = self
            .get("Boto", "proxy_pass")
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);

        if let (Some(h), Some(port)) = (host, parsed_port) {
            let rdns = if proxy_type == ProxyType::Http {
                self.get_bool("Boto", "proxy_rdns", true)
            } else {
                false
            };
            return Some(ProxyConfig {
                proxy_type,
                host: h.to_string(),
                port,
                user,
                pass,
                rdns,
            });
        }

        for env_var in ["http_proxy", "https_proxy", "HTTPS_PROXY"] {
            if let Ok(raw) = env::var(env_var) {
                if !raw.trim().is_empty() {
                    if let Some(mut proxy) = parse_proxy_env_url(env_var, &raw) {
                        if !self.has_option("Boto", "proxy_rdns") {
                            proxy.rdns = true;
                        } else {
                            proxy.rdns = self.get_bool("Boto", "proxy_rdns", true);
                        }
                        return Some(proxy);
                    }
                }
            }
        }

        // If `[Boto] proxy` is set without `proxy_port` (and no env proxy), default to 443/80.
        if let Some(h) = host {
            let default_port = if raw_proxy_type.eq_ignore_ascii_case("https") {
                443
            } else {
                80
            };
            let rdns = if proxy_type == ProxyType::Http {
                self.get_bool("Boto", "proxy_rdns", true)
            } else {
                false
            };
            return Some(ProxyConfig {
                proxy_type,
                host: h.to_string(),
                port: default_port,
                user,
                pass,
                rdns,
            });
        }

        None
    }
}

/// Discover boto config file paths according to `BOTO_CONFIG`, `BOTO_PATH`,
/// `/etc/boto.cfg`, and `~/.boto`.
pub fn discover_boto_config_paths() -> Vec<PathBuf> {
    if let Ok(cfg) = env::var("BOTO_CONFIG") {
        if !cfg.trim().is_empty() {
            return vec![expand_tilde(&cfg)];
        }
    }

    if let Ok(path_list) = env::var("BOTO_PATH") {
        if !path_list.trim().is_empty() {
            let sep = if cfg!(windows) { ';' } else { ':' };
            return path_list
                .split(sep)
                .filter(|p| !p.trim().is_empty())
                .map(expand_tilde)
                .collect();
        }
    }

    let mut paths = vec![PathBuf::from("/etc/boto.cfg")];
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".boto"));
    }
    paths
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    Path::new(path).to_path_buf()
}

fn split_ini_kv(line: &str) -> Option<(&str, &str)> {
    let eq_pos = line.find('=');
    let colon_pos = line.find(':');
    let idx = match (eq_pos, colon_pos) {
        (Some(e), Some(c)) => e.min(c),
        (Some(e), None) => e,
        (None, Some(c)) => c,
        (None, None) => return None,
    };
    let k = line[..idx].trim();
    let v = line[idx + 1..].trim();
    if k.is_empty() {
        None
    } else {
        Some((k, v))
    }
}

fn parse_proxy_env_url(env_var: &str, raw: &str) -> Option<ProxyConfig> {
    let lower_var = env_var.to_ascii_lowercase();
    if !lower_var.starts_with("http") {
        return None;
    }
    let proto = lower_var.split('_').next().unwrap_or("http");
    let full = if raw.to_ascii_lowercase().starts_with("http") {
        raw.to_string()
    } else {
        format!("{proto}://{raw}")
    };
    let parsed = url::Url::parse(&full).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let user = if parsed.username().is_empty() {
        None
    } else {
        Some(parsed.username().to_string())
    };
    let pass = parsed.password().map(ToString::to_string);
    Some(ProxyConfig {
        proxy_type: ProxyType::Http,
        host,
        port,
        user,
        pass,
        rdns: true,
    })
}

/// Parse human-readable byte sizes like `"150M"`, `"2GiB"`, `"10K"`, `"512"`, `"0"`.
pub fn parse_human_readable_bytes(s: &str) -> Option<u64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    let split_idx = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let num: u64 = trimmed[..split_idx].parse().ok()?;
    let suffix = trimmed[split_idx..].trim().to_ascii_lowercase();
    let mult: u64 = match suffix.as_str() {
        "" | "b" => 1,
        "k" | "kb" | "ki" | "kib" => ONE_KIB,
        "m" | "mb" | "mi" | "mib" => ONE_MIB,
        "g" | "gb" | "gi" | "gib" => ONE_GIB,
        "t" | "tb" | "ti" | "tib" => 1024 * ONE_GIB,
        _ => return None,
    };
    num.checked_mul(mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ini_parse_and_overrides() {
        let mut cfg = BotoConfig::new();
        cfg.parse_ini_str(
            r#"
            # Comment
            [Credentials]
            gs_oauth2_refresh_token = secret_tok

            [Boto]
            num_retries = 10
            proxy = proxy.example.com
            proxy_port = 8080
            proxy_pass = supersecret

            [GSUtil]
            default_project_id = my-proj
            parallel_composite_upload_threshold = 150M
            json_resumable_chunk_size = 300000
            "#,
        );

        assert_eq!(cfg.default_project_id(), Some("my-proj"));
        assert_eq!(cfg.num_retries(), 10);
        assert_eq!(cfg.parallel_composite_upload_threshold(), 150 * ONE_MIB);
        // 300000 rounded up to multiple of 256 KiB (262144 * 2 = 524288)
        assert_eq!(cfg.json_resumable_chunk_size(), 524_288);
        assert!(cfg.has_configured_credentials());
        assert!(!cfg.using_gs_hmac());

        cfg.apply_override("GSUtil:default_project_id=override-proj")
            .unwrap();
        assert_eq!(cfg.default_project_id(), Some("override-proj"));
        // Missing `=` sets empty string (matching Python partition('=')).
        cfg.apply_override("GSUtil:empty_opt").unwrap();
        assert_eq!(cfg.get("GSUtil", "empty_opt"), Some(""));
        assert!(cfg.apply_override("bad_format").is_err());
        assert!(cfg.apply_override(":missing_section=1").is_err());
        assert!(cfg.apply_override("GSUtil:=1").is_err());

        let redacted = cfg.redacted_debug_items();
        assert!(redacted
            .iter()
            .any(|(k, v)| k == "proxy_pass" && v == "REDACTED"));
        assert!(redacted
            .iter()
            .any(|(k, v)| k == "proxy" && v == "REDACTED"));
        assert!(redacted
            .iter()
            .any(|(k, v)| k == "default_project_id" && v == "override-proj"));
    }

    #[test]
    fn test_proxy_resolution_from_boto() {
        let mut cfg = BotoConfig::new();
        cfg.set("Boto", "proxy", "127.0.0.1");
        cfg.set("Boto", "proxy_port", "3128");
        cfg.set("Boto", "proxy_user", "alice");
        cfg.set("Boto", "proxy_pass", "pw");

        let proxy = cfg.resolve_proxy().unwrap();
        assert_eq!(proxy.host, "127.0.0.1");
        assert_eq!(proxy.port, 3128);
        assert_eq!(proxy.to_url(), "http://alice:pw@127.0.0.1:3128");
        assert!(proxy.rdns);
    }

    #[test]
    fn test_parse_human_readable_bytes() {
        assert_eq!(parse_human_readable_bytes("0"), Some(0));
        assert_eq!(parse_human_readable_bytes("150M"), Some(150 * ONE_MIB));
        assert_eq!(parse_human_readable_bytes("2GiB"), Some(2 * ONE_GIB));
        assert_eq!(parse_human_readable_bytes("64K"), Some(64 * ONE_KIB));
    }
}
