//! Application Default Credentials (ADC) and `gcloud` active user credentials.
//!
//! Supports:
//! - `GOOGLE_APPLICATION_CREDENTIALS` env var
//! - `~/.config/gcloud/application_default_credentials.json` (authorized_user or service_account)
//! - `gcloud auth print-access-token` fallback (which natively handles Context-Aware Access mTLS/ECP,
//!   reauth/RAPT challenges, and active `gcloud` configurations)

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result, ServiceError};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tokio::sync::RwLock;

use crate::oauth2::OAuth2UserCredentials;
use crate::service_account::ServiceAccountCredentials;
use crate::{AccessToken, CredentialType, TokenProvider, DEFAULT_TOKEN_URI};

/// Standard ADC JSON file for `type = "authorized_user"`.
#[derive(Deserialize)]
struct AdcAuthorizedUser {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    #[serde(default)]
    quota_project_id: Option<String>,
    #[serde(default)]
    token_uri: Option<String>,
}

/// Loader for Application Default Credentials JSON files.
pub struct AdcCredentials;

impl AdcCredentials {
    /// Discover the default ADC file path:
    /// 1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable
    /// 2. `$CLOUDSDK_CONFIG/application_default_credentials.json` or
    ///    `~/.config/gcloud/application_default_credentials.json`
    pub fn default_adc_path() -> Option<PathBuf> {
        if let Ok(path) = env::var("GOOGLE_APPLICATION_CREDENTIALS") {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                return Some(PathBuf::from(trimmed));
            }
        }
        Self::well_known_adc_path()
    }

    /// Well-known gcloud ADC path (`~/.config/gcloud/application_default_credentials.json`).
    pub fn well_known_adc_path() -> Option<PathBuf> {
        if let Ok(cfg_dir) = env::var("CLOUDSDK_CONFIG") {
            let trimmed = cfg_dir.trim();
            if !trimmed.is_empty() {
                return Some(PathBuf::from(trimmed).join("application_default_credentials.json"));
            }
        }
        dirs::home_dir().map(|h| {
            h.join(".config")
                .join("gcloud")
                .join("application_default_credentials.json")
        })
    }

    /// Load credentials from an ADC JSON file (`authorized_user` or `service_account`).
    pub fn from_file(
        path: &Path,
        token_uri_override: Option<&str>,
        http: Client,
    ) -> Result<Arc<dyn TokenProvider>> {
        let raw = fs::read_to_string(path).map_err(|e| {
            GsutilError::command(format!(
                "Could not read Application Default Credentials file \"{}\": {e}",
                path.display()
            ))
        })?;
        Self::from_json_str(&raw, &path.display().to_string(), token_uri_override, http)
    }

    /// Parse an ADC JSON payload into a concrete [`TokenProvider`].
    pub fn from_json_str(
        raw: &str,
        source_name: &str,
        token_uri_override: Option<&str>,
        http: Client,
    ) -> Result<Arc<dyn TokenProvider>> {
        let val: serde_json::Value = serde_json::from_str(raw).map_err(|e| {
            GsutilError::command(format!(
                "Could not parse ADC file \"{source_name}\" as valid JSON: {e}"
            ))
        })?;

        let cred_type = val.get("type").and_then(|v| v.as_str()).unwrap_or_default();

        match cred_type {
            "service_account" => {
                let sa = ServiceAccountCredentials::from_json_str(
                    raw,
                    source_name,
                    token_uri_override,
                    http,
                )?;
                Ok(Arc::new(sa))
            }
            "authorized_user" => {
                let user: AdcAuthorizedUser = serde_json::from_value(val).map_err(|e| {
                    GsutilError::command(format!(
                        "Invalid authorized_user ADC file \"{source_name}\": {e}"
                    ))
                })?;
                let token_uri = token_uri_override
                    .or(user.token_uri.as_deref())
                    .unwrap_or(DEFAULT_TOKEN_URI);
                let creds = OAuth2UserCredentials::new(
                    user.client_id,
                    user.client_secret,
                    user.refresh_token,
                    token_uri,
                    user.quota_project_id,
                    CredentialType::ApplicationDefault,
                    http,
                );
                Ok(Arc::new(creds))
            }
            other => Err(GsutilError::command(format!(
                "Unsupported ADC credential type \"{other}\" in \"{source_name}\""
            ))),
        }
    }
}

/// Discover an Enterprise Certificate Proxy (ECP) certificate config file, if present.
///
/// Checks `CLOUDSDK_CONTEXT_AWARE_CERTIFICATE_CONFIG_FILE_PATH`,
/// `~/.config/gcloud/certificate_config.json`, and `/etc/gcloud/certificate_config.json`.
pub fn certificate_config_path() -> Option<PathBuf> {
    if let Ok(path) = env::var("CLOUDSDK_CONTEXT_AWARE_CERTIFICATE_CONFIG_FILE_PATH") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            let pb = PathBuf::from(trimmed);
            if pb.is_file() {
                return Some(pb);
            }
        }
    }
    if let Some(home) = dirs::home_dir() {
        let user_cfg = home
            .join(".config")
            .join("gcloud")
            .join("certificate_config.json");
        if user_cfg.is_file() {
            return Some(user_cfg);
        }
    }
    #[cfg(windows)]
    {
        if let Ok(appdata) = env::var("APPDATA") {
            let win_user_cfg = PathBuf::from(appdata)
                .join("gcloud")
                .join("certificate_config.json");
            if win_user_cfg.is_file() {
                return Some(win_user_cfg);
            }
        }
        if let Ok(progdata) = env::var("PROGRAMDATA") {
            let win_sys_cfg = PathBuf::from(progdata)
                .join("Google")
                .join("Cloud SDK")
                .join("certificate_config.json");
            if win_sys_cfg.is_file() {
                return Some(win_sys_cfg);
            }
        }
    }
    let system_cfg = PathBuf::from("/etc/gcloud/certificate_config.json");
    if system_cfg.is_file() {
        return Some(system_cfg);
    }
    None
}

/// Detect whether mTLS / Context-Aware Access (ECP) client certificates are enabled
/// in `.boto`, Cloud SDK environment variables, or an installed `certificate_config.json`.
pub fn is_mtls_enabled(config: &BotoConfig) -> bool {
    if config.has_option("Credentials", "use_client_certificate") {
        return config.get_bool("Credentials", "use_client_certificate", false);
    }
    for var in [
        "CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE",
        "GOOGLE_API_USE_CLIENT_CERTIFICATE",
    ] {
        if let Ok(val) = env::var(var) {
            match val.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => return true,
                "false" | "0" | "no" => return false,
                _ => {}
            }
        }
    }
    if let Ok(val) = env::var("CLOUDSDK_CONTEXT_AWARE_USE_ECP_HTTP_PROXY") {
        if matches!(
            val.trim().to_ascii_lowercase().as_str(),
            "false" | "0" | "no"
        ) {
            return false;
        }
    }
    certificate_config_path().is_some()
}

/// On-disk cache entry for `gcloud auth print-access-token` (`0600` permissions).
#[derive(Serialize, Deserialize)]
struct GcloudDiskTokenCache {
    cache_key: String,
    access_token: String,
    expires_at: DateTime<Utc>,
}

/// Default TTL for cached gcloud access tokens (45 minutes; Google tokens live 60 minutes).
const GCLOUD_TOKEN_CACHE_TTL_SECS: i64 = 45 * 60;

/// Credentials retrieved via `gcloud auth print-access-token`.
///
/// Automatically supports active `gcloud` accounts, Context-Aware Access mTLS/ECP, and reauth sessions.
/// Caches tokens on disk (`0600` permissions) under `state_dir` so repeated CLI invocations
/// avoid spawning the Python `gcloud` subprocess.
#[derive(Debug)]
pub struct GcloudCredentials {
    gcloud_bin: String,
    cache_file: Option<PathBuf>,
    cached: RwLock<Option<AccessToken>>,
}

fn default_gcloud_bin() -> String {
    if cfg!(windows) {
        "gcloud.cmd".to_string()
    } else {
        "gcloud".to_string()
    }
}

impl GcloudCredentials {
    pub fn new() -> Self {
        let cache_file =
            dirs::home_dir().map(|h| h.join(".gsutil").join("gcloud_token_cache.json"));
        Self {
            gcloud_bin: default_gcloud_bin(),
            cache_file,
            cached: RwLock::new(None),
        }
    }

    pub fn with_cache_dir(state_dir: PathBuf) -> Self {
        Self {
            gcloud_bin: default_gcloud_bin(),
            cache_file: Some(state_dir.join("gcloud_token_cache.json")),
            cached: RwLock::new(None),
        }
    }

    pub fn with_binary(gcloud_bin: impl Into<String>) -> Self {
        Self {
            gcloud_bin: gcloud_bin.into(),
            cache_file: None,
            cached: RwLock::new(None),
        }
    }

    fn current_cache_key() -> String {
        let cfg = env::var("CLOUDSDK_CONFIG").unwrap_or_default();
        let active = env::var("CLOUDSDK_ACTIVE_CONFIG_NAME").unwrap_or_default();
        let acct = env::var("CLOUDSDK_CORE_ACCOUNT").unwrap_or_default();
        format!("{cfg}|{active}|{acct}")
    }

    fn read_disk_cache(&self) -> Option<AccessToken> {
        let path = self.cache_file.as_ref()?;
        let raw = fs::read_to_string(path).ok()?;
        let entry: GcloudDiskTokenCache = serde_json::from_str(&raw).ok()?;
        if entry.cache_key != Self::current_cache_key() {
            return None;
        }
        let tok = AccessToken::new(entry.access_token, Some(entry.expires_at));
        if tok.is_expired() {
            return None;
        }
        Some(tok)
    }

    fn write_disk_cache(&self, tok: &AccessToken) {
        let Some(ref path) = self.cache_file else {
            return;
        };
        let Some(expires_at) = tok.expires_at else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let entry = GcloudDiskTokenCache {
            cache_key: Self::current_cache_key(),
            access_token: tok.token.clone(),
            expires_at,
        };
        let Ok(json) = serde_json::to_vec(&entry) else {
            return;
        };
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        if let Ok(mut f) = opts.open(path) {
            let _ = f.write_all(&json);
        }
    }

    /// Check if a valid cached token exists or `gcloud` can mint an access token.
    pub async fn try_fetch_initial(&self) -> Option<AccessToken> {
        if let Some(disk_tok) = self.read_disk_cache() {
            let mut guard = self.cached.write().await;
            *guard = Some(disk_tok.clone());
            return Some(disk_tok);
        }
        let fresh = self.fetch_token().await.ok()?;
        self.write_disk_cache(&fresh);
        let mut guard = self.cached.write().await;
        *guard = Some(fresh.clone());
        Some(fresh)
    }

    async fn fetch_token(&self) -> Result<AccessToken> {
        let output = Command::new(&self.gcloud_bin)
            .args(["auth", "print-access-token"])
            .output()
            .await
            .map_err(|e| {
                GsutilError::Service(ServiceError::authentication(
                    format!("Failed to invoke `{}`: {e}", self.gcloud_bin),
                    None,
                    None,
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(GsutilError::Service(ServiceError::authentication(
                format!("`gcloud auth print-access-token` failed: {stderr}"),
                None,
                None,
            )));
        }

        let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if token.is_empty() {
            return Err(GsutilError::Service(ServiceError::authentication(
                "`gcloud auth print-access-token` returned an empty token",
                None,
                None,
            )));
        }

        let expires_at = Utc::now() + Duration::seconds(GCLOUD_TOKEN_CACHE_TTL_SECS);
        Ok(AccessToken::new(token, Some(expires_at)))
    }
}

impl Default for GcloudCredentials {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TokenProvider for GcloudCredentials {
    async fn token(&self) -> Result<Option<AccessToken>> {
        {
            let guard = self.cached.read().await;
            if let Some(ref tok) = *guard {
                if !tok.is_expired() {
                    return Ok(Some(tok.clone()));
                }
            }
        }

        let mut guard = self.cached.write().await;
        if let Some(ref tok) = *guard {
            if !tok.is_expired() {
                return Ok(Some(tok.clone()));
            }
        }

        if let Some(disk_tok) = self.read_disk_cache() {
            *guard = Some(disk_tok.clone());
            return Ok(Some(disk_tok));
        }

        let fresh = self.fetch_token().await?;
        self.write_disk_cache(&fresh);
        *guard = Some(fresh.clone());
        Ok(Some(fresh))
    }

    fn credential_type(&self) -> CredentialType {
        CredentialType::Gcloud
    }
}
