//! Full credential resolution chain matching Python gsutil + gcloud/ADC integration.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result};
use reqwest::Client;
use tracing::warn;

use crate::adc::{is_mtls_enabled, AdcCredentials, GcloudCredentials};
use crate::gce::{GceMetadataCredentials, DEFAULT_METADATA_HOST};
use crate::hmac::{HmacCredentials, HmacProvider};
use crate::impersonation::ImpersonationCredentials;
use crate::noop::NoOpCredentials;
use crate::oauth2::OAuth2UserCredentials;
use crate::service_account::{P12ServiceAccountCredentials, ServiceAccountCredentials};
use crate::{CredentialType, TokenProvider};

/// Options controlling credential resolution (useful for CLI flags and deterministic testing).
#[derive(Debug, Clone)]
pub struct AuthOptions {
    /// Service account email from CLI `-i` / `--impersonate-service-account`.
    pub impersonate_service_account: Option<String>,
    /// Allow falling back to `gcloud auth print-access-token` when no `.boto` / ADC creds exist.
    pub allow_gcloud_fallback: bool,
    /// Allow probing the GCE metadata server even when `[GoogleCompute] service_account` is unset.
    pub allow_gce_metadata: bool,
    /// Allow reading `GOOGLE_APPLICATION_CREDENTIALS` and well-known ADC JSON.
    pub allow_adc: bool,
    /// Override GCE metadata base URL (for testing).
    pub gce_metadata_url: String,
    /// Override IAMCredentials base URL (for testing impersonation).
    pub iamcredentials_base_url: Option<String>,
    /// Override ADC file path (for testing).
    pub adc_path_override: Option<PathBuf>,
}

impl Default for AuthOptions {
    fn default() -> Self {
        Self {
            impersonate_service_account: None,
            allow_gcloud_fallback: true,
            allow_gce_metadata: true,
            allow_adc: true,
            gce_metadata_url: DEFAULT_METADATA_HOST.to_string(),
            iamcredentials_base_url: None,
            adc_path_override: None,
        }
    }
}

/// Resolve credentials using default options (`BotoConfig` -> ADC -> `gcloud` -> GCE -> NoOp).
pub async fn resolve_credentials(
    config: &BotoConfig,
    impersonate_service_account: Option<&str>,
) -> Result<Arc<dyn TokenProvider>> {
    let opts = AuthOptions {
        impersonate_service_account: impersonate_service_account.map(ToString::to_string),
        ..Default::default()
    };
    resolve_credentials_with_options(config, &opts).await
}

/// Resolve credentials with explicit [`AuthOptions`].
pub async fn resolve_credentials_with_options(
    config: &BotoConfig,
    options: &AuthOptions,
) -> Result<Arc<dyn TokenProvider>> {
    let http = build_auth_http_client(config)?;

    // 1. Check for conflicting .boto OAuth2 user + service account credentials
    //    (exact parity with gslib/gcs_json_credentials.py::_CheckAndGetCredentials).
    let has_oauth_user = config
        .get("Credentials", "gs_oauth2_refresh_token")
        .is_some_and(|v| !v.trim().is_empty());
    let has_sa_key = config
        .get("Credentials", "gs_service_key_file")
        .is_some_and(|v| !v.trim().is_empty());

    if has_oauth_user && has_sa_key {
        let configured = vec![
            CredentialType::OAuth2UserAccount.as_str(),
            CredentialType::OAuth2ServiceAccount.as_str(),
        ];
        return Err(GsutilError::command(format!(
            "You have multiple types of configured credentials ({configured:?}), which is \
             not supported. One common way this happens is if you run gsutil \
             config to create credentials and later run gcloud auth, and \
             create a second set of credentials. Your boto config path is: \
             {:?}. For more help, see \"gsutil help creds\".",
            config.friendly_config_file_paths()
        )));
    }

    let mut base_creds: Option<Arc<dyn TokenProvider>> = None;

    // 2. .boto OAuth2 User Account refresh token.
    if has_oauth_user {
        if let Some(user_creds) = OAuth2UserCredentials::from_boto_config(config, http.clone()) {
            base_creds = Some(Arc::new(user_creds));
        }
    }

    // 3. .boto Service Account keyfile (JSON or legacy PKCS12 .p12).
    if base_creds.is_none() && has_sa_key {
        let key_path_str = config
            .get("Credentials", "gs_service_key_file")
            .unwrap_or_default()
            .trim();
        let key_path = Path::new(key_path_str);
        let token_uri_override = config.get("OAuth2", "provider_token_uri");
        let sa = load_service_account_keyfile(key_path, config, token_uri_override, http.clone())?;
        base_creds = Some(sa);
    }

    // 4. .boto HMAC keys (GCS or AWS).
    if base_creds.is_none() {
        if let (Some(access_id), Some(secret)) = (
            config
                .get("Credentials", "gs_access_key_id")
                .filter(|v| !v.trim().is_empty()),
            config
                .get("Credentials", "gs_secret_access_key")
                .filter(|v| !v.trim().is_empty()),
        ) {
            base_creds = Some(Arc::new(HmacCredentials::new(
                access_id.trim(),
                secret.trim(),
                HmacProvider::Gcs,
            )));
        } else if let (Some(access_id), Some(secret)) = (
            config
                .get("Credentials", "aws_access_key_id")
                .filter(|v| !v.trim().is_empty()),
            config
                .get("Credentials", "aws_secret_access_key")
                .filter(|v| !v.trim().is_empty()),
        ) {
            base_creds = Some(Arc::new(HmacCredentials::new(
                access_id.trim(),
                secret.trim(),
                HmacProvider::Aws,
            )));
        }
    }

    // 5. On Context-Aware Access with mTLS/ECP enabled, prefer `gcloud` active user credentials
    //    because `gcloud` natively negotiates ECP/mTLS certificates and RAPT reauth.
    if base_creds.is_none() && options.allow_gcloud_fallback && is_mtls_enabled(config) {
        let gcloud = GcloudCredentials::with_cache_dir(config.state_dir());
        if gcloud.try_fetch_initial().await.is_some() {
            base_creds = Some(Arc::new(gcloud));
        }
    }

    // 6. Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS or well-known ADC JSON).
    if base_creds.is_none() && options.allow_adc {
        let adc_path = options
            .adc_path_override
            .clone()
            .or_else(AdcCredentials::default_adc_path);
        if let Some(path) = adc_path {
            if path.is_file() {
                let token_uri_override = config.get("OAuth2", "provider_token_uri");
                let creds = AdcCredentials::from_file(&path, token_uri_override, http.clone())?;
                base_creds = Some(creds);
            }
        }
    }

    // 7. `gcloud` active user credentials fallback (`gcloud auth print-access-token`).
    if base_creds.is_none() && options.allow_gcloud_fallback {
        let gcloud = GcloudCredentials::with_cache_dir(config.state_dir());
        if gcloud.try_fetch_initial().await.is_some() {
            base_creds = Some(Arc::new(gcloud));
        }
    }

    // 8. GCE metadata server (`[GoogleCompute] service_account` or live metadata probe).
    if base_creds.is_none() {
        if let Some(sa_name) = config
            .get("GoogleCompute", "service_account")
            .filter(|s| !s.trim().is_empty())
        {
            base_creds = Some(Arc::new(GceMetadataCredentials::with_base_url(
                &options.gce_metadata_url,
                sa_name.trim(),
                http.clone(),
            )));
        } else if options.allow_gce_metadata
            && GceMetadataCredentials::is_available(&options.gce_metadata_url).await
        {
            base_creds = Some(Arc::new(GceMetadataCredentials::with_base_url(
                &options.gce_metadata_url,
                "default",
                http.clone(),
            )));
        }
    }

    // 9. Fallback to NoOpCredentials for public/anonymous buckets.
    let resolved = base_creds.unwrap_or_else(|| Arc::new(NoOpCredentials));

    // 10. Wrap with Service Account Impersonation if configured (CLI `-i` > `.boto` > env var).
    let impersonate_target = resolve_impersonate_target(config, options);
    if let Some(target_sa) = impersonate_target {
        if !resolved.is_anonymous() {
            warn!(
                "WARNING: This command is using service account impersonation. \
                 All API calls will be executed as [{}].",
                target_sa
            );
            let imp = match &options.iamcredentials_base_url {
                Some(base_url) => ImpersonationCredentials::with_base_url(
                    target_sa,
                    vec![crate::CLOUD_PLATFORM_SCOPE.to_string()],
                    resolved,
                    base_url,
                    http,
                ),
                None => ImpersonationCredentials::new(target_sa, resolved, config, http),
            };
            return Ok(Arc::new(imp));
        }
    }

    Ok(resolved)
}

fn resolve_impersonate_target(config: &BotoConfig, options: &AuthOptions) -> Option<String> {
    if let Some(ref sa) = options.impersonate_service_account {
        if !sa.trim().is_empty() {
            return Some(sa.trim().to_string());
        }
    }
    if let Some(sa) = config.get("Credentials", "gs_impersonate_service_account") {
        if !sa.trim().is_empty() {
            return Some(sa.trim().to_string());
        }
    }
    if let Ok(sa) = env::var("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT") {
        if !sa.trim().is_empty() {
            return Some(sa.trim().to_string());
        }
    }
    None
}

fn load_service_account_keyfile(
    path: &Path,
    config: &BotoConfig,
    token_uri_override: Option<&str>,
    http: Client,
) -> Result<Arc<dyn TokenProvider>> {
    let raw_bytes = fs::read(path).map_err(|e| {
        GsutilError::command(format!(
            "Could not read service account keyfile \"{}\": {e}",
            path.display()
        ))
    })?;

    // Match gslib/gcs_json_credentials.py: UTF-8 files are parsed as JSON; non-UTF-8 binary
    // files are treated as PKCS12 (.p12).
    match String::from_utf8(raw_bytes) {
        Ok(utf8_str) => {
            let sa = ServiceAccountCredentials::from_json_str(
                &utf8_str,
                &path.display().to_string(),
                token_uri_override,
                http,
            )?;
            Ok(Arc::new(sa))
        }
        Err(_) => {
            let email = config.get_or("Credentials", "gs_service_client_id", "");
            let password = config.get("Credentials", "gs_service_key_file_password");
            let p12 = P12ServiceAccountCredentials::from_p12_file(
                path,
                email,
                password,
                token_uri_override,
                http,
            )?;
            Ok(Arc::new(p12))
        }
    }
}

fn build_auth_http_client(config: &BotoConfig) -> Result<Client> {
    let mut builder =
        Client::builder().danger_accept_invalid_certs(!config.https_validate_certificates());
    if let Some(ca_path) = config.ca_certificates_file() {
        let pem = fs::read(ca_path).map_err(|e| {
            GsutilError::command(format!(
                "Failed to read ca_certificates_file \"{ca_path}\": {e}"
            ))
        })?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
            GsutilError::command(format!(
                "Failed to parse PEM certificates from \"{ca_path}\": {e}"
            ))
        })?;
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    if let Some(proxy) = config.resolve_proxy() {
        let proxy_url = format_proxy_url(&proxy);
        let reqwest_proxy = reqwest::Proxy::all(&proxy_url)
            .map_err(|e| GsutilError::command(format!("Invalid proxy configuration: {e}")))?;
        builder = builder.proxy(reqwest_proxy);
    }
    builder
        .build()
        .map_err(|e| GsutilError::command(format!("Failed to initialize auth HTTP client: {e}")))
}

/// Format a `ProxyConfig` as a `reqwest`-compatible proxy URL, using `socks5h://` / `socks4a://`
/// when `proxy_rdns` is enabled.
pub fn format_proxy_url(proxy: &gsutil_core::config::ProxyConfig) -> String {
    use gsutil_core::config::ProxyType;
    let scheme = match (proxy.proxy_type, proxy.rdns) {
        (ProxyType::Http, _) => "http",
        (ProxyType::Socks4, true) => "socks4a",
        (ProxyType::Socks4, false) => "socks4",
        (ProxyType::Socks5, true) => "socks5h",
        (ProxyType::Socks5, false) => "socks5",
    };
    match (&proxy.user, &proxy.pass) {
        (Some(u), Some(p)) => format!("{scheme}://{u}:{p}@{}:{}", proxy.host, proxy.port),
        (Some(u), None) => format!("{scheme}://{u}@{}:{}", proxy.host, proxy.port),
        _ => format!("{scheme}://{}:{}", proxy.host, proxy.port),
    }
}
