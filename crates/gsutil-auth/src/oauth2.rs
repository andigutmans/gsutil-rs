//! OAuth 2.0 User Account credentials using refresh tokens (`.boto` `gs_oauth2_refresh_token`
//! or ADC `authorized_user`).

use std::env;
use std::fmt;

use async_trait::async_trait;
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result, ServiceError};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::{AccessToken, CredentialType, TokenProvider, DEFAULT_TOKEN_URI};

/// Default gsutil OAuth2 installed-application client ID and secret
/// (publicly known, matching `gslib/utils/system_util.py`).
pub const GSUTIL_CLIENT_ID: &str = "909320924072.apps.googleusercontent.com";
pub const GSUTIL_CLIENT_SECRET: &str = "p3RlpR10xMFh9ZXBS/ZNLYUu";

/// Cloud SDK OAuth2 installed-application client ID and secret
/// (matching `gslib/utils/system_util.py`).
pub const CLOUDSDK_CLIENT_ID: &str = "32555940559.apps.googleusercontent.com";
pub const CLOUDSDK_CLIENT_SECRET: &str = "ZmssLNjJy2998hD4CTg2ejr2";

/// Returns `(client_id, client_secret)` matching `GetGsutilClientIdAndSecret()`.
pub fn default_client_id_and_secret() -> (&'static str, &'static str) {
    let via_cloudsdk = env::var("CLOUDSDK_WRAPPER").ok().as_deref() == Some("1");
    let pass_creds = env::var("CLOUDSDK_CORE_PASS_CREDENTIALS_TO_GSUTIL")
        .ok()
        .as_deref()
        == Some("1");
    if via_cloudsdk && pass_creds {
        (CLOUDSDK_CLIENT_ID, CLOUDSDK_CLIENT_SECRET)
    } else {
        (GSUTIL_CLIENT_ID, GSUTIL_CLIENT_SECRET)
    }
}

#[derive(Debug, Deserialize)]
struct TokenRefreshResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
}

/// OAuth2 user account credential provider backed by a refresh token.
pub struct OAuth2UserCredentials {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    token_uri: String,
    quota_project_id: Option<String>,
    cred_type: CredentialType,
    http: Client,
    cached: RwLock<Option<AccessToken>>,
}

impl fmt::Debug for OAuth2UserCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2UserCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("token_uri", &self.token_uri)
            .field("quota_project_id", &self.quota_project_id)
            .field("cred_type", &self.cred_type)
            .finish()
    }
}

impl OAuth2UserCredentials {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        refresh_token: impl Into<String>,
        token_uri: impl Into<String>,
        quota_project_id: Option<String>,
        cred_type: CredentialType,
        http: Client,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            refresh_token: refresh_token.into(),
            token_uri: token_uri.into(),
            quota_project_id,
            cred_type,
            http,
            cached: RwLock::new(None),
        }
    }

    /// Construct from `.boto` `[Credentials] gs_oauth2_refresh_token`.
    pub fn from_boto_config(config: &BotoConfig, http: Client) -> Option<Self> {
        let refresh_token = config
            .get("Credentials", "gs_oauth2_refresh_token")
            .filter(|s| !s.trim().is_empty())?;
        let token_uri = config.get_or("OAuth2", "provider_token_uri", DEFAULT_TOKEN_URI);
        let (default_id, default_secret) = default_client_id_and_secret();

        let env_client_id = env::var("OAUTH2_CLIENT_ID").ok();
        let client_id = config
            .get("OAuth2", "client_id")
            .or(env_client_id.as_deref())
            .unwrap_or(default_id);

        let env_client_secret = env::var("OAUTH2_CLIENT_SECRET").ok();
        let client_secret = config
            .get("OAuth2", "client_secret")
            .or(env_client_secret.as_deref())
            .unwrap_or(default_secret);

        Some(Self::new(
            client_id,
            client_secret,
            refresh_token.trim(),
            token_uri,
            None,
            CredentialType::OAuth2UserAccount,
            http,
        ))
    }

    async fn refresh(&self) -> Result<AccessToken> {
        let params = [
            ("grant_type", "refresh_token"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("refresh_token", self.refresh_token.as_str()),
        ];

        let resp = self
            .http
            .post(&self.token_uri)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                GsutilError::Service(ServiceError::authentication(
                    format!("Failed to refresh OAuth2 token: {e}"),
                    None,
                    None,
                ))
            })?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(GsutilError::Service(ServiceError::authentication(
                format!("OAuth2 token refresh failed (HTTP {})", status.as_u16()),
                Some(status.as_u16()),
                Some(body),
            )));
        }

        let parsed: TokenRefreshResponse = serde_json::from_str(&body).map_err(|e| {
            GsutilError::Service(ServiceError::authentication(
                format!("Invalid OAuth2 token response: {e}"),
                Some(status.as_u16()),
                None,
            ))
        })?;

        let expires_in = parsed.expires_in.unwrap_or(3600);
        Ok(AccessToken::from_expires_in(
            parsed.access_token,
            expires_in,
        ))
    }
}

#[async_trait]
impl TokenProvider for OAuth2UserCredentials {
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

        let fresh = self.refresh().await?;
        *guard = Some(fresh.clone());
        Ok(Some(fresh))
    }

    fn credential_type(&self) -> CredentialType {
        self.cred_type
    }

    fn quota_project_id(&self) -> Option<&str> {
        self.quota_project_id.as_deref()
    }
}
