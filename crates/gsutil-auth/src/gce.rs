//! GCE metadata server credentials (`http://metadata.google.internal`).
//!
//! Matches `_GetGceCreds` in `gslib/gcs_json_credentials.py`.

use std::time::Duration;

use async_trait::async_trait;
use gsutil_core::error::{GsutilError, Result, ServiceError};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::{AccessToken, CredentialType, TokenProvider};

pub const DEFAULT_METADATA_HOST: &str = "http://metadata.google.internal";

#[derive(Debug, Deserialize)]
struct GceTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
}

/// Credentials obtained from the Google Compute Engine metadata server.
#[derive(Debug)]
pub struct GceMetadataCredentials {
    metadata_base_url: String,
    service_account: String,
    http: Client,
    cached: RwLock<Option<AccessToken>>,
}

impl GceMetadataCredentials {
    pub fn new(service_account: impl Into<String>, http: Client) -> Self {
        Self::with_base_url(DEFAULT_METADATA_HOST, service_account, http)
    }

    pub fn with_base_url(
        metadata_base_url: impl Into<String>,
        service_account: impl Into<String>,
        http: Client,
    ) -> Self {
        Self {
            metadata_base_url: metadata_base_url.into().trim_end_matches('/').to_string(),
            service_account: service_account.into(),
            http,
            cached: RwLock::new(None),
        }
    }

    /// Probe whether the GCE metadata server is reachable and responds with
    /// `Metadata-Flavor: Google` within a short timeout.
    pub async fn is_available(metadata_base_url: &str) -> bool {
        let client = match Client::builder()
            .connect_timeout(Duration::from_millis(500))
            .timeout(Duration::from_secs(1))
            .build()
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        let url = format!("{}/", metadata_base_url.trim_end_matches('/'));
        match client
            .get(&url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
        {
            Ok(resp) => resp
                .headers()
                .get("metadata-flavor")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("Google"))
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    async fn fetch_token(&self) -> Result<AccessToken> {
        let url = format!(
            "{}/computeMetadata/v1/instance/service-accounts/{}/token",
            self.metadata_base_url, self.service_account
        );

        let resp = self
            .http
            .get(&url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|e| {
                GsutilError::Service(ServiceError::authentication(
                    format!("Failed to contact GCE metadata server: {e}"),
                    None,
                    None,
                ))
            })?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(GsutilError::Service(ServiceError::authentication(
                format!(
                    "GCE metadata server returned HTTP {} for service account '{}'",
                    status.as_u16(),
                    self.service_account
                ),
                Some(status.as_u16()),
                Some(body),
            )));
        }

        let parsed: GceTokenResponse = serde_json::from_str(&body).map_err(|e| {
            GsutilError::Service(ServiceError::authentication(
                format!("Invalid GCE metadata token response: {e}"),
                Some(status.as_u16()),
                None,
            ))
        })?;

        Ok(AccessToken::from_expires_in(
            parsed.access_token,
            parsed.expires_in.unwrap_or(3600),
        ))
    }
}

#[async_trait]
impl TokenProvider for GceMetadataCredentials {
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

        let fresh = self.fetch_token().await?;
        *guard = Some(fresh.clone());
        Ok(Some(fresh))
    }

    fn credential_type(&self) -> CredentialType {
        CredentialType::Gce
    }
}
