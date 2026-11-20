//! Service Account Impersonation credentials via the IAMCredentials v1 API.
//!
//! Matches `gslib/impersonation_credentials.py` and `gslib/iamcredentials_api.py`.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result, ServiceError};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{AccessToken, CredentialType, TokenProvider, CLOUD_PLATFORM_SCOPE};

pub const DEFAULT_IAMCREDENTIALS_HOST: &str = "iamcredentials.googleapis.com";

#[derive(Serialize)]
struct GenerateAccessTokenRequest<'a> {
    scope: &'a [String],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateAccessTokenResponse {
    access_token: String,
    expire_time: String,
}

#[derive(Serialize)]
struct SignBlobRequest {
    payload: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignBlobResponse {
    key_id: String,
    signed_blob: String,
}

/// Credentials that impersonate a target service account using an originating `TokenProvider`.
pub struct ImpersonationCredentials {
    target_service_account: String,
    scopes: Vec<String>,
    source: Arc<dyn TokenProvider>,
    base_url: String,
    http: Client,
    cached: RwLock<Option<AccessToken>>,
}

impl fmt::Debug for ImpersonationCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImpersonationCredentials")
            .field("target_service_account", &self.target_service_account)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl ImpersonationCredentials {
    pub fn new(
        target_service_account: impl Into<String>,
        source: Arc<dyn TokenProvider>,
        config: &BotoConfig,
        http: Client,
    ) -> Self {
        let base_url = resolve_iamcredentials_base_url(config);
        Self::with_base_url(
            target_service_account,
            vec![CLOUD_PLATFORM_SCOPE.to_string()],
            source,
            base_url,
            http,
        )
    }

    pub fn with_base_url(
        target_service_account: impl Into<String>,
        scopes: Vec<String>,
        source: Arc<dyn TokenProvider>,
        base_url: impl Into<String>,
        http: Client,
    ) -> Self {
        Self {
            target_service_account: target_service_account.into(),
            scopes,
            source,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
            cached: RwLock::new(None),
        }
    }

    async fn generate_access_token(&self) -> Result<AccessToken> {
        let source_token = self.source.token().await?.ok_or_else(|| {
            GsutilError::Service(ServiceError::access_denied(
                "Cannot impersonate a service account with anonymous credentials.",
                Some(401),
                None,
            ))
        })?;

        let url = format!(
            "{}/v1/projects/-/serviceAccounts/{}:generateAccessToken",
            self.base_url, self.target_service_account
        );

        let body = GenerateAccessTokenRequest {
            scope: &self.scopes,
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&source_token.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                GsutilError::Service(ServiceError::service(
                    format!("IAMCredentials generateAccessToken request failed: {e}"),
                    None,
                    None,
                ))
            })?;

        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(translate_iamcredentials_error(
                status,
                &text,
                &self.target_service_account,
            ));
        }

        let parsed: GenerateAccessTokenResponse = serde_json::from_str(&text).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Invalid IAMCredentials response: {e}"),
                Some(status),
                None,
            ))
        })?;

        let expires_at = DateTime::parse_from_rfc3339(&parsed.expire_time)
            .ok()
            .map(|dt| dt.with_timezone(&Utc));

        Ok(AccessToken::new(parsed.access_token, expires_at))
    }
}

#[async_trait]
impl TokenProvider for ImpersonationCredentials {
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

        let fresh = self.generate_access_token().await?;
        *guard = Some(fresh.clone());
        Ok(Some(fresh))
    }

    fn credential_type(&self) -> CredentialType {
        CredentialType::Impersonation
    }

    fn service_account_email(&self) -> Option<&str> {
        Some(&self.target_service_account)
    }

    async fn sign_blob(&self, payload: &[u8]) -> Result<(String, Vec<u8>)> {
        let source_token = self.source.token().await?.ok_or_else(|| {
            GsutilError::Service(ServiceError::access_denied(
                "Cannot sign blob via impersonation with anonymous credentials.",
                Some(401),
                None,
            ))
        })?;

        let url = format!(
            "{}/v1/projects/-/serviceAccounts/{}:signBlob",
            self.base_url, self.target_service_account
        );

        let req_body = SignBlobRequest {
            payload: STANDARD.encode(payload),
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&source_token.token)
            .json(&req_body)
            .send()
            .await
            .map_err(|e| {
                GsutilError::Service(ServiceError::service(
                    format!("IAMCredentials signBlob request failed: {e}"),
                    None,
                    None,
                ))
            })?;

        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(translate_iamcredentials_error(
                status,
                &text,
                &self.target_service_account,
            ));
        }

        let parsed: SignBlobResponse = serde_json::from_str(&text).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Invalid IAMCredentials signBlob response: {e}"),
                Some(status),
                None,
            ))
        })?;

        let sig = STANDARD.decode(&parsed.signed_blob).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Invalid base64 signedBlob from IAMCredentials: {e}"),
                Some(status),
                None,
            ))
        })?;

        Ok((parsed.key_id, sig))
    }
}

/// Resolve the IAMCredentials base URL from `.boto` config (honoring legacy typo `gs_iamcredentails_host`).
pub fn resolve_iamcredentials_base_url(config: &BotoConfig) -> String {
    let host = config
        .get("Credentials", "gs_iamcredentials_host")
        .or_else(|| config.get("Credentials", "gs_iamcredentails_host"))
        .unwrap_or(DEFAULT_IAMCREDENTIALS_HOST);
    let port = config
        .get("Credentials", "gs_iamcredentials_port")
        .or_else(|| config.get("Credentials", "gs_iamcredentails_port"));
    let scheme = if host.starts_with("http://") || host.starts_with("https://") {
        ""
    } else {
        "https://"
    };
    match port.filter(|p| !p.is_empty()) {
        Some(p) => format!("{scheme}{host}:{p}"),
        None => format!("{scheme}{host}"),
    }
}

/// Translate IAMCredentials HTTP errors matching `gslib/iamcredentials_api.py`.
pub fn translate_iamcredentials_error(
    status: u16,
    body: &str,
    service_account_id: &str,
) -> GsutilError {
    let message = extract_json_error_message(body);
    let err = match status {
        400 => ServiceError::bad_request(
            message.unwrap_or_else(|| "Bad Request".to_string()),
            Some(status),
            None,
        ),
        401 => {
            if body.contains("Login Required") {
                ServiceError::access_denied(
                    message.unwrap_or_else(|| "Access denied: login required.".to_string()),
                    Some(status),
                    None,
                )
            } else {
                ServiceError::service(
                    message.unwrap_or_else(|| "Unauthorized".to_string()),
                    Some(status),
                    None,
                )
            }
        }
        403 => {
            if body.contains("The caller does not have permission") {
                ServiceError::access_denied(
                    "Service account impersonation failed. Please go to the Google \
                     Cloud Platform Console (https://cloud.google.com/console), \
                     select IAM & admin, then Service Accounts, and grant your \
                     originating account the Service Account Token Creator role on \
                     the target service account.",
                    None,
                    None,
                )
            } else if body.contains("IAM Service Account Credentials API has not been used") {
                ServiceError::access_denied(message.unwrap_or_else(|| body.to_string()), None, None)
            } else if body.contains("The account for the specified project has been disabled") {
                ServiceError::access_denied(
                    message.unwrap_or_else(|| "Account disabled.".to_string()),
                    Some(status),
                    None,
                )
            } else if body.contains("Daily Limit for Unauthenticated Use Exceeded") {
                ServiceError::access_denied(
                    message.unwrap_or_else(|| {
                        "Access denied: quota exceeded. Is your project ID valid?".to_string()
                    }),
                    Some(status),
                    None,
                )
            } else if body.contains("User Rate Limit Exceeded") {
                ServiceError::access_denied(
                    "Rate limit exceeded. Please retry this request later.",
                    Some(status),
                    None,
                )
            } else if body.contains("Access Not Configured") {
                ServiceError::access_denied(
                    "Access Not Configured. Please go to the Google Cloud Platform \
                     Console (https://cloud.google.com/console#/project) for your \
                     project, select APIs & services, and enable the Google Cloud \
                     IAM Credentials API.",
                    Some(status),
                    None,
                )
            } else {
                ServiceError::access_denied(
                    message.unwrap_or_else(|| service_account_id.to_string()),
                    Some(status),
                    None,
                )
            }
        }
        404 => ServiceError::not_found(
            message.unwrap_or_else(|| format!("Service account {service_account_id} not found.")),
            Some(status),
            None,
        ),
        412 => ServiceError::precondition(
            message.unwrap_or_else(|| "Precondition Failed".to_string()),
            Some(status),
            None,
        ),
        _ => ServiceError::service(
            message.unwrap_or_else(|| format!("HTTP {status}")),
            Some(status),
            None,
        ),
    };
    GsutilError::Service(err)
}

fn extract_json_error_message(body: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(body).ok()?;
    val.get("error")?
        .get("message")?
        .as_str()
        .map(ToString::to_string)
}
