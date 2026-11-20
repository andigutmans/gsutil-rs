//! Cloud IAM Credentials v1 API client matching `gslib/iamcredentials_api.py`.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use gsutil_auth::impersonation::{resolve_iamcredentials_base_url, translate_iamcredentials_error};
use gsutil_auth::TokenProvider;
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result, ServiceError};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::retry::RetryPolicy;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedAccessToken {
    pub access_token: String,
    pub expire_time: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedBlob {
    pub key_id: String,
    pub signed_blob: String,
}

#[derive(Serialize)]
struct GenerateAccessTokenRequest<'a> {
    scope: &'a [String],
}

#[derive(Serialize)]
struct SignBlobRequest {
    payload: String,
}

/// Client for Google Cloud IAM Credentials v1 API (`gslib/iamcredentials_api.py`).
#[derive(Clone)]
pub struct IamCredentialsClient {
    base_url: String,
    http: Client,
    credentials: Arc<dyn TokenProvider>,
    retry_policy: RetryPolicy,
}

impl IamCredentialsClient {
    pub fn new(config: &BotoConfig, credentials: Arc<dyn TokenProvider>) -> Result<Self> {
        let base_url = resolve_iamcredentials_base_url(config);
        let http = Client::builder()
            .danger_accept_invalid_certs(!config.https_validate_certificates())
            .build()
            .map_err(|e| {
                GsutilError::command(format!("Failed to build IAMCredentials HTTP client: {e}"))
            })?;
        Ok(Self {
            base_url,
            http,
            credentials,
            retry_policy: RetryPolicy::from_config(config),
        })
    }

    pub fn with_base_url(
        base_url: impl Into<String>,
        credentials: Arc<dyn TokenProvider>,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: Client::new(),
            credentials,
            retry_policy,
        }
    }

    async fn apply_auth(
        &self,
        mut req: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder> {
        if let Some(tok) = self.credentials.token().await? {
            req = req.bearer_auth(&tok.token);
        }
        Ok(req)
    }

    /// `POST /v1/projects/-/serviceAccounts/{service_account_id}:generateAccessToken`
    pub async fn generate_access_token(
        &self,
        service_account_id: &str,
        scopes: &[String],
    ) -> Result<GeneratedAccessToken> {
        let url = format!(
            "{}/v1/projects/-/serviceAccounts/{service_account_id}:generateAccessToken",
            self.base_url
        );
        let body = GenerateAccessTokenRequest { scope: scopes };

        let text = self
            .retry_policy
            .execute(
                || async {
                    let req = self.apply_auth(self.http.post(&url).json(&body)).await?;
                    let resp = req.send().await.map_err(|e| {
                        if RetryPolicy::is_retryable_reqwest_error(&e) {
                            GsutilError::Service(ServiceError::retryable(
                                format!("IAMCredentials request error: {e}"),
                                None,
                                None,
                            ))
                        } else {
                            GsutilError::Service(ServiceError::service(
                                format!("IAMCredentials request error: {e}"),
                                None,
                                None,
                            ))
                        }
                    })?;
                    let status = resp.status().as_u16();
                    let body_text = resp.text().await.unwrap_or_default();
                    if (200..300).contains(&status) {
                        Ok(body_text)
                    } else if RetryPolicy::is_retryable_status(status) {
                        Err(GsutilError::Service(ServiceError::retryable(
                            format!("HTTP {status}"),
                            Some(status),
                            Some(body_text),
                        )))
                    } else {
                        Err(translate_iamcredentials_error(
                            status,
                            &body_text,
                            service_account_id,
                        ))
                    }
                },
                |e| matches!(e, GsutilError::Service(se) if se.is_retryable()),
            )
            .await?;

        serde_json::from_str(&text).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Failed to parse IAMCredentials generateAccessToken response: {e}"),
                None,
                None,
            ))
        })
    }

    /// `POST /v1/projects/-/serviceAccounts/{service_account_id}:signBlob`
    pub async fn sign_blob(&self, service_account_id: &str, payload: &[u8]) -> Result<SignedBlob> {
        let url = format!(
            "{}/v1/projects/-/serviceAccounts/{service_account_id}:signBlob",
            self.base_url
        );
        let body = SignBlobRequest {
            payload: STANDARD.encode(payload),
        };

        let text = self
            .retry_policy
            .execute(
                || async {
                    let req = self.apply_auth(self.http.post(&url).json(&body)).await?;
                    let resp = req.send().await.map_err(|e| {
                        if RetryPolicy::is_retryable_reqwest_error(&e) {
                            GsutilError::Service(ServiceError::retryable(
                                format!("IAMCredentials request error: {e}"),
                                None,
                                None,
                            ))
                        } else {
                            GsutilError::Service(ServiceError::service(
                                format!("IAMCredentials request error: {e}"),
                                None,
                                None,
                            ))
                        }
                    })?;
                    let status = resp.status().as_u16();
                    let body_text = resp.text().await.unwrap_or_default();
                    if (200..300).contains(&status) {
                        Ok(body_text)
                    } else if RetryPolicy::is_retryable_status(status) {
                        Err(GsutilError::Service(ServiceError::retryable(
                            format!("HTTP {status}"),
                            Some(status),
                            Some(body_text),
                        )))
                    } else {
                        Err(translate_iamcredentials_error(
                            status,
                            &body_text,
                            service_account_id,
                        ))
                    }
                },
                |e| matches!(e, GsutilError::Service(se) if se.is_retryable()),
            )
            .await?;

        serde_json::from_str(&text).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Failed to parse IAMCredentials signBlob response: {e}"),
                None,
                None,
            ))
        })
    }
}
