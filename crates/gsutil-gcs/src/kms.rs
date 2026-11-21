//! Cloud KMS v1 API client matching `gslib/kms_api.py`.

use std::sync::Arc;

use async_trait::async_trait;
use gsutil_auth::TokenProvider;
use gsutil_core::api::{IamBinding, IamPolicy, KmsApi};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result, ServiceError};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::ecp::{EcpProxy, ECP_TARGET_HOST_HEADER};
use crate::error_translation::{extract_acceptable_scopes, extract_json_error_message};
use crate::retry::RetryPolicy;

pub const DEFAULT_KMS_HOST: &str = "cloudkms.googleapis.com";

#[derive(Serialize)]
struct SetIamPolicyBody<'a> {
    policy: &'a IamPolicy,
}

#[derive(Serialize)]
struct CreateCryptoKeyBody {
    purpose: &'static str,
}

#[derive(Deserialize)]
struct KeyRingResponse {
    #[allow(dead_code)]
    name: Option<String>,
}

/// Client for Google Cloud KMS v1 API (`gslib/kms_api.py`).
#[derive(Clone)]
pub struct KmsClient {
    base_url: String,
    ecp_target_host: Option<String>,
    _ecp_proxy: Option<Arc<EcpProxy>>,
    http: Client,
    credentials: Arc<dyn TokenProvider>,
    retry_policy: RetryPolicy,
}

impl KmsClient {
    pub fn new(config: &BotoConfig, credentials: Arc<dyn TokenProvider>) -> Result<Self> {
        let host = config.get_or("Credentials", "gs_kms_host", DEFAULT_KMS_HOST);
        let port = config.get("Credentials", "gs_kms_port");
        let mut base_url = match port.filter(|p| !p.is_empty()) {
            Some(p) => format!("https://{host}:{p}"),
            None => format!("https://{host}"),
        };
        let mut ecp_target_host = None;
        let mut ecp_proxy = None;
        if host == DEFAULT_KMS_HOST && port.is_none() {
            if let Some(proxy) = EcpProxy::detect_or_spawn(config)? {
                let (rewritten, target) = proxy.rewrite_google_api_url(&base_url);
                base_url = rewritten;
                ecp_target_host = target;
                ecp_proxy = Some(proxy);
            }
        }
        let http = Client::builder()
            .danger_accept_invalid_certs(!config.https_validate_certificates())
            .build()
            .map_err(|e| GsutilError::command(format!("Failed to build KMS HTTP client: {e}")))?;
        Ok(Self {
            base_url,
            ecp_target_host,
            _ecp_proxy: ecp_proxy,
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
            ecp_target_host: None,
            _ecp_proxy: None,
            http: Client::new(),
            credentials,
            retry_policy,
        }
    }

    async fn apply_auth(
        &self,
        mut req: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder> {
        if let Some(ref target) = self.ecp_target_host {
            req = req.header(ECP_TARGET_HOST_HEADER, target);
        }
        if let Some(tok) = self.credentials.token().await? {
            req = req.bearer_auth(&tok.token);
        }
        Ok(req)
    }

    /// `GET /v1/{key_name}:getIamPolicy`
    pub async fn get_key_iam_policy(&self, key_name: &str) -> Result<IamPolicy> {
        let url = format!("{}/v1/{key_name}:getIamPolicy", self.base_url);
        let resp_text = self
            .retry_policy
            .execute(
                || async {
                    let req = self.apply_auth(self.http.get(&url)).await?;
                    send_and_check_kms(req, Some(key_name)).await
                },
                is_retryable_err,
            )
            .await?;

        serde_json::from_str(&resp_text).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Failed to parse KMS IAM policy: {e}"),
                None,
                None,
            ))
        })
    }

    /// `POST /v1/{key_name}:setIamPolicy`
    pub async fn set_key_iam_policy(
        &self,
        key_name: &str,
        policy: &IamPolicy,
    ) -> Result<IamPolicy> {
        let url = format!("{}/v1/{key_name}:setIamPolicy", self.base_url);
        let body = SetIamPolicyBody { policy };
        let resp_text = self
            .retry_policy
            .execute(
                || async {
                    let req = self.apply_auth(self.http.post(&url).json(&body)).await?;
                    send_and_check_kms(req, Some(key_name)).await
                },
                is_retryable_err,
            )
            .await?;

        serde_json::from_str(&resp_text).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Failed to parse KMS SetIamPolicy response: {e}"),
                None,
                None,
            ))
        })
    }

    /// `POST /v1/projects/{project}/locations/{location}/keyRings?keyRingId={keyring_name}`
    ///
    /// Treats HTTP 409 (already exists) as success, matching `KmsApi.CreateKeyRing`.
    pub async fn create_key_ring(
        &self,
        project: &str,
        keyring_name: &str,
        location: &str,
    ) -> Result<String> {
        let fqn = format!("projects/{project}/locations/{location}/keyRings/{keyring_name}");
        let url = format!(
            "{}/v1/projects/{project}/locations/{location}/keyRings",
            self.base_url
        );
        let payload = serde_json::json!({ "name": fqn });

        let res = self
            .retry_policy
            .execute(
                || async {
                    let req = self
                        .apply_auth(
                            self.http
                                .post(&url)
                                .query(&[("keyRingId", keyring_name)])
                                .json(&payload),
                        )
                        .await?;
                    let resp = req.send().await.map_err(reqwest_to_service_err)?;
                    let status = resp.status().as_u16();
                    let www_auth = resp
                        .headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .map(ToString::to_string);
                    let text = resp.text().await.unwrap_or_default();
                    if status == 409 || (200..300).contains(&status) {
                        let _: Option<KeyRingResponse> = serde_json::from_str(&text).ok();
                        Ok(())
                    } else {
                        Err(translate_kms_error(
                            status,
                            &text,
                            www_auth.as_deref(),
                            Some(&fqn),
                        ))
                    }
                },
                is_retryable_err,
            )
            .await;

        res?;
        Ok(fqn)
    }

    /// `POST /v1/{keyring_fqn}/cryptoKeys?cryptoKeyId={key_name}`
    ///
    /// Treats HTTP 409 (already exists) as success, matching `KmsApi.CreateCryptoKey`.
    pub async fn create_crypto_key(&self, keyring_fqn: &str, key_name: &str) -> Result<String> {
        let trimmed = keyring_fqn.trim_end_matches('/');
        let fqn = format!("{trimmed}/cryptoKeys/{key_name}");
        let url = format!("{}/v1/{trimmed}/cryptoKeys", self.base_url);
        let payload = CreateCryptoKeyBody {
            purpose: "ENCRYPT_DECRYPT",
        };

        self.retry_policy
            .execute(
                || async {
                    let req = self
                        .apply_auth(
                            self.http
                                .post(&url)
                                .query(&[("cryptoKeyId", key_name)])
                                .json(&payload),
                        )
                        .await?;
                    let resp = req.send().await.map_err(reqwest_to_service_err)?;
                    let status = resp.status().as_u16();
                    let www_auth = resp
                        .headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .map(ToString::to_string);
                    let text = resp.text().await.unwrap_or_default();
                    if status == 409 || (200..300).contains(&status) {
                        Ok(())
                    } else {
                        Err(translate_kms_error(
                            status,
                            &text,
                            www_auth.as_deref(),
                            Some(&fqn),
                        ))
                    }
                },
                is_retryable_err,
            )
            .await?;

        Ok(fqn)
    }
}

#[async_trait]
impl KmsApi for KmsClient {
    async fn authorize_service_account(
        &self,
        kms_key_name: &str,
        service_account_email: &str,
    ) -> Result<bool> {
        const KMS_ROLE: &str = "roles/cloudkms.cryptoKeyEncrypterDecrypter";
        let member = format!("serviceAccount:{service_account_email}");
        let mut policy = self.get_key_iam_policy(kms_key_name).await?;

        if let Some(binding) = policy
            .bindings
            .iter_mut()
            .find(|b| b.role == KMS_ROLE && b.condition.is_none())
        {
            if binding.members.iter().any(|m| m == &member) {
                return Ok(false);
            }
            binding.members.push(member);
        } else {
            policy.bindings.push(IamBinding {
                role: KMS_ROLE.to_string(),
                members: vec![member],
                condition: None,
            });
        }

        self.set_key_iam_policy(kms_key_name, &policy).await?;
        Ok(true)
    }
}

async fn send_and_check_kms(
    req: reqwest::RequestBuilder,
    key_name: Option<&str>,
) -> Result<String> {
    let resp = req.send().await.map_err(reqwest_to_service_err)?;
    let status = resp.status().as_u16();
    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let text = resp.text().await.unwrap_or_default();
    if (200..300).contains(&status) {
        Ok(text)
    } else {
        Err(translate_kms_error(
            status,
            &text,
            www_auth.as_deref(),
            key_name,
        ))
    }
}

fn reqwest_to_service_err(e: reqwest::Error) -> GsutilError {
    if RetryPolicy::is_retryable_reqwest_error(&e) {
        GsutilError::Service(ServiceError::retryable(
            format!("KMS request error: {e}"),
            None,
            None,
        ))
    } else {
        GsutilError::Service(ServiceError::service(
            format!("KMS request error: {e}"),
            None,
            None,
        ))
    }
}

fn is_retryable_err(e: &GsutilError) -> bool {
    matches!(e, GsutilError::Service(se) if se.is_retryable())
}

/// Translate Cloud KMS HTTP error matching `gslib/kms_api.py::_TranslateApitoolsException`.
pub fn translate_kms_error(
    status: u16,
    body: &str,
    www_authenticate: Option<&str>,
    key_name: Option<&str>,
) -> GsutilError {
    let message = extract_json_error_message(body);
    let combined = match www_authenticate {
        Some(h) => format!("{body} {h}"),
        None => body.to_string(),
    };
    let err = match status {
        400 => ServiceError::bad_request(
            message.unwrap_or_else(|| "Bad Request".to_string()),
            Some(status),
            None,
        ),
        401 => {
            if combined.contains("Login Required") {
                ServiceError::access_denied(
                    message.unwrap_or_else(|| "Access denied: login required.".to_string()),
                    Some(status),
                    None,
                )
            } else if combined.contains("insufficient_scope") {
                ServiceError::access_denied(
                    "Insufficient OAuth2 scope to perform this operation. \
                     Please re-run `gsutil config`",
                    Some(status),
                    extract_acceptable_scopes(www_authenticate),
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
            if combined.contains("The account for the specified project has been disabled") {
                ServiceError::access_denied(
                    message.unwrap_or_else(|| "Account disabled.".to_string()),
                    Some(status),
                    None,
                )
            } else if combined.contains("Daily Limit for Unauthenticated Use Exceeded") {
                ServiceError::access_denied(
                    message.unwrap_or_else(|| {
                        "Access denied: quota exceeded. Is your project ID valid?".to_string()
                    }),
                    Some(status),
                    None,
                )
            } else if combined.contains("User Rate Limit Exceeded") {
                ServiceError::access_denied(
                    "Rate limit exceeded. Please retry this request later.",
                    Some(status),
                    None,
                )
            } else if combined.contains("Access Not Configured") {
                ServiceError::access_denied(
                    "Access Not Configured. Please go to the Google Cloud Platform \
                     Console (https://cloud.google.com/console#/project) for your \
                     project, select APIs & services, and enable the Google Cloud \
                     KMS API.",
                    Some(status),
                    None,
                )
            } else if combined.contains("insufficient_scope") {
                ServiceError::access_denied(
                    "Insufficient OAuth2 scope to perform this operation. \
                     Please re-run `gsutil config`",
                    Some(status),
                    extract_acceptable_scopes(www_authenticate),
                )
            } else {
                ServiceError::access_denied(
                    message
                        .or_else(|| key_name.map(ToString::to_string))
                        .unwrap_or_else(|| body.to_string()),
                    Some(status),
                    None,
                )
            }
        }
        404 => ServiceError::not_found(
            message.unwrap_or_else(|| "Not Found".to_string()),
            Some(status),
            None,
        ),
        409 if key_name.is_some() => ServiceError::service(
            format!("The key {} already exists.", key_name.unwrap_or("")),
            Some(status),
            None,
        ),
        412 => ServiceError::precondition(
            message.unwrap_or_else(|| "Precondition Failed".to_string()),
            Some(status),
            None,
        ),
        429 | 500..=599 => ServiceError::retryable(
            message.unwrap_or_else(|| format!("HTTP {status}")),
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
