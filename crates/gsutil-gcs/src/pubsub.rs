//! Cloud Pub/Sub v1 API client matching `gslib/pubsub_api.py`.

use std::sync::Arc;

use gsutil_auth::TokenProvider;
use gsutil_core::api::IamPolicy;
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result, ServiceError};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::error_translation::{extract_acceptable_scopes, extract_json_error_message};
use crate::retry::RetryPolicy;

pub const DEFAULT_PUBSUB_HOST: &str = "pubsub.googleapis.com";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PubsubTopic {
    pub name: String,
}

#[derive(Serialize)]
struct SetIamPolicyBody<'a> {
    policy: &'a IamPolicy,
}

/// Client for Google Cloud Pub/Sub v1 API (`gslib/pubsub_api.py`).
#[derive(Clone)]
pub struct PubsubClient {
    base_url: String,
    http: Client,
    credentials: Arc<dyn TokenProvider>,
    retry_policy: RetryPolicy,
}

impl PubsubClient {
    pub fn new(config: &BotoConfig, credentials: Arc<dyn TokenProvider>) -> Result<Self> {
        let host = config.get_or("Credentials", "gs_pubsub_host", DEFAULT_PUBSUB_HOST);
        let port = config.get("Credentials", "gs_pubsub_port");
        let base_url = match port.filter(|p| !p.is_empty()) {
            Some(p) => format!("https://{host}:{p}"),
            None => format!("https://{host}"),
        };
        let http = Client::builder()
            .danger_accept_invalid_certs(!config.https_validate_certificates())
            .build()
            .map_err(|e| {
                GsutilError::command(format!("Failed to build Pub/Sub HTTP client: {e}"))
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

    /// `GET /v1/{topic_name}`
    pub async fn get_topic(&self, topic_name: &str) -> Result<PubsubTopic> {
        let url = format!("{}/v1/{topic_name}", self.base_url);
        let text = self
            .retry_policy
            .execute(
                || async {
                    let req = self.apply_auth(self.http.get(&url)).await?;
                    send_and_check_pubsub(req, Some(topic_name)).await
                },
                is_retryable_err,
            )
            .await?;

        serde_json::from_str(&text).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Failed to parse Pub/Sub topic: {e}"),
                None,
                None,
            ))
        })
    }

    /// `PUT /v1/{topic_name}`
    pub async fn create_topic(&self, topic_name: &str) -> Result<PubsubTopic> {
        let url = format!("{}/v1/{topic_name}", self.base_url);
        let body = serde_json::json!({});
        let text = self
            .retry_policy
            .execute(
                || async {
                    let req = self.apply_auth(self.http.put(&url).json(&body)).await?;
                    send_and_check_pubsub(req, Some(topic_name)).await
                },
                is_retryable_err,
            )
            .await?;

        serde_json::from_str(&text).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Failed to parse Pub/Sub CreateTopic response: {e}"),
                None,
                None,
            ))
        })
    }

    /// `DELETE /v1/{topic_name}`
    pub async fn delete_topic(&self, topic_name: &str) -> Result<()> {
        let url = format!("{}/v1/{topic_name}", self.base_url);
        self.retry_policy
            .execute(
                || async {
                    let req = self.apply_auth(self.http.delete(&url)).await?;
                    send_and_check_pubsub(req, Some(topic_name))
                        .await
                        .map(|_| ())
                },
                is_retryable_err,
            )
            .await
    }

    /// `GET /v1/{topic_name}:getIamPolicy`
    pub async fn get_topic_iam_policy(&self, topic_name: &str) -> Result<IamPolicy> {
        let url = format!("{}/v1/{topic_name}:getIamPolicy", self.base_url);
        let text = self
            .retry_policy
            .execute(
                || async {
                    let req = self.apply_auth(self.http.get(&url)).await?;
                    send_and_check_pubsub(req, Some(topic_name)).await
                },
                is_retryable_err,
            )
            .await?;

        serde_json::from_str(&text).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Failed to parse Pub/Sub IAM policy: {e}"),
                None,
                None,
            ))
        })
    }

    /// `POST /v1/{topic_name}:setIamPolicy`
    pub async fn set_topic_iam_policy(
        &self,
        topic_name: &str,
        policy: &IamPolicy,
    ) -> Result<IamPolicy> {
        let url = format!("{}/v1/{topic_name}:setIamPolicy", self.base_url);
        let body = SetIamPolicyBody { policy };
        let text = self
            .retry_policy
            .execute(
                || async {
                    let req = self.apply_auth(self.http.post(&url).json(&body)).await?;
                    send_and_check_pubsub(req, Some(topic_name)).await
                },
                is_retryable_err,
            )
            .await?;

        serde_json::from_str(&text).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Failed to parse Pub/Sub SetIamPolicy response: {e}"),
                None,
                None,
            ))
        })
    }
}

async fn send_and_check_pubsub(
    req: reqwest::RequestBuilder,
    topic_name: Option<&str>,
) -> Result<String> {
    let resp = req.send().await.map_err(|e| {
        if RetryPolicy::is_retryable_reqwest_error(&e) {
            GsutilError::Service(ServiceError::retryable(
                format!("Pub/Sub request error: {e}"),
                None,
                None,
            ))
        } else {
            GsutilError::Service(ServiceError::service(
                format!("Pub/Sub request error: {e}"),
                None,
                None,
            ))
        }
    })?;
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
        Err(translate_pubsub_error(
            status,
            &text,
            www_auth.as_deref(),
            topic_name,
        ))
    }
}

fn is_retryable_err(e: &GsutilError) -> bool {
    matches!(e, GsutilError::Service(se) if se.is_retryable())
}

/// Translate Pub/Sub HTTP error matching `gslib/pubsub_api.py::_TranslateApitoolsException`.
pub fn translate_pubsub_error(
    status: u16,
    body: &str,
    www_authenticate: Option<&str>,
    topic_name: Option<&str>,
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
                     project, select APIs and Auth and enable the \
                     Google Cloud Pub/Sub API.",
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
                    message.unwrap_or_else(|| body.to_string()),
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
        409 if topic_name.is_some() => ServiceError::service(
            format!("The topic {} already exists.", topic_name.unwrap_or("")),
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
