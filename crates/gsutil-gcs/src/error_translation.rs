//! Exact HTTP-to-`GsutilError`/`ServiceError` translation matching
//! `GcsJsonApi::_TranslateApitoolsException` and `_TranslateApitoolsResumableUploadException`
//! in `gslib/gcs_json_api.py`, plus `gslib/utils/translation_helper.py`.

use gsutil_core::error::{GsutilError, ServiceError};

/// Message used for insufficient OAuth2 scope errors in GCS JSON API.
pub const INSUFFICIENT_OAUTH2_SCOPE_MESSAGE: &str =
    "Insufficient OAuth2 scope to perform this operation.";

/// Contextual metadata attached to an HTTP error for accurate gsutil error messages.
#[derive(Debug, Clone, Default)]
pub struct ErrorContext<'a> {
    pub provider: &'a str,
    pub bucket_name: Option<&'a str>,
    pub object_name: Option<&'a str>,
    pub generation: Option<&'a str>,
    /// Pre-constructed 404 override (e.g. `create_not_found_for_object_write`).
    pub not_found_override: Option<ServiceError>,
}

impl<'a> ErrorContext<'a> {
    pub fn gs() -> Self {
        Self {
            provider: "gs",
            ..Default::default()
        }
    }

    pub fn bucket(bucket_name: &'a str) -> Self {
        Self {
            provider: "gs",
            bucket_name: Some(bucket_name),
            ..Default::default()
        }
    }

    pub fn object(bucket_name: &'a str, object_name: &'a str, generation: Option<&'a str>) -> Self {
        Self {
            provider: "gs",
            bucket_name: Some(bucket_name),
            object_name: Some(object_name),
            generation,
            not_found_override: None,
        }
    }
}

/// Extract `error.message` from a Google JSON API error payload.
pub fn extract_json_error_message(body: &str) -> Option<String> {
    let val: serde_json::Value = serde_json::from_str(body).ok()?;
    val.get("error")?
        .get("message")?
        .as_str()
        .map(ToString::to_string)
}

/// Parse `Acceptable scopes: ...` from a `www-authenticate` HTTP response header.
///
/// Matches `GcsJsonApi::_GetAcceptableScopesFromHttpError`.
pub fn extract_acceptable_scopes(www_authenticate: Option<&str>) -> Option<String> {
    let hdr = www_authenticate?;
    let idx = hdr.find("scope=\"")?;
    let rest = &hdr[idx + "scope=\"".len()..];
    let end = rest.find('"')?;
    Some(format!("Acceptable scopes: {}", &rest[..end]))
}

/// Match `CreateBucketNotFoundException` in `gslib/utils/translation_helper.py`.
pub fn create_bucket_not_found(status: u16, provider: &str, bucket_name: &str) -> ServiceError {
    ServiceError::bucket_not_found(
        format!("{provider}://{bucket_name} bucket does not exist."),
        bucket_name,
        Some(status),
        None,
    )
}

/// Match `CreateObjectNotFoundException` in `gslib/utils/translation_helper.py`.
pub fn create_object_not_found(
    status: u16,
    provider: &str,
    bucket_name: &str,
    object_name: &str,
    generation: Option<&str>,
) -> ServiceError {
    let mut uri = format!("{provider}://{bucket_name}/{object_name}");
    if let Some(gen) = generation {
        uri.push('#');
        uri.push_str(gen);
    }
    ServiceError::not_found(format!("{uri} does not exist."), Some(status), None)
}

/// Match `CreateNotFoundExceptionForObjectWrite` in `gslib/utils/translation_helper.py`.
pub fn create_not_found_for_object_write(
    dst_provider: &str,
    dst_bucket: &str,
    src_bucket: Option<&str>,
    src_object: Option<&str>,
    src_generation: Option<&str>,
) -> ServiceError {
    let dst_url = format!("{dst_provider}://{dst_bucket}");
    if let (Some(sb), Some(so)) = (src_bucket, src_object) {
        let mut src_url = format!("{dst_provider}://{sb}/{so}");
        if let Some(gen) = src_generation {
            src_url.push('#');
            src_url.push_str(gen);
        }
        return ServiceError::not_found(
            format!(
                "The source object {src_url} or the destination bucket {dst_url} does not exist."
            ),
            None,
            None,
        );
    }
    ServiceError::not_found(
        format!(
            "The destination bucket {dst_url} does not exist or the write to the \
             destination must be restarted"
        ),
        None,
        None,
    )
}

/// Translate an HTTP error response from GCS JSON API into the exact `GsutilError`
/// matching `GcsJsonApi::_TranslateApitoolsException`.
pub fn translate_http_error(
    status: u16,
    body: &str,
    www_authenticate: Option<&str>,
    ctx: &ErrorContext<'_>,
) -> GsutilError {
    let message = extract_json_error_message(body);
    let combined_text = match www_authenticate {
        Some(hdr) => format!("{body} {hdr}"),
        None => body.to_string(),
    };

    let service_err = match status {
        400 => ServiceError::bad_request(
            message.unwrap_or_else(|| "Bad Request".to_string()),
            Some(status),
            None,
        ),
        401 => {
            if combined_text.contains("Login Required") {
                ServiceError::access_denied(
                    message.unwrap_or_else(|| "Access denied: login required.".to_string()),
                    Some(status),
                    None,
                )
            } else if combined_text.contains("insufficient_scope") {
                ServiceError::access_denied(
                    INSUFFICIENT_OAUTH2_SCOPE_MESSAGE,
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
            if combined_text.contains("The account for the specified project has been disabled") {
                ServiceError::access_denied(
                    message.unwrap_or_else(|| "Account disabled.".to_string()),
                    Some(status),
                    None,
                )
            } else if combined_text.contains("Daily Limit for Unauthenticated Use Exceeded") {
                ServiceError::access_denied(
                    message.unwrap_or_else(|| {
                        "Access denied: quota exceeded. Is your project ID valid?".to_string()
                    }),
                    Some(status),
                    None,
                )
            } else if combined_text.contains("The bucket you tried to delete was not empty.") {
                let bkt = ctx.bucket_name.unwrap_or("");
                ServiceError::not_empty(format!("BucketNotEmpty ({bkt})"), Some(status), None)
            } else if combined_text
                .contains("The bucket you tried to create requires domain ownership verification.")
            {
                ServiceError::access_denied(
                    "The bucket you tried to create requires domain ownership \
                     verification. Please see \
                     https://cloud.google.com/storage/docs/naming?hl=en#verification \
                     for more details.",
                    Some(status),
                    None,
                )
            } else if combined_text.contains("User Rate Limit Exceeded") {
                ServiceError::access_denied(
                    "Rate limit exceeded. Please retry this request later.",
                    Some(status),
                    None,
                )
            } else if combined_text.contains("Access Not Configured") {
                ServiceError::access_denied(
                    "Access Not Configured. Please go to the Google Cloud Platform \
                     Console (https://cloud.google.com/console#/project) for your \
                     project, select APIs and Auth and enable the \
                     Google Cloud Storage JSON API.",
                    Some(status),
                    None,
                )
            } else if combined_text.contains("insufficient_scope") {
                ServiceError::access_denied(
                    INSUFFICIENT_OAUTH2_SCOPE_MESSAGE,
                    Some(status),
                    extract_acceptable_scopes(www_authenticate),
                )
            } else if combined_text.contains("does not have permission to publish messages") {
                ServiceError::publish_permission_denied(
                    message.unwrap_or_else(|| body.to_string()),
                    Some(status),
                    None,
                )
            } else {
                ServiceError::access_denied(
                    message.unwrap_or_else(|| body.to_string()),
                    Some(status),
                    None,
                )
            }
        }
        404 => {
            if let Some(mut override_err) = ctx.not_found_override.clone() {
                override_err.status = Some(status);
                override_err
            } else if let Some(bucket_name) = ctx.bucket_name {
                let provider = if ctx.provider.is_empty() {
                    "gs"
                } else {
                    ctx.provider
                };
                if let Some(object_name) = ctx.object_name {
                    create_object_not_found(
                        status,
                        provider,
                        bucket_name,
                        object_name,
                        ctx.generation,
                    )
                } else {
                    create_bucket_not_found(status, provider, bucket_name)
                }
            } else {
                ServiceError::not_found(
                    message.unwrap_or_else(|| "Not Found".to_string()),
                    Some(status),
                    None,
                )
            }
        }
        409 if ctx.bucket_name.is_some() => {
            let bucket_name = ctx.bucket_name.unwrap_or("");
            if body.contains("The bucket you tried to delete is not empty.") {
                ServiceError::not_empty(
                    format!("BucketNotEmpty ({bucket_name})"),
                    Some(status),
                    None,
                )
            } else {
                ServiceError::service(
                    format!(
                        "A Cloud Storage bucket named '{bucket_name}' already exists. Try another \
                         name. Bucket names must be globally unique across all Google Cloud \
                         projects, including those outside of your organization."
                    ),
                    Some(status),
                    None,
                )
            }
        }
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

    GsutilError::Service(service_err)
}

/// Translate an HTTP error during a resumable upload session matching
/// `GcsJsonApi::_TranslateApitoolsResumableUploadException`.
pub fn translate_resumable_upload_error(status: u16, body: &str) -> GsutilError {
    let message = extract_json_error_message(body);
    let err = if status >= 500 {
        ServiceError::resumable_upload(
            message.unwrap_or_else(|| "Server Error".to_string()),
            Some(status),
            None,
        )
    } else if status == 429 {
        ServiceError::resumable_upload(
            message.unwrap_or_else(|| "Too Many Requests".to_string()),
            Some(status),
            None,
        )
    } else if status == 410 || status == 404 {
        ServiceError::resumable_upload_start_over(
            message.unwrap_or_else(|| "Bad Request".to_string()),
            Some(status),
            None,
        )
    } else if status >= 400 {
        ServiceError::resumable_upload_abort(
            message.unwrap_or_else(|| "Bad Request".to_string()),
            Some(status),
            None,
        )
    } else {
        ServiceError::service(
            message.unwrap_or_else(|| format!("HTTP {status}")),
            Some(status),
            None,
        )
    };
    GsutilError::Service(err)
}
