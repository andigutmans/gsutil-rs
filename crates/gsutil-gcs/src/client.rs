//! Full GCS JSON API v1 client implementing `gsutil_core::api::CloudApi`.
//!
//! Mirrors `gslib/gcs_json_api.py` in Python gsutil v5.38.

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use chrono::Utc;
use futures::StreamExt;
use gsutil_auth::adc::is_mtls_enabled;
use gsutil_auth::resolver::format_proxy_url;
use gsutil_auth::TokenProvider;
use gsutil_core::api::{
    Bucket, ByteStream, Channel, CloudApi, ComposeSourceObject, CopyOptions,
    CreateNotificationOptions, CsObjectOrPrefix, DownloadOptions, DownloadStrategy, EncryptionKey,
    HmacKeyCreateResponse, HmacKeyMetadata, IamPolicy, ListObjectsOptions, Notification, Object,
    Preconditions, ServiceAccount, SignUrlOptions, UploadOptions,
};
use gsutil_core::config::{BotoConfig, RESUMABLE_CHUNK_QUANTUM};
use gsutil_core::error::{GsutilError, Result, ServiceError, ServiceErrorKind};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, RANGE, USER_AGENT};
use reqwest::{Client, Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, SeekFrom};
use tracing::debug;

use crate::ecp::{EcpProxy, ECP_TARGET_HOST_HEADER};
use crate::error_translation::{
    create_not_found_for_object_write, translate_http_error, translate_resumable_upload_error,
    ErrorContext,
};
use crate::retry::RetryPolicy;

pub const DEFAULT_GCS_HOST: &str = "storage.googleapis.com";
pub const MTLS_GCS_HOST: &str = "storage.mtls.googleapis.com";
pub const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";
pub const DEFAULT_USER_AGENT: &str = "gsutil-rs/0.1.0 (gsutil 5.38 compatible)";
pub const IAM_POLICY_VERSION: i32 = 3;
pub const NUM_BUCKETS_PER_LIST_PAGE: u32 = 1000;
pub const NUM_OBJECTS_PER_LIST_PAGE: u32 = 1000;
pub const REQUEST_REASON_ENV_VAR: &str = "CLOUDSDK_CORE_REQUEST_REASON";
pub const REQUEST_REASON_HEADER_KEY: &str = "x-goog-request-reason";

const ACL_FIELDS: &[&str] = &[
    "acl",
    "defaultObjectAcl",
    "items/acl",
    "items/defaultObjectAcl",
    "items/owner",
    "owner",
];

/// Configuration options for [`GcsJsonClient`].
#[derive(Debug, Clone)]
pub struct GcsJsonClientConfig {
    /// Base URL for JSON API endpoints (e.g. `https://storage.googleapis.com/storage/v1`).
    pub storage_base_url: String,
    /// Base URL for upload endpoints (e.g. `https://storage.googleapis.com/upload/storage/v1`).
    pub upload_base_url: String,
    /// API version string (default `"v1"`).
    pub api_version: String,
    /// Project ID to bill for Requester Pays (`-u` / `userProject`).
    pub user_project: Option<String>,
    /// Default project ID from `.boto` `[GSUtil] default_project_id`.
    pub default_project_id: Option<String>,
    /// Arbitrary `-h` custom HTTP headers applied to requests.
    pub custom_headers: BTreeMap<String, String>,
    /// Apiary trace token (`--trace-token`).
    pub trace_token: Option<String>,
    /// Performance trace token (`--perf-trace-token`, sent as `cookie` header).
    pub perf_trace_token: Option<String>,
    /// Custom `User-Agent` header.
    pub user_agent: String,
    /// Chunk size for resumable uploads (rounded up to multiple of 256 KiB).
    pub resumable_chunk_size: usize,
    /// Retry policy for transient failures.
    pub retry_policy: RetryPolicy,
    /// Debug verbosity level (`0` = off, `2` = `-d`/`-D` headers, `3` = `-DD` headers + body).
    pub debug_level: u8,
    /// Configured CSEK keys from `.boto` (`[GSUtil] encryption_key` and `decryption_key1..100`)
    /// stored as `(key_b64, key_sha256_b64)` pairs for transparent metadata/hash decryption.
    pub csek_keys: Vec<(String, String)>,
}

impl GcsJsonClientConfig {
    /// Build configuration from `.boto` config (validating `gs_json_host` / `gs_host` / mTLS
    /// rules matching `GcsJsonApi.__init__`).
    pub fn from_boto_config(config: &BotoConfig) -> Result<Self> {
        let gs_json_host = config
            .get("Credentials", "gs_json_host")
            .filter(|s| !s.is_empty());
        let explicit_boto_mtls = config.get_bool("Credentials", "use_client_certificate", false);
        let use_mtls = is_mtls_enabled(config);
        let has_client_identity = resolve_client_identity_pem(config).is_some();

        let host_base = if let Some(custom) = gs_json_host {
            if explicit_boto_mtls {
                return Err(GsutilError::argument(format!(
                    "\"use_client_certificate\" is enabled, which sets gsutil to use the \
                     host {MTLS_GCS_HOST}. However, a custom host was set using \
                     \"gs_json_host\": {custom}. Please set \"use_client_certificate\" to \
                     \"False\" or comment out the \"gs_json_host\" line in the Boto config."
                )));
            }
            custom
        } else if use_mtls {
            if has_client_identity {
                MTLS_GCS_HOST
            } else {
                debug!(
                    "mTLS requested but no client TLS identity PEM was found; \
                     falling back to {DEFAULT_GCS_HOST}"
                );
                DEFAULT_GCS_HOST
            }
        } else {
            DEFAULT_GCS_HOST
        };

        if gs_json_host.is_none() {
            if let Some(gs_host) = config
                .get("Credentials", "gs_host")
                .filter(|s| !s.is_empty())
            {
                return Err(GsutilError::argument(format!(
                    "JSON API is selected but gs_json_host is not configured, \
                     while gs_host is configured to {gs_host}. Please also configure \
                     gs_json_host and gs_json_port to match your desired endpoint."
                )));
            }
        }

        let gs_json_port = config
            .get("Credentials", "gs_json_port")
            .filter(|s| !s.is_empty());
        if gs_json_port.is_none() {
            if let Some(gs_port) = config
                .get("Credentials", "gs_port")
                .filter(|s| !s.is_empty())
            {
                return Err(GsutilError::argument(format!(
                    "JSON API is selected but gs_json_port is not configured, \
                     while gs_port is configured to {gs_port}. Please also configure \
                     gs_json_host and gs_json_port to match your desired endpoint."
                )));
            }
        }

        let force_mock_http = env::var("GSUTIL_TEST_MOCK_HTTP")
            .ok()
            .as_deref()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        let is_loopback = host_base == "127.0.0.1" || host_base == "localhost";
        let scheme = if host_base.starts_with("http://") || host_base.starts_with("https://") {
            ""
        } else if !config.is_secure() || (force_mock_http && is_loopback) {
            "http://"
        } else {
            "https://"
        };
        let port_suffix = gs_json_port.map(|p| format!(":{p}")).unwrap_or_default();
        let api_version = config.gcs_json_api_version().to_string();
        let origin = format!("{scheme}{host_base}{port_suffix}");

        let mut custom_headers = BTreeMap::new();
        if let (Some(host_hdr), true) = (
            config
                .get("Credentials", "gs_json_host_header")
                .filter(|s| !s.is_empty()),
            gs_json_host.is_some(),
        ) {
            custom_headers.insert("Host".to_string(), host_hdr.to_string());
        }

        let chunk_size = config
            .json_resumable_chunk_size()
            .max(RESUMABLE_CHUNK_QUANTUM) as usize;

        Ok(Self {
            storage_base_url: format!("{origin}/storage/{api_version}"),
            upload_base_url: format!("{origin}/upload/storage/{api_version}"),
            api_version,
            user_project: None,
            default_project_id: config.default_project_id().map(ToString::to_string),
            custom_headers,
            trace_token: None,
            perf_trace_token: None,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            resumable_chunk_size: chunk_size,
            retry_policy: RetryPolicy::from_config(config),
            debug_level: 0,
            csek_keys: load_csek_keys_from_boto(config),
        })
    }

    /// Construct a config pointing to a local mock server URL (e.g. `http://127.0.0.1:12345`).
    pub fn for_mock_server(base_url: impl Into<String>) -> Self {
        let base = base_url.into().trim_end_matches('/').to_string();
        Self {
            storage_base_url: format!("{base}/storage/v1"),
            upload_base_url: format!("{base}/upload/storage/v1"),
            api_version: "v1".to_string(),
            user_project: None,
            default_project_id: Some("test-project".to_string()),
            custom_headers: BTreeMap::new(),
            trace_token: None,
            perf_trace_token: None,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            resumable_chunk_size: RESUMABLE_CHUNK_QUANTUM as usize,
            retry_policy: RetryPolicy::fast_for_tests(3),
            debug_level: 0,
            csek_keys: Vec::new(),
        }
    }
}

/// Google Cloud Storage JSON API v1 client.
#[derive(Clone)]
pub struct GcsJsonClient {
    http: Client,
    /// Separate HTTP client with `.no_gzip()` for object media downloads so `Accept-Encoding: gzip`
    /// is never injected automatically and compressed payloads are never transparently decompressed.
    media_http: Client,
    credentials: Arc<dyn TokenProvider>,
    config: GcsJsonClientConfig,
    ecp_proxy: Option<Arc<EcpProxy>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BucketsListResponse {
    #[serde(default)]
    items: Vec<Bucket>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ObjectsListResponse {
    #[serde(default)]
    items: Vec<Object>,
    #[serde(default)]
    prefixes: Vec<String>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotificationsListResponse {
    #[serde(default)]
    items: Vec<Notification>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacKeysListResponse {
    #[serde(default)]
    items: Vec<HmacKeyMetadata>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RewriteResponse {
    #[serde(default)]
    done: bool,
    rewrite_token: Option<String>,
    resource: Option<Object>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ComposeRequestBody<'a> {
    source_objects: &'a [ComposeSourceObject],
    destination: &'a Object,
}

impl GcsJsonClient {
    /// Create a new `GcsJsonClient` from `.boto` configuration and a `TokenProvider`.
    pub fn from_boto_config(
        boto_config: &BotoConfig,
        credentials: Arc<dyn TokenProvider>,
    ) -> Result<Self> {
        let client_config = GcsJsonClientConfig::from_boto_config(boto_config)?;
        Self::with_http_config(boto_config, client_config, credentials)
    }

    /// Create a `GcsJsonClient` with explicit [`GcsJsonClientConfig`] and HTTP settings from `.boto`.
    pub fn with_http_config(
        boto_config: &BotoConfig,
        mut client_config: GcsJsonClientConfig,
        credentials: Arc<dyn TokenProvider>,
    ) -> Result<Self> {
        let mut ecp_proxy = None;
        let targets_google_storage = client_config
            .storage_base_url
            .starts_with("https://storage.googleapis.com")
            || client_config
                .storage_base_url
                .starts_with("https://storage.mtls.googleapis.com");

        if is_mtls_enabled(boto_config) {
            if resolve_client_identity_pem(boto_config).is_none() && targets_google_storage {
                if let Some(proxy) = EcpProxy::detect_or_spawn(boto_config)? {
                    client_config.storage_base_url =
                        proxy.rewrite_gcs_url(&client_config.storage_base_url);
                    client_config.upload_base_url =
                        proxy.rewrite_gcs_url(&client_config.upload_base_url);
                    client_config.custom_headers.insert(
                        ECP_TARGET_HOST_HEADER.to_string(),
                        proxy.target_host().to_string(),
                    );
                    ecp_proxy = Some(proxy);
                }
            }
        } else if targets_google_storage {
            if let Some(proxy) = EcpProxy::detect_or_spawn(boto_config)? {
                client_config.storage_base_url =
                    proxy.rewrite_gcs_url(&client_config.storage_base_url);
                client_config.upload_base_url =
                    proxy.rewrite_gcs_url(&client_config.upload_base_url);
                client_config.custom_headers.insert(
                    ECP_TARGET_HOST_HEADER.to_string(),
                    proxy.target_host().to_string(),
                );
                ecp_proxy = Some(proxy);
            }
        }

        let http = build_reqwest_client(boto_config, false)?;
        let media_http = build_reqwest_client(boto_config, true)?;

        Ok(Self {
            http,
            media_http,
            credentials,
            config: client_config,
            ecp_proxy,
        })
    }

    /// Create a `GcsJsonClient` directly from a [`GcsJsonClientConfig`] (convenient for tests).
    pub fn new(config: GcsJsonClientConfig, credentials: Arc<dyn TokenProvider>) -> Result<Self> {
        let http = Client::builder()
            .pool_max_idle_per_host(32)
            .build()
            .map_err(|e| GsutilError::command(format!("Failed to build GCS HTTP client: {e}")))?;
        let media_http = Client::builder()
            .pool_max_idle_per_host(32)
            .no_gzip()
            .build()
            .map_err(|e| {
                GsutilError::command(format!("Failed to build GCS media HTTP client: {e}"))
            })?;
        Ok(Self {
            http,
            media_http,
            credentials,
            config,
            ecp_proxy: None,
        })
    }

    pub fn config(&self) -> &GcsJsonClientConfig {
        &self.config
    }

    /// Return the configured `user_project` (`-u`) for Requester Pays billing.
    fn effective_user_project(&self) -> Option<&str> {
        self.config.user_project.as_deref()
    }

    fn require_project_id<'a>(&'a self, project_id: Option<&'a str>) -> Result<&'a str> {
        project_id
            .filter(|s| !s.trim().is_empty())
            .or(self.config.default_project_id.as_deref())
            .ok_or_else(|| GsutilError::project_id("No project ID configured for this operation."))
    }

    fn base_headers(&self, extra: Option<&HeaderMap>) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.config.user_agent)
                .unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_USER_AGENT)),
        );

        for (k, v) in &self.config.custom_headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                headers.insert(name, val);
            }
        }

        if let Some(ref perf) = self.config.perf_trace_token {
            if let Ok(val) = HeaderValue::from_str(perf) {
                headers.insert(HeaderName::from_static("cookie"), val);
            }
        }

        if let Ok(reason) = env::var(REQUEST_REASON_ENV_VAR) {
            if !reason.trim().is_empty() {
                if let Ok(val) = HeaderValue::from_str(reason.trim()) {
                    headers.insert(HeaderName::from_static(REQUEST_REASON_HEADER_KEY), val);
                }
            }
        }

        if let Some(extra_hdrs) = extra {
            for (k, v) in extra_hdrs {
                headers.insert(k.clone(), v.clone());
            }
        }
        Ok(headers)
    }

    async fn prepare_request(
        &self,
        method: Method,
        url: &str,
        query: &[(String, String)],
        extra_headers: Option<&HeaderMap>,
    ) -> Result<RequestBuilder> {
        self.prepare_request_with_client(&self.http, method, url, query, extra_headers)
            .await
    }

    async fn prepare_request_with_client(
        &self,
        client: &Client,
        method: Method,
        url: &str,
        query: &[(String, String)],
        extra_headers: Option<&HeaderMap>,
    ) -> Result<RequestBuilder> {
        let headers = self.base_headers(extra_headers)?;
        if self.config.debug_level >= 2 {
            log_wire_request(&method, url, query, &headers);
        }
        let mut req = client.request(method, url).headers(headers);

        if let Some(tok) = self.credentials.token().await? {
            req = req.bearer_auth(&tok.token);
        }

        if let Some(ref trace) = self.config.trace_token {
            req = req.query(&[("trace", format!("token:{trace}"))]);
        }

        if !query.is_empty() {
            req = req.query(query);
        }

        Ok(req)
    }

    async fn send_json_request<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        url: &str,
        query: &[(String, String)],
        body: Option<&serde_json::Value>,
        extra_headers: Option<&HeaderMap>,
        ctx: &ErrorContext<'_>,
    ) -> Result<T> {
        let text = self
            .send_text_request(method, url, query, body, extra_headers, ctx)
            .await?;
        serde_json::from_str(&text).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Failed to parse GCS JSON response: {e}"),
                None,
                None,
            ))
        })
    }

    async fn send_text_request(
        &self,
        method: Method,
        url: &str,
        query: &[(String, String)],
        body: Option<&serde_json::Value>,
        extra_headers: Option<&HeaderMap>,
        ctx: &ErrorContext<'_>,
    ) -> Result<String> {
        self.config
            .retry_policy
            .execute(
                || async {
                    let mut req = self
                        .prepare_request(method.clone(), url, query, extra_headers)
                        .await?;
                    if let Some(b) = body {
                        if self.config.debug_level >= 3 {
                            eprintln!("send body: {b}");
                        }
                        req = req.json(b);
                    }
                    let resp = req.send().await.map_err(reqwest_to_service_error)?;
                    let status = resp.status().as_u16();
                    if self.config.debug_level >= 2 {
                        log_wire_response(status, resp.headers());
                    }
                    let www_auth = resp
                        .headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .map(ToString::to_string);
                    let text = resp.text().await.unwrap_or_default();
                    if self.config.debug_level >= 3 && !text.is_empty() {
                        eprintln!("reply body: {text}");
                    }
                    if (200..300).contains(&status) {
                        Ok(text)
                    } else {
                        Err(translate_http_error(
                            status,
                            &text,
                            www_auth.as_deref(),
                            ctx,
                        ))
                    }
                },
                is_retryable_gsutil_error,
            )
            .await
    }

    async fn send_empty_request(
        &self,
        method: Method,
        url: &str,
        query: &[(String, String)],
        body: Option<&serde_json::Value>,
        extra_headers: Option<&HeaderMap>,
        ctx: &ErrorContext<'_>,
    ) -> Result<()> {
        self.send_text_request(method, url, query, body, extra_headers, ctx)
            .await
            .map(|_| ())
    }
}

#[async_trait]
impl CloudApi for GcsJsonClient {
    async fn get_service_account_id(&self) -> Result<String> {
        self.credentials
            .service_account_email()
            .map(ToString::to_string)
            .ok_or_else(|| {
                GsutilError::command(
                    "Cannot get service account email id for the given credential type.",
                )
            })
    }

    // -----------------------------------------------------------------------
    // Buckets
    // -----------------------------------------------------------------------

    async fn get_bucket(&self, bucket_name: &str, fields: Option<&[String]>) -> Result<Bucket> {
        let url = format!(
            "{}/b/{}",
            self.config.storage_base_url,
            encode_path_segment(bucket_name)
        );
        let mut query = vec![(
            "projection".to_string(),
            projection_for_fields(fields).to_string(),
        )];
        add_user_project(&mut query, self.effective_user_project());
        add_fields_param(&mut query, fields, false);

        let ctx = ErrorContext::bucket(bucket_name);
        self.send_json_request(Method::GET, &url, &query, None, None, &ctx)
            .await
    }

    async fn list_buckets(
        &self,
        project_id: Option<&str>,
        fields: Option<&[String]>,
    ) -> Result<Vec<Bucket>> {
        let project = self.require_project_id(project_id)?;
        let url = format!("{}/b", self.config.storage_base_url);
        let projection = projection_for_fields(fields);

        let mut buckets = Vec::new();
        let mut next_page_token: Option<String> = None;

        loop {
            let mut query = vec![
                ("project".to_string(), project.to_string()),
                (
                    "maxResults".to_string(),
                    NUM_BUCKETS_PER_LIST_PAGE.to_string(),
                ),
                ("projection".to_string(), projection.to_string()),
            ];
            add_user_project(&mut query, self.effective_user_project());
            add_list_fields_param(&mut query, fields, false);
            if let Some(ref tok) = next_page_token {
                query.push(("pageToken".to_string(), tok.clone()));
            }

            let ctx = ErrorContext::gs();
            let page: BucketsListResponse = self
                .send_json_request(Method::GET, &url, &query, None, None, &ctx)
                .await?;

            buckets.extend(page.items);
            match page.next_page_token {
                Some(tok) if !tok.is_empty() => next_page_token = Some(tok),
                _ => break,
            }
        }

        Ok(buckets)
    }

    async fn create_bucket(
        &self,
        bucket_name: &str,
        project_id: Option<&str>,
        metadata: Option<&Bucket>,
        fields: Option<&[String]>,
    ) -> Result<Bucket> {
        let project = self.require_project_id(project_id)?;
        let url = format!("{}/b", self.config.storage_base_url);

        let mut bucket_body = metadata.cloned().unwrap_or_default();
        bucket_body.name = Some(bucket_name.to_string());
        if let Some(ref loc) = bucket_body.location {
            bucket_body.location = Some(loc.to_ascii_lowercase());
        }
        if let Some(ref sc) = bucket_body.storage_class {
            bucket_body.storage_class = Some(sc.to_ascii_lowercase());
        }

        let mut query = vec![
            ("project".to_string(), project.to_string()),
            (
                "projection".to_string(),
                projection_for_fields(fields).to_string(),
            ),
        ];
        add_user_project(&mut query, self.effective_user_project());
        add_fields_param(&mut query, fields, false);

        let body_val = serde_json::to_value(&bucket_body).map_err(|e| {
            GsutilError::command(format!("Failed to serialize bucket metadata: {e}"))
        })?;
        let ctx = ErrorContext::bucket(bucket_name);
        self.send_json_request(Method::POST, &url, &query, Some(&body_val), None, &ctx)
            .await
    }

    async fn patch_bucket(
        &self,
        bucket_name: &str,
        metadata: &Bucket,
        canned_acl: Option<&str>,
        canned_def_acl: Option<&str>,
        preconditions: Option<&Preconditions>,
        fields: Option<&[String]>,
    ) -> Result<Bucket> {
        let url = format!(
            "{}/b/{}",
            self.config.storage_base_url,
            encode_path_segment(bucket_name)
        );
        let mut query = vec![(
            "projection".to_string(),
            projection_for_fields(fields).to_string(),
        )];

        if let Some(pre) = preconditions {
            if let Some(mg) = pre.meta_gen_match {
                query.push(("ifMetagenerationMatch".to_string(), mg.to_string()));
            }
        }
        if let Some(acl) = canned_acl {
            query.push((
                "predefinedAcl".to_string(),
                bucket_canned_acl_to_json(acl)?.to_string(),
            ));
        }
        if let Some(def_acl) = canned_def_acl {
            query.push((
                "predefinedDefaultObjectAcl".to_string(),
                object_canned_acl_to_json(def_acl)?.to_string(),
            ));
        }
        add_user_project(&mut query, self.effective_user_project());
        add_fields_param(&mut query, fields, false);

        let body_val = metadata.to_patch_value();
        let ctx = ErrorContext::bucket(bucket_name);
        self.send_json_request(Method::PATCH, &url, &query, Some(&body_val), None, &ctx)
            .await
    }

    async fn delete_bucket(
        &self,
        bucket_name: &str,
        preconditions: Option<&Preconditions>,
    ) -> Result<()> {
        let url = format!(
            "{}/b/{}",
            self.config.storage_base_url,
            encode_path_segment(bucket_name)
        );
        let mut query = Vec::new();
        if let Some(pre) = preconditions {
            if let Some(mg) = pre.meta_gen_match {
                query.push(("ifMetagenerationMatch".to_string(), mg.to_string()));
            }
        }
        add_user_project(&mut query, self.effective_user_project());

        let ctx = ErrorContext::bucket(bucket_name);
        match self
            .send_empty_request(Method::DELETE, &url, &query, None, None, &ctx)
            .await
        {
            Ok(()) => Ok(()),
            Err(GsutilError::Service(se)) if se.kind == ServiceErrorKind::NotEmpty => {
                // Match GcsJsonApi.DeleteBucket: check whether versioning is enabled
                // and signal VersionedBucketNotEmpty if so.
                let fields = vec!["versioning".to_string()];
                if let Ok(bkt) = self.get_bucket(bucket_name, Some(&fields)).await {
                    if bkt.versioning.and_then(|v| v.enabled) == Some(true) {
                        return Err(GsutilError::Service(ServiceError::not_empty(
                            "VersionedBucketNotEmpty",
                            se.status,
                            None,
                        )));
                    }
                }
                Err(GsutilError::Service(se))
            }
            Err(other) => Err(other),
        }
    }

    async fn lock_retention_policy(
        &self,
        bucket_name: &str,
        metageneration: i64,
    ) -> Result<Bucket> {
        let url = format!(
            "{}/b/{}/lockRetentionPolicy",
            self.config.storage_base_url,
            encode_path_segment(bucket_name)
        );
        let mut query = vec![(
            "ifMetagenerationMatch".to_string(),
            metageneration.to_string(),
        )];
        add_user_project(&mut query, self.effective_user_project());
        let ctx = ErrorContext::bucket(bucket_name);
        self.send_json_request(Method::POST, &url, &query, None, None, &ctx)
            .await
    }

    async fn get_bucket_iam_policy(
        &self,
        bucket_name: &str,
        fields: Option<&[String]>,
    ) -> Result<IamPolicy> {
        let url = format!(
            "{}/b/{}/iam",
            self.config.storage_base_url,
            encode_path_segment(bucket_name)
        );
        let mut query = vec![(
            "optionsRequestedPolicyVersion".to_string(),
            IAM_POLICY_VERSION.to_string(),
        )];
        add_user_project(&mut query, self.effective_user_project());
        add_fields_param(&mut query, fields, false);

        let ctx = ErrorContext::bucket(bucket_name);
        self.send_json_request(Method::GET, &url, &query, None, None, &ctx)
            .await
    }

    async fn set_bucket_iam_policy(
        &self,
        bucket_name: &str,
        policy: &IamPolicy,
    ) -> Result<IamPolicy> {
        let url = format!(
            "{}/b/{}/iam",
            self.config.storage_base_url,
            encode_path_segment(bucket_name)
        );
        let mut query = Vec::new();
        add_user_project(&mut query, self.effective_user_project());
        let body_val = serde_json::to_value(policy)
            .map_err(|e| GsutilError::command(format!("Failed to serialize IAM policy: {e}")))?;
        let ctx = ErrorContext::bucket(bucket_name);
        self.send_json_request(Method::PUT, &url, &query, Some(&body_val), None, &ctx)
            .await
    }

    // -----------------------------------------------------------------------
    // Objects
    // -----------------------------------------------------------------------

    async fn list_objects(
        &self,
        bucket_name: &str,
        options: &ListObjectsOptions,
    ) -> Result<Vec<CsObjectOrPrefix>> {
        let url = format!(
            "{}/b/{}/o",
            self.config.storage_base_url,
            encode_path_segment(bucket_name)
        );
        let fields_slice = options.fields.as_deref();
        let projection = projection_for_fields(fields_slice);

        let mut results = Vec::new();
        let mut next_page_token: Option<String> = None;

        loop {
            let mut query = vec![
                ("projection".to_string(), projection.to_string()),
                (
                    "maxResults".to_string(),
                    NUM_OBJECTS_PER_LIST_PAGE.to_string(),
                ),
            ];
            if let Some(ref prefix) = options.prefix {
                query.push(("prefix".to_string(), prefix.clone()));
            }
            if let Some(ref delimiter) = options.delimiter {
                query.push(("delimiter".to_string(), delimiter.clone()));
            }
            if options.all_versions {
                query.push(("versions".to_string(), "true".to_string()));
            }
            if let Some(ref tok) = next_page_token {
                query.push(("pageToken".to_string(), tok.clone()));
            }
            add_user_project(&mut query, self.effective_user_project());
            add_list_fields_param(&mut query, fields_slice, true);

            let ctx = ErrorContext::bucket(bucket_name);
            let page: ObjectsListResponse = self
                .send_json_request(Method::GET, &url, &query, None, None, &ctx)
                .await?;

            // gsutil ls depends on yielding objects before prefixes.
            let needs_hash_decrypt = fields_request_hashes(fields_slice);
            for mut obj in page.items {
                if needs_hash_decrypt {
                    if let Some(ref ce) = obj.customer_encryption {
                        if obj.crc32c.is_none() && obj.md5_hash.is_none() {
                            if let (Some(ref key_sha256), Some(ref obj_name)) =
                                (&ce.key_sha256, &obj.name)
                            {
                                if let Some(dec_key) = self.find_matching_csek(key_sha256) {
                                    match self
                                        .get_object_metadata_with_key(
                                            bucket_name,
                                            obj_name,
                                            obj.generation.as_deref(),
                                            None,
                                            Some(&dec_key),
                                        )
                                        .await
                                    {
                                        Ok(decrypted) => obj = decrypted,
                                        Err(e) if e.is_not_found() => continue,
                                        Err(_) => {}
                                    }
                                }
                            }
                        }
                    }
                }
                results.push(CsObjectOrPrefix::Object(Box::new(obj)));
            }
            for prefix in page.prefixes {
                results.push(CsObjectOrPrefix::Prefix(prefix));
            }

            match page.next_page_token {
                Some(tok) if !tok.is_empty() => next_page_token = Some(tok),
                _ => break,
            }
        }

        Ok(results)
    }

    async fn get_object_metadata(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
        fields: Option<&[String]>,
    ) -> Result<Object> {
        let obj = self
            .get_object_metadata_with_key(bucket_name, object_name, generation, fields, None)
            .await?;

        let obj = if let Some(ref ce) = obj.customer_encryption {
            let need_hashes =
                obj.crc32c.is_none() && obj.md5_hash.is_none() && fields_request_hashes(fields);
            if need_hashes {
                if let Some(ref key_sha256) = ce.key_sha256 {
                    if let Some(dec_key) = self.find_matching_csek(key_sha256) {
                        self.get_object_metadata_with_key(
                            bucket_name,
                            object_name,
                            generation,
                            fields,
                            Some(&dec_key),
                        )
                        .await?
                    } else if fields.is_some() {
                        return Err(GsutilError::Encryption(format!(
                            "Missing decryption key with SHA256 hash {key_sha256}. \
                             No decryption key matches object gs://{bucket_name}/{object_name}"
                        )));
                    } else {
                        obj
                    }
                } else {
                    obj
                }
            } else {
                obj
            }
        } else {
            obj
        };

        if self.config.debug_level >= 2 {
            if let Some(ref md5) = obj.md5_hash {
                eprintln!("md5Hash: '{md5}'");
            }
        }

        Ok(obj)
    }

    async fn patch_object_metadata(
        &self,
        bucket_name: &str,
        object_name: &str,
        metadata: &Object,
        canned_acl: Option<&str>,
        generation: Option<&str>,
        preconditions: Option<&Preconditions>,
        fields: Option<&[String]>,
    ) -> Result<Object> {
        let url = format!(
            "{}/b/{}/o/{}",
            self.config.storage_base_url,
            encode_path_segment(bucket_name),
            encode_path_segment(object_name)
        );
        let mut query = vec![(
            "projection".to_string(),
            projection_for_fields(fields).to_string(),
        )];
        if let Some(gen) = generation {
            query.push(("generation".to_string(), gen.to_string()));
        }
        add_preconditions(&mut query, preconditions);
        if let Some(acl) = canned_acl {
            query.push((
                "predefinedAcl".to_string(),
                object_canned_acl_to_json(acl)?.to_string(),
            ));
        }
        add_user_project(&mut query, self.effective_user_project());
        add_fields_param(&mut query, fields, false);

        let body_val = metadata.to_patch_value();
        let ctx = ErrorContext::object(bucket_name, object_name, generation);
        self.send_json_request(Method::PATCH, &url, &query, Some(&body_val), None, &ctx)
            .await
    }

    async fn get_object_iam_policy(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
        fields: Option<&[String]>,
    ) -> Result<IamPolicy> {
        let url = format!(
            "{}/b/{}/o/{}/iam",
            self.config.storage_base_url,
            encode_path_segment(bucket_name),
            encode_path_segment(object_name)
        );
        let mut query = Vec::new();
        if let Some(gen) = generation {
            query.push(("generation".to_string(), gen.to_string()));
        }
        add_user_project(&mut query, self.effective_user_project());
        add_fields_param(&mut query, fields, false);

        let ctx = ErrorContext::object(bucket_name, object_name, generation);
        self.send_json_request(Method::GET, &url, &query, None, None, &ctx)
            .await
    }

    async fn set_object_iam_policy(
        &self,
        bucket_name: &str,
        object_name: &str,
        policy: &IamPolicy,
        generation: Option<&str>,
    ) -> Result<IamPolicy> {
        let url = format!(
            "{}/b/{}/o/{}/iam",
            self.config.storage_base_url,
            encode_path_segment(bucket_name),
            encode_path_segment(object_name)
        );
        let mut query = Vec::new();
        if let Some(gen) = generation {
            query.push(("generation".to_string(), gen.to_string()));
        }
        add_user_project(&mut query, self.effective_user_project());
        let body_val = serde_json::to_value(policy)
            .map_err(|e| GsutilError::command(format!("Failed to serialize IAM policy: {e}")))?;

        let ctx = ErrorContext::object(bucket_name, object_name, generation);
        self.send_json_request(Method::PUT, &url, &query, Some(&body_val), None, &ctx)
            .await
    }

    async fn get_object_media(
        &self,
        bucket_name: &str,
        object_name: &str,
        options: &DownloadOptions,
    ) -> Result<Bytes> {
        let url = format!(
            "{}/b/{}/o/{}",
            self.config.storage_base_url,
            encode_path_segment(bucket_name),
            encode_path_segment(object_name)
        );
        let mut query = vec![("alt".to_string(), "media".to_string())];
        if let Some(ref gen) = options.generation {
            query.push(("generation".to_string(), gen.clone()));
        }
        add_user_project(&mut query, self.effective_user_project());

        let mut extra = HeaderMap::new();
        if let Some(range_hdr) = format_range_header(options.start_byte, options.end_byte) {
            if let Ok(val) = HeaderValue::from_str(&range_hdr) {
                extra.insert(RANGE, val);
            }
        }
        if options.compressed_encoding {
            extra.insert(
                HeaderName::from_static("accept-encoding"),
                HeaderValue::from_static("gzip"),
            );
        }
        apply_encryption_headers(&mut extra, options.decryption_key.as_ref());

        let ctx = ErrorContext::object(bucket_name, object_name, options.generation.as_deref());

        let do_fetch = |extra_hdrs: HeaderMap| {
            let url = url.clone();
            let query = query.clone();
            let ctx = ctx.clone();
            async move {
                let req = self
                    .prepare_request_with_client(
                        &self.media_http,
                        Method::GET,
                        &url,
                        &query,
                        Some(&extra_hdrs),
                    )
                    .await?;
                let resp = req.send().await.map_err(reqwest_to_service_error)?;
                let status = resp.status().as_u16();
                if self.config.debug_level >= 2 {
                    log_wire_response(status, resp.headers());
                }
                let www_auth = resp
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .map(ToString::to_string);
                if (200..300).contains(&status) {
                    resp.bytes().await.map_err(reqwest_to_service_error)
                } else {
                    let text = resp.text().await.unwrap_or_default();
                    Err(translate_http_error(
                        status,
                        &text,
                        www_auth.as_deref(),
                        &ctx,
                    ))
                }
            }
        };

        let first_result = match options.strategy {
            DownloadStrategy::Resumable => {
                self.config
                    .retry_policy
                    .execute(|| do_fetch(extra.clone()), is_retryable_gsutil_error)
                    .await
            }
            DownloadStrategy::OneShot => do_fetch(extra.clone()).await,
        };

        match first_result {
            Ok(bytes) => Ok(bytes),
            Err(err) if is_csek_required_error(&err) => {
                let dec_key = self
                    .resolve_csek_for_object(
                        bucket_name,
                        object_name,
                        options.generation.as_deref(),
                    )
                    .await?;
                if options.decryption_key.as_ref() == Some(&dec_key) {
                    return Err(err);
                }
                let mut retry_extra = extra;
                apply_encryption_headers(&mut retry_extra, Some(&dec_key));
                match options.strategy {
                    DownloadStrategy::Resumable => {
                        self.config
                            .retry_policy
                            .execute(|| do_fetch(retry_extra.clone()), is_retryable_gsutil_error)
                            .await
                    }
                    DownloadStrategy::OneShot => do_fetch(retry_extra).await,
                }
            }
            Err(err) => Err(err),
        }
    }

    async fn get_object_media_stream(
        &self,
        bucket_name: &str,
        object_name: &str,
        options: &DownloadOptions,
    ) -> Result<ByteStream> {
        let url = format!(
            "{}/b/{}/o/{}",
            self.config.storage_base_url,
            encode_path_segment(bucket_name),
            encode_path_segment(object_name)
        );
        let mut query = vec![("alt".to_string(), "media".to_string())];
        if let Some(ref gen) = options.generation {
            query.push(("generation".to_string(), gen.clone()));
        }
        add_user_project(&mut query, self.effective_user_project());

        let mut extra = HeaderMap::new();
        if let Some(range_hdr) = format_range_header(options.start_byte, options.end_byte) {
            if let Ok(val) = HeaderValue::from_str(&range_hdr) {
                extra.insert(RANGE, val);
            }
        }
        if options.compressed_encoding {
            extra.insert(
                HeaderName::from_static("accept-encoding"),
                HeaderValue::from_static("gzip"),
            );
        }
        apply_encryption_headers(&mut extra, options.decryption_key.as_ref());

        let ctx = ErrorContext::object(bucket_name, object_name, options.generation.as_deref());

        let do_open = |extra_hdrs: HeaderMap| {
            let url = url.clone();
            let query = query.clone();
            let ctx = ctx.clone();
            async move {
                let req = self
                    .prepare_request_with_client(
                        &self.media_http,
                        Method::GET,
                        &url,
                        &query,
                        Some(&extra_hdrs),
                    )
                    .await?;
                let resp = req.send().await.map_err(reqwest_to_service_error)?;
                let status = resp.status().as_u16();
                if self.config.debug_level >= 2 {
                    log_wire_response(status, resp.headers());
                }
                if (200..300).contains(&status) {
                    Ok(resp)
                } else {
                    let www_auth = resp
                        .headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .map(ToString::to_string);
                    let text = resp.text().await.unwrap_or_default();
                    Err(translate_http_error(
                        status,
                        &text,
                        www_auth.as_deref(),
                        &ctx,
                    ))
                }
            }
        };

        let first_resp = match options.strategy {
            DownloadStrategy::Resumable => {
                self.config
                    .retry_policy
                    .execute(|| do_open(extra.clone()), is_retryable_gsutil_error)
                    .await
            }
            DownloadStrategy::OneShot => do_open(extra.clone()).await,
        };

        let resp = match first_resp {
            Ok(r) => r,
            Err(err) if is_csek_required_error(&err) => {
                let dec_key = self
                    .resolve_csek_for_object(
                        bucket_name,
                        object_name,
                        options.generation.as_deref(),
                    )
                    .await?;
                if options.decryption_key.as_ref() == Some(&dec_key) {
                    return Err(err);
                }
                let mut retry_extra = extra;
                apply_encryption_headers(&mut retry_extra, Some(&dec_key));
                match options.strategy {
                    DownloadStrategy::Resumable => {
                        self.config
                            .retry_policy
                            .execute(|| do_open(retry_extra.clone()), is_retryable_gsutil_error)
                            .await?
                    }
                    DownloadStrategy::OneShot => do_open(retry_extra).await?,
                }
            }
            Err(err) => return Err(err),
        };

        let total_hint = resp.content_length();
        let progress_cb = options.progress_callback.clone();
        let bytes_seen = Arc::new(AtomicU64::new(0));

        let stream = resp.bytes_stream().map(move |item| {
            item.inspect(|chunk| {
                let total = bytes_seen.fetch_add(chunk.len() as u64, Ordering::Relaxed)
                    + chunk.len() as u64;
                if let Some(ref cb) = progress_cb {
                    cb(total, total_hint);
                }
            })
            .map_err(std::io::Error::other)
        });

        Ok(Box::pin(stream))
    }

    async fn upload_object(
        &self,
        data: Bytes,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        let bucket_name = object_metadata.bucket.as_deref().ok_or_else(|| {
            GsutilError::argument("Object metadata must specify bucket for upload.")
        })?;
        let object_name = object_metadata.name.as_deref().ok_or_else(|| {
            GsutilError::argument("Object metadata must specify name for upload.")
        })?;

        let url = format!(
            "{}/b/{}/o",
            self.config.upload_base_url,
            encode_path_segment(bucket_name)
        );

        let mut query = vec![("uploadType".to_string(), "multipart".to_string())];
        add_preconditions(&mut query, options.preconditions.as_ref());
        if let Some(ref acl) = options.canned_acl {
            query.push((
                "predefinedAcl".to_string(),
                object_canned_acl_to_json(acl)?.to_string(),
            ));
        }
        if let Some(EncryptionKey::Cmek { kms_key_name }) = &options.encryption_key {
            query.push(("kmsKeyName".to_string(), kms_key_name.clone()));
        }
        add_user_project(&mut query, self.effective_user_project());
        add_fields_param(&mut query, options.fields.as_deref(), false);

        let boundary = "gsutil_rs_multipart_boundary_7f9a3e";
        let content_type = object_metadata
            .content_type
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_CONTENT_TYPE);
        let meta_json = serde_json::to_vec(object_metadata).map_err(|e| {
            GsutilError::command(format!("Failed to serialize object metadata: {e}"))
        })?;

        let mut multipart_body = Vec::with_capacity(meta_json.len() + data.len() + 256);
        multipart_body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        multipart_body.extend_from_slice(b"Content-Type: application/json; charset=UTF-8\r\n\r\n");
        multipart_body.extend_from_slice(&meta_json);
        multipart_body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
        multipart_body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        if options.gzip_encoded {
            multipart_body.extend_from_slice(b"Content-Encoding: gzip\r\n");
        }
        multipart_body.extend_from_slice(b"\r\n");
        multipart_body.extend_from_slice(&data);
        multipart_body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let body_bytes = Bytes::from(multipart_body);

        let mut extra = HeaderMap::new();
        extra.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(&format!("multipart/related; boundary={boundary}"))
                .unwrap_or_else(|_| HeaderValue::from_static("multipart/related")),
        );
        apply_encryption_headers(&mut extra, options.encryption_key.as_ref());

        let ctx = ErrorContext {
            provider: "gs",
            bucket_name: Some(bucket_name),
            object_name: Some(object_name),
            generation: None,
            not_found_override: Some(create_not_found_for_object_write(
                "gs",
                bucket_name,
                None,
                None,
                None,
            )),
        };

        if self.config.debug_level >= 2 {
            eprintln!("send: multipart upload (media body omitted)");
        }
        let text = self
            .config
            .retry_policy
            .execute(
                || async {
                    let req = self
                        .prepare_request(Method::POST, &url, &query, Some(&extra))
                        .await?
                        .body(body_bytes.clone());
                    let resp = req.send().await.map_err(reqwest_to_service_error)?;
                    let status = resp.status().as_u16();
                    if self.config.debug_level >= 2 {
                        log_wire_response(status, resp.headers());
                    }
                    let www_auth = resp
                        .headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .map(ToString::to_string);
                    let resp_text = resp.text().await.unwrap_or_default();
                    if (200..300).contains(&status) {
                        Ok(resp_text)
                    } else {
                        Err(translate_http_error(
                            status,
                            &resp_text,
                            www_auth.as_deref(),
                            &ctx,
                        ))
                    }
                },
                is_retryable_gsutil_error,
            )
            .await?;

        serde_json::from_str(&text).map_err(|e| {
            GsutilError::Service(ServiceError::service(
                format!("Failed to parse uploaded object metadata: {e}"),
                None,
                None,
            ))
        })
    }

    async fn upload_object_resumable(
        &self,
        data: Bytes,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        let bucket_name = object_metadata.bucket.as_deref().ok_or_else(|| {
            GsutilError::argument("Object metadata must specify bucket for resumable upload.")
        })?;
        let object_name = object_metadata.name.as_deref().ok_or_else(|| {
            GsutilError::argument("Object metadata must specify name for resumable upload.")
        })?;

        let init_url = format!(
            "{}/b/{}/o",
            self.config.upload_base_url,
            encode_path_segment(bucket_name)
        );

        let mut query = vec![("uploadType".to_string(), "resumable".to_string())];
        add_preconditions(&mut query, options.preconditions.as_ref());
        if let Some(ref acl) = options.canned_acl {
            query.push((
                "predefinedAcl".to_string(),
                object_canned_acl_to_json(acl)?.to_string(),
            ));
        }
        if let Some(EncryptionKey::Cmek { kms_key_name }) = &options.encryption_key {
            query.push(("kmsKeyName".to_string(), kms_key_name.clone()));
        }
        add_user_project(&mut query, self.effective_user_project());
        add_fields_param(&mut query, options.fields.as_deref(), false);

        let content_type = object_metadata
            .content_type
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_CONTENT_TYPE);
        let mut init_headers = HeaderMap::new();
        if let Ok(ct_val) = HeaderValue::from_str(content_type) {
            init_headers.insert(HeaderName::from_static("x-upload-content-type"), ct_val);
        }
        if let Ok(len_val) = HeaderValue::from_str(&data.len().to_string()) {
            init_headers.insert(HeaderName::from_static("x-upload-content-length"), len_val);
        }
        apply_encryption_headers(&mut init_headers, options.encryption_key.as_ref());

        let meta_val = serde_json::to_value(object_metadata).map_err(|e| {
            GsutilError::command(format!("Failed to serialize object metadata: {e}"))
        })?;

        let init_ctx = ErrorContext {
            provider: "gs",
            bucket_name: Some(bucket_name),
            object_name: Some(object_name),
            generation: None,
            not_found_override: Some(create_not_found_for_object_write(
                "gs",
                bucket_name,
                None,
                None,
                None,
            )),
        };

        // Step 1: Initiate resumable upload session and get `Location` URI.
        let session_uri = self
            .config
            .retry_policy
            .execute(
                || async {
                    let req = self
                        .prepare_request(Method::POST, &init_url, &query, Some(&init_headers))
                        .await?
                        .json(&meta_val);
                    let resp = req.send().await.map_err(reqwest_to_service_error)?;
                    let status = resp.status().as_u16();
                    let www_auth = resp
                        .headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .map(ToString::to_string);
                    let location = resp
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .map(ToString::to_string);
                    let text = resp.text().await.unwrap_or_default();
                    if (200..300).contains(&status) {
                        location.ok_or_else(|| {
                            GsutilError::Service(ServiceError::resumable_upload_abort(
                                "Resumable upload initiation response missing Location header.",
                                Some(status),
                                None,
                            ))
                        })
                    } else {
                        Err(translate_http_error(
                            status,
                            &text,
                            www_auth.as_deref(),
                            &init_ctx,
                        ))
                    }
                },
                is_retryable_gsutil_error,
            )
            .await?;

        let session_uri = match &self.ecp_proxy {
            Some(proxy) => proxy.rewrite_gcs_url(&session_uri),
            None => session_uri,
        };

        // Step 2: Upload in 256KiB-aligned chunks (or single PUT for empty object).
        let total_len = data.len();
        let chunk_size = self
            .config
            .resumable_chunk_size
            .max(RESUMABLE_CHUNK_QUANTUM as usize);

        let mut chunk_headers_base = HeaderMap::new();
        if let Ok(ct_val) = HeaderValue::from_str(content_type) {
            chunk_headers_base.insert(CONTENT_TYPE, ct_val);
        }
        if options.gzip_encoded {
            chunk_headers_base.insert(
                HeaderName::from_static("content-encoding"),
                HeaderValue::from_static("gzip"),
            );
        }
        apply_encryption_headers(&mut chunk_headers_base, options.encryption_key.as_ref());

        if total_len == 0 {
            let mut hdrs = chunk_headers_base.clone();
            hdrs.insert(
                HeaderName::from_static("content-range"),
                HeaderValue::from_static("bytes */0"),
            );
            let resp_text = self
                .upload_resumable_chunk(&session_uri, Bytes::new(), &hdrs)
                .await?;
            return serde_json::from_str(&resp_text).map_err(|e| {
                GsutilError::Service(ServiceError::service(
                    format!("Failed to parse resumable upload response: {e}"),
                    None,
                    None,
                ))
            });
        }

        let mut offset = 0usize;
        while offset < total_len {
            let end = (offset + chunk_size).min(total_len);
            let chunk = data.slice(offset..end);
            let content_range = format!("bytes {}-{}/{}", offset, end - 1, total_len);

            let mut hdrs = chunk_headers_base.clone();
            if let Ok(val) = HeaderValue::from_str(&content_range) {
                hdrs.insert(HeaderName::from_static("content-range"), val);
            }

            let outcome = self
                .config
                .retry_policy
                .execute(
                    || async {
                        let req = self
                            .prepare_request(Method::PUT, &session_uri, &[], Some(&hdrs))
                            .await?
                            .body(chunk.clone());
                        let resp = req.send().await.map_err(reqwest_to_service_error)?;
                        let status = resp.status().as_u16();
                        let range_hdr = resp
                            .headers()
                            .get("range")
                            .and_then(|v| v.to_str().ok())
                            .map(ToString::to_string);
                        let body_text = resp.text().await.unwrap_or_default();

                        if status == 308 {
                            // Resume Incomplete — advance offset from Range header if present.
                            let next_off = range_hdr
                                .as_deref()
                                .and_then(parse_resume_range_next_offset)
                                .unwrap_or(end);
                            Ok(ResumableChunkOutcome::Continue(next_off))
                        } else if (200..300).contains(&status) {
                            Ok(ResumableChunkOutcome::Complete(body_text))
                        } else {
                            Err(translate_resumable_upload_error(status, &body_text))
                        }
                    },
                    is_retryable_gsutil_error,
                )
                .await?;

            match outcome {
                ResumableChunkOutcome::Complete(resp_text) => {
                    return serde_json::from_str(&resp_text).map_err(|e| {
                        GsutilError::Service(ServiceError::service(
                            format!("Failed to parse completed resumable upload object: {e}"),
                            None,
                            None,
                        ))
                    });
                }
                ResumableChunkOutcome::Continue(next_offset) => {
                    debug!(
                        "Resumable upload progress: {next_offset}/{total_len} bytes for gs://{bucket_name}/{object_name}"
                    );
                    offset = next_offset;
                }
            }
        }

        Err(GsutilError::Service(ServiceError::resumable_upload_abort(
            "Resumable upload ended without completion response from server.",
            None,
            None,
        )))
    }

    async fn upload_object_resumable_file(
        &self,
        file_path: &Path,
        start_offset: u64,
        length: u64,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        let bucket_name = object_metadata.bucket.as_deref().ok_or_else(|| {
            GsutilError::argument("Object metadata must specify bucket for resumable upload.")
        })?;
        let object_name = object_metadata.name.as_deref().ok_or_else(|| {
            GsutilError::argument("Object metadata must specify name for resumable upload.")
        })?;

        let content_type = object_metadata
            .content_type
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_CONTENT_TYPE);

        let mut chunk_headers_base = HeaderMap::new();
        if let Ok(ct_val) = HeaderValue::from_str(content_type) {
            chunk_headers_base.insert(CONTENT_TYPE, ct_val);
        }
        if options.gzip_encoded {
            chunk_headers_base.insert(
                HeaderName::from_static("content-encoding"),
                HeaderValue::from_static("gzip"),
            );
        }
        apply_encryption_headers(&mut chunk_headers_base, options.encryption_key.as_ref());

        // Step 1: Attempt to resume an existing session if provided, otherwise initiate a new one.
        let mut resumed: Option<(String, u64)> = None;
        if let Some(ref existing_uri) = options.resumable_session_uri {
            let effective_uri = self.rewrite_for_ecp(existing_uri);
            match self
                .query_resumable_upload_status(&effective_uri, Some(length), &chunk_headers_base)
                .await?
            {
                ResumableQueryStatus::Complete(obj) => {
                    if let Some(ref cb) = options.progress_callback {
                        cb(length, Some(length));
                    }
                    return Ok(*obj);
                }
                ResumableQueryStatus::Incomplete(committed_offset) => {
                    debug!(
                        "Resuming GCS upload session for gs://{bucket_name}/{object_name} at byte {committed_offset}/{length}"
                    );
                    resumed = Some((effective_uri, committed_offset));
                }
                ResumableQueryStatus::Expired => {
                    debug!(
                        "Existing upload session expired for gs://{bucket_name}/{object_name}; starting new session"
                    );
                }
            }
        }

        let (session_uri, mut offset) = match resumed {
            Some((uri, off)) => (uri, off),
            None => {
                let raw_uri = self
                    .initiate_resumable_upload(
                        bucket_name,
                        object_name,
                        object_metadata,
                        options,
                        Some(length),
                    )
                    .await?;
                if let Some(ref cb) = options.session_uri_callback {
                    cb(&raw_uri);
                }
                (self.rewrite_for_ecp(&raw_uri), 0u64)
            }
        };

        // Handle 0-byte upload cleanly.
        if length == 0 {
            let mut hdrs = chunk_headers_base.clone();
            hdrs.insert(
                HeaderName::from_static("content-range"),
                HeaderValue::from_static("bytes */0"),
            );
            let resp_text = self
                .upload_resumable_chunk(&session_uri, Bytes::new(), &hdrs)
                .await?;
            if let Some(ref cb) = options.progress_callback {
                cb(0, Some(0));
            }
            return serde_json::from_str(&resp_text).map_err(|e| {
                GsutilError::Service(ServiceError::service(
                    format!("Failed to parse resumable upload response: {e}"),
                    None,
                    None,
                ))
            });
        }

        // Bounded chunk size (default 8 MiB, aligned to 256 KiB) for constant memory.
        let chunk_size =
            effective_streaming_chunk_size(options.chunk_size, self.config.resumable_chunk_size);

        let mut file = tokio::fs::File::open(file_path).await?;
        let mut retries_without_progress: u32 = 0;

        while offset < length {
            file.seek(SeekFrom::Start(start_offset + offset)).await?;
            let to_read = (chunk_size as u64).min(length - offset) as usize;
            let mut buf = vec![0u8; to_read];
            read_exact_async(&mut file, &mut buf).await?;
            let chunk = Bytes::from(buf);

            let end_inclusive = offset + to_read as u64 - 1;
            let content_range = format!("bytes {offset}-{end_inclusive}/{length}");
            let mut hdrs = chunk_headers_base.clone();
            if let Ok(val) = HeaderValue::from_str(&content_range) {
                hdrs.insert(HeaderName::from_static("content-range"), val);
            }

            let send_res = self.send_resumable_put(&session_uri, chunk, &hdrs).await;

            match send_res {
                Ok(ResumablePutOutcome::Complete(obj)) => {
                    if let Some(ref cb) = options.progress_callback {
                        cb(length, Some(length));
                    }
                    return Ok(*obj);
                }
                Ok(ResumablePutOutcome::Continue(next_off)) => {
                    let advanced = next_off.unwrap_or(offset + to_read as u64);
                    if advanced > offset {
                        retries_without_progress = 0;
                    }
                    offset = advanced;
                    if let Some(ref cb) = options.progress_callback {
                        cb(offset, Some(length));
                    }
                }
                Err(ResumablePutError::Retryable {
                    err,
                    retry_after_secs,
                }) => {
                    retries_without_progress += 1;
                    if retries_without_progress > self.config.retry_policy.max_retries {
                        return Err(err);
                    }
                    let delay = match retry_after_secs {
                        Some(secs) => Duration::from_secs(secs.min(60)),
                        None => self
                            .config
                            .retry_policy
                            .delay_for_attempt(retries_without_progress),
                    };
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    // Re-query GCS to discover exact committed offset.
                    match self
                        .query_resumable_upload_status(
                            &session_uri,
                            Some(length),
                            &chunk_headers_base,
                        )
                        .await
                    {
                        Ok(ResumableQueryStatus::Complete(obj)) => {
                            if let Some(ref cb) = options.progress_callback {
                                cb(length, Some(length));
                            }
                            return Ok(*obj);
                        }
                        Ok(ResumableQueryStatus::Incomplete(server_off)) => {
                            if server_off > offset {
                                retries_without_progress = 0;
                            }
                            offset = server_off;
                        }
                        Ok(ResumableQueryStatus::Expired) => {
                            return Err(GsutilError::Service(
                                ServiceError::resumable_upload_start_over(
                                    "Resumable upload session expired during retry.",
                                    Some(410),
                                    None,
                                ),
                            ));
                        }
                        Err(_) => {
                            // Keep current offset and retry on next iteration.
                        }
                    }
                }
                Err(ResumablePutError::Fatal(err)) => return Err(err),
            }
        }

        Err(GsutilError::Service(ServiceError::resumable_upload_abort(
            "Resumable file upload ended without completion response from server.",
            None,
            None,
        )))
    }

    async fn upload_object_streaming(
        &self,
        mut reader: Box<dyn AsyncRead + Send + Unpin>,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        let bucket_name = object_metadata.bucket.as_deref().ok_or_else(|| {
            GsutilError::argument("Object metadata must specify bucket for streaming upload.")
        })?;
        let object_name = object_metadata.name.as_deref().ok_or_else(|| {
            GsutilError::argument("Object metadata must specify name for streaming upload.")
        })?;

        let content_type = object_metadata
            .content_type
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_CONTENT_TYPE);

        let raw_uri = self
            .initiate_resumable_upload(
                bucket_name,
                object_name,
                object_metadata,
                options,
                options.total_size,
            )
            .await?;
        if let Some(ref cb) = options.session_uri_callback {
            cb(&raw_uri);
        }
        let session_uri = self.rewrite_for_ecp(&raw_uri);

        let mut chunk_headers_base = HeaderMap::new();
        if let Ok(ct_val) = HeaderValue::from_str(content_type) {
            chunk_headers_base.insert(CONTENT_TYPE, ct_val);
        }
        if options.gzip_encoded {
            chunk_headers_base.insert(
                HeaderName::from_static("content-encoding"),
                HeaderValue::from_static("gzip"),
            );
        }
        apply_encryption_headers(&mut chunk_headers_base, options.encryption_key.as_ref());

        let chunk_size =
            effective_streaming_chunk_size(options.chunk_size, self.config.resumable_chunk_size);

        let mut offset: u64 = 0;
        let mut pending_byte: Option<u8> = None;

        loop {
            // Fill up to `chunk_size` bytes from the reader.
            let mut buf = Vec::with_capacity(chunk_size.min(1024 * 1024));
            if let Some(b) = pending_byte.take() {
                buf.push(b);
            }
            while buf.len() < chunk_size {
                let remaining = chunk_size - buf.len();
                let mut tmp = vec![0u8; remaining.min(64 * 1024)];
                let n = reader.read(&mut tmp).await?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }

            // Probe 1 byte ahead to detect EOF accurately when buf.len() == chunk_size.
            let is_eof = if buf.len() < chunk_size {
                true
            } else {
                let mut probe = [0u8; 1];
                let n = reader.read(&mut probe).await?;
                if n == 0 {
                    true
                } else {
                    pending_byte = Some(probe[0]);
                    false
                }
            };

            if buf.is_empty() && offset == 0 {
                let mut hdrs = chunk_headers_base.clone();
                hdrs.insert(
                    HeaderName::from_static("content-range"),
                    HeaderValue::from_static("bytes */0"),
                );
                let resp_text = self
                    .upload_resumable_chunk(&session_uri, Bytes::new(), &hdrs)
                    .await?;
                if let Some(ref cb) = options.progress_callback {
                    cb(0, Some(0));
                }
                return serde_json::from_str(&resp_text).map_err(|e| {
                    GsutilError::Service(ServiceError::service(
                        format!("Failed to parse streaming upload response: {e}"),
                        None,
                        None,
                    ))
                });
            }

            let chunk_len = buf.len() as u64;
            let end_inclusive = offset + chunk_len - 1;
            let content_range = if is_eof {
                format!("bytes {offset}-{end_inclusive}/{}", offset + chunk_len)
            } else {
                match options.total_size {
                    Some(total) => format!("bytes {offset}-{end_inclusive}/{total}"),
                    None => format!("bytes {offset}-{end_inclusive}/*"),
                }
            };

            let mut hdrs = chunk_headers_base.clone();
            if let Ok(val) = HeaderValue::from_str(&content_range) {
                hdrs.insert(HeaderName::from_static("content-range"), val);
            }
            let chunk = Bytes::from(buf);

            let mut attempt = 0u32;
            loop {
                match self
                    .send_resumable_put(&session_uri, chunk.clone(), &hdrs)
                    .await
                {
                    Ok(ResumablePutOutcome::Complete(obj)) => {
                        if let Some(ref cb) = options.progress_callback {
                            cb(offset + chunk_len, Some(offset + chunk_len));
                        }
                        return Ok(*obj);
                    }
                    Ok(ResumablePutOutcome::Continue(_)) => {
                        offset += chunk_len;
                        if let Some(ref cb) = options.progress_callback {
                            cb(offset, options.total_size);
                        }
                        break;
                    }
                    Err(ResumablePutError::Retryable {
                        err,
                        retry_after_secs,
                    }) => {
                        attempt += 1;
                        if attempt > self.config.retry_policy.max_retries {
                            return Err(err);
                        }
                        let delay = match retry_after_secs {
                            Some(secs) => Duration::from_secs(secs.min(60)),
                            None => self.config.retry_policy.delay_for_attempt(attempt),
                        };
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                    }
                    Err(ResumablePutError::Fatal(err)) => return Err(err),
                }
            }

            if is_eof {
                return Err(GsutilError::Service(ServiceError::resumable_upload_abort(
                    "Streaming upload reached EOF without completion response from server.",
                    None,
                    None,
                )));
            }
        }
    }

    async fn copy_object(
        &self,
        src_obj_metadata: &Object,
        dst_obj_metadata: &Object,
        options: &CopyOptions,
    ) -> Result<Object> {
        let src_bucket = src_obj_metadata
            .bucket
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Source object metadata missing bucket."))?;
        let src_object = src_obj_metadata
            .name
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Source object metadata missing name."))?;
        let dst_bucket = dst_obj_metadata
            .bucket
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Destination object metadata missing bucket."))?;
        let dst_object = dst_obj_metadata
            .name
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Destination object metadata missing name."))?;

        let url = format!(
            "{}/b/{}/o/{}/rewriteTo/b/{}/o/{}",
            self.config.storage_base_url,
            encode_path_segment(src_bucket),
            encode_path_segment(src_object),
            encode_path_segment(dst_bucket),
            encode_path_segment(dst_object)
        );

        let mut dst_meta = dst_obj_metadata.clone();
        if let Some(EncryptionKey::Cmek { kms_key_name }) = &options.encryption_key {
            dst_meta.kms_key_name = Some(kms_key_name.clone());
        }

        // Resolve the best source decryption key: if `src_obj_metadata.customer_encryption`
        // specifies a SHA256 hash, prefer the matching key from `.boto` `csek_keys` (or the
        // caller's `options.decryption_key` if it matches) so key rotation (`encryption_key`
        // != `decryption_key1`) automatically uses the right source key.
        let mut effective_decryption_key = options.decryption_key.clone();
        if let Some(sha) = src_obj_metadata
            .customer_encryption
            .as_ref()
            .and_then(|ce| ce.key_sha256.as_deref())
        {
            let caller_matches = matches!(
                effective_decryption_key.as_ref(),
                Some(EncryptionKey::Csek { key_sha256_b64, .. }) if key_sha256_b64 == sha
            );
            if !caller_matches {
                if let Some(matched) = self.find_matching_csek(sha) {
                    effective_decryption_key = Some(matched);
                } else {
                    return Err(GsutilError::Encryption(format!(
                        "Missing decryption key with SHA256 hash {sha}. \
                         No decryption key matches object gs://{src_bucket}/{src_object}"
                    )));
                }
            }
        }

        let mut extra = HeaderMap::new();
        apply_rewrite_crypto_headers(
            &mut extra,
            effective_decryption_key.as_ref(),
            options.encryption_key.as_ref(),
        );

        let body_val = serde_json::to_value(&dst_meta).map_err(|e| {
            GsutilError::command(format!(
                "Failed to serialize rewrite destination metadata: {e}"
            ))
        })?;

        let ctx = ErrorContext {
            provider: "gs",
            bucket_name: Some(dst_bucket),
            object_name: Some(dst_object),
            generation: None,
            not_found_override: Some(create_not_found_for_object_write(
                "gs",
                dst_bucket,
                Some(src_bucket),
                Some(src_object),
                options.src_generation.as_deref(),
            )),
        };

        let mut rewrite_token: Option<String> = None;
        let mut retried_csek = false;
        loop {
            let mut query = vec![(
                "projection".to_string(),
                projection_for_fields(options.fields.as_deref()).to_string(),
            )];
            if let Some(ref gen) = options.src_generation {
                query.push(("sourceGeneration".to_string(), gen.clone()));
            }
            add_preconditions(&mut query, options.preconditions.as_ref());
            if let Some(ref acl) = options.canned_acl {
                query.push((
                    "destinationPredefinedAcl".to_string(),
                    object_canned_acl_to_json(acl)?.to_string(),
                ));
            }
            if let Some(ref kms) = dst_meta.kms_key_name {
                query.push(("destinationKmsKeyName".to_string(), kms.clone()));
            }
            if let Some(max_bytes) = options.max_bytes_per_call {
                query.push((
                    "maxBytesRewrittenPerCall".to_string(),
                    max_bytes.to_string(),
                ));
            }
            if let Some(ref tok) = rewrite_token {
                query.push(("rewriteToken".to_string(), tok.clone()));
            }
            add_user_project(&mut query, self.effective_user_project());
            if let Some(ref fields) = options.fields {
                let mut rewrite_fields: HashSet<String> =
                    ["done", "objectSize", "rewriteToken", "totalBytesRewritten"]
                        .into_iter()
                        .map(ToString::to_string)
                        .collect();
                for f in fields {
                    rewrite_fields.insert(format!("resource/{f}"));
                }
                let mut sorted: Vec<String> = rewrite_fields.into_iter().collect();
                sorted.sort();
                query.push(("fields".to_string(), sorted.join(",")));
            }

            let resp: RewriteResponse = match self
                .send_json_request(
                    Method::POST,
                    &url,
                    &query,
                    Some(&body_val),
                    Some(&extra),
                    &ctx,
                )
                .await
            {
                Ok(r) => r,
                Err(err) if !retried_csek && is_csek_required_error(&err) => {
                    retried_csek = true;
                    let dec_key = self
                        .resolve_csek_for_object(
                            src_bucket,
                            src_object,
                            options.src_generation.as_deref(),
                        )
                        .await?;
                    if effective_decryption_key.as_ref() == Some(&dec_key) {
                        return Err(err);
                    }
                    effective_decryption_key = Some(dec_key);
                    extra = HeaderMap::new();
                    apply_rewrite_crypto_headers(
                        &mut extra,
                        effective_decryption_key.as_ref(),
                        options.encryption_key.as_ref(),
                    );
                    rewrite_token = None;
                    continue;
                }
                Err(err) => return Err(err),
            };

            if resp.done {
                return resp.resource.ok_or_else(|| {
                    GsutilError::Service(ServiceError::service(
                        "Rewrite completed without resource metadata.",
                        None,
                        None,
                    ))
                });
            }
            rewrite_token = resp.rewrite_token;
        }
    }

    async fn compose_object(
        &self,
        src_objs: &[ComposeSourceObject],
        dst_obj_metadata: &Object,
        preconditions: Option<&Preconditions>,
        encryption_key: Option<&EncryptionKey>,
        fields: Option<&[String]>,
    ) -> Result<Object> {
        let dst_bucket = dst_obj_metadata
            .bucket
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Compose destination missing bucket."))?;
        let dst_object = dst_obj_metadata
            .name
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Compose destination missing name."))?;

        let url = format!(
            "{}/b/{}/o/{}/compose",
            self.config.storage_base_url,
            encode_path_segment(dst_bucket),
            encode_path_segment(dst_object)
        );

        let mut dst_clean = dst_obj_metadata.clone();
        dst_clean.bucket = None;
        dst_clean.name = None;
        if dst_clean.content_type.as_deref().unwrap_or("").is_empty() {
            dst_clean.content_type = Some(DEFAULT_CONTENT_TYPE.to_string());
        }

        let mut query = Vec::new();
        add_preconditions(&mut query, preconditions);
        if let Some(EncryptionKey::Cmek { kms_key_name }) = encryption_key {
            query.push(("kmsKeyName".to_string(), kms_key_name.clone()));
        }
        add_user_project(&mut query, self.effective_user_project());
        add_fields_param(&mut query, fields, false);

        let mut extra = HeaderMap::new();
        apply_encryption_headers(&mut extra, encryption_key);

        let compose_req = ComposeRequestBody {
            source_objects: src_objs,
            destination: &dst_clean,
        };
        let body_val = serde_json::to_value(&compose_req).map_err(|e| {
            GsutilError::command(format!("Failed to serialize compose request: {e}"))
        })?;

        let ctx = ErrorContext {
            provider: "gs",
            bucket_name: Some(dst_bucket),
            object_name: Some(dst_object),
            generation: None,
            not_found_override: Some(ServiceError::not_found(
                "One of the source objects does not exist.",
                None,
                None,
            )),
        };

        self.send_json_request(
            Method::POST,
            &url,
            &query,
            Some(&body_val),
            Some(&extra),
            &ctx,
        )
        .await
    }

    async fn delete_object(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
        preconditions: Option<&Preconditions>,
    ) -> Result<()> {
        let url = format!(
            "{}/b/{}/o/{}",
            self.config.storage_base_url,
            encode_path_segment(bucket_name),
            encode_path_segment(object_name)
        );
        let mut query = Vec::new();
        if let Some(gen) = generation {
            query.push(("generation".to_string(), gen.to_string()));
        }
        add_preconditions(&mut query, preconditions);
        add_user_project(&mut query, self.effective_user_project());

        let ctx = ErrorContext::object(bucket_name, object_name, generation);
        self.send_empty_request(Method::DELETE, &url, &query, None, None, &ctx)
            .await
    }

    // -----------------------------------------------------------------------
    // Notifications & Channels
    // -----------------------------------------------------------------------

    async fn watch_bucket(
        &self,
        bucket_name: &str,
        address: &str,
        channel_id: &str,
        token: Option<&str>,
    ) -> Result<Channel> {
        let url = format!(
            "{}/b/{}/o/watch",
            self.config.storage_base_url,
            encode_path_segment(bucket_name)
        );
        let mut query = vec![("projection".to_string(), "full".to_string())];
        add_user_project(&mut query, self.effective_user_project());

        let channel = Channel {
            id: Some(channel_id.to_string()),
            address: Some(address.to_string()),
            token: token.map(ToString::to_string),
            channel_type: Some("WEB_HOOK".to_string()),
            ..Default::default()
        };
        let body_val = serde_json::to_value(&channel)
            .map_err(|e| GsutilError::command(format!("Failed to serialize channel: {e}")))?;

        let ctx = ErrorContext::bucket(bucket_name);
        self.send_json_request(Method::POST, &url, &query, Some(&body_val), None, &ctx)
            .await
    }

    async fn stop_channel(&self, channel_id: &str, resource_id: &str) -> Result<()> {
        let url = format!("{}/channels/stop", self.config.storage_base_url);
        let channel = Channel {
            id: Some(channel_id.to_string()),
            resource_id: Some(resource_id.to_string()),
            ..Default::default()
        };
        let body_val = serde_json::to_value(&channel)
            .map_err(|e| GsutilError::command(format!("Failed to serialize channel: {e}")))?;

        let ctx = ErrorContext::gs();
        self.send_empty_request(Method::POST, &url, &[], Some(&body_val), None, &ctx)
            .await
    }

    async fn get_project_service_account(&self, project_id: &str) -> Result<ServiceAccount> {
        let url = format!(
            "{}/projects/{}/serviceAccount",
            self.config.storage_base_url,
            encode_path_segment(project_id)
        );
        let ctx = ErrorContext::gs();
        self.send_json_request(Method::GET, &url, &[], None, None, &ctx)
            .await
    }

    async fn create_notification_config(
        &self,
        bucket_name: &str,
        options: &CreateNotificationOptions,
    ) -> Result<Notification> {
        let url = format!(
            "{}/b/{}/notificationConfigs",
            self.config.storage_base_url,
            encode_path_segment(bucket_name)
        );
        let mut query = Vec::new();
        add_user_project(&mut query, self.effective_user_project());

        let notification = Notification {
            topic: Some(options.pubsub_topic.clone()),
            payload_format: Some(options.payload_format.clone()),
            event_types: options.event_types.clone(),
            custom_attributes: options.custom_attributes.clone(),
            object_name_prefix: options.object_name_prefix.clone(),
            ..Default::default()
        };
        let body_val = serde_json::to_value(&notification)
            .map_err(|e| GsutilError::command(format!("Failed to serialize notification: {e}")))?;

        let ctx = ErrorContext::bucket(bucket_name);
        self.send_json_request(Method::POST, &url, &query, Some(&body_val), None, &ctx)
            .await
    }

    async fn delete_notification_config(
        &self,
        bucket_name: &str,
        notification_id: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/b/{}/notificationConfigs/{}",
            self.config.storage_base_url,
            encode_path_segment(bucket_name),
            encode_path_segment(notification_id)
        );
        let mut query = Vec::new();
        add_user_project(&mut query, self.effective_user_project());

        let ctx = ErrorContext::bucket(bucket_name);
        self.send_empty_request(Method::DELETE, &url, &query, None, None, &ctx)
            .await
    }

    async fn list_notification_configs(&self, bucket_name: &str) -> Result<Vec<Notification>> {
        let url = format!(
            "{}/b/{}/notificationConfigs",
            self.config.storage_base_url,
            encode_path_segment(bucket_name)
        );
        let mut query = Vec::new();
        add_user_project(&mut query, self.effective_user_project());

        let ctx = ErrorContext::bucket(bucket_name);
        let resp: NotificationsListResponse = self
            .send_json_request(Method::GET, &url, &query, None, None, &ctx)
            .await?;
        Ok(resp.items)
    }

    // -----------------------------------------------------------------------
    // HMAC Keys
    // -----------------------------------------------------------------------

    async fn create_hmac_key(
        &self,
        project_id: &str,
        service_account_email: &str,
    ) -> Result<HmacKeyCreateResponse> {
        let url = format!(
            "{}/projects/{}/hmacKeys",
            self.config.storage_base_url,
            encode_path_segment(project_id)
        );
        let query = vec![(
            "serviceAccountEmail".to_string(),
            service_account_email.to_string(),
        )];
        let ctx = ErrorContext::gs();
        self.send_json_request(Method::POST, &url, &query, None, None, &ctx)
            .await
    }

    async fn delete_hmac_key(&self, project_id: &str, access_id: &str) -> Result<()> {
        let url = format!(
            "{}/projects/{}/hmacKeys/{}",
            self.config.storage_base_url,
            encode_path_segment(project_id),
            encode_path_segment(access_id)
        );
        let ctx = ErrorContext::gs();
        self.send_empty_request(Method::DELETE, &url, &[], None, None, &ctx)
            .await
    }

    async fn get_hmac_key(&self, project_id: &str, access_id: &str) -> Result<HmacKeyMetadata> {
        let url = format!(
            "{}/projects/{}/hmacKeys/{}",
            self.config.storage_base_url,
            encode_path_segment(project_id),
            encode_path_segment(access_id)
        );
        let ctx = ErrorContext::gs();
        self.send_json_request(Method::GET, &url, &[], None, None, &ctx)
            .await
    }

    async fn list_hmac_keys(
        &self,
        project_id: &str,
        service_account_email: Option<&str>,
        show_deleted_keys: bool,
    ) -> Result<Vec<HmacKeyMetadata>> {
        let url = format!(
            "{}/projects/{}/hmacKeys",
            self.config.storage_base_url,
            encode_path_segment(project_id)
        );

        let mut items = Vec::new();
        let mut next_page_token: Option<String> = None;

        loop {
            let mut query = vec![
                ("showDeletedKeys".to_string(), show_deleted_keys.to_string()),
                (
                    "maxResults".to_string(),
                    NUM_BUCKETS_PER_LIST_PAGE.to_string(),
                ),
            ];
            if let Some(sa) = service_account_email {
                query.push(("serviceAccountEmail".to_string(), sa.to_string()));
            }
            if let Some(ref tok) = next_page_token {
                query.push(("pageToken".to_string(), tok.clone()));
            }

            let ctx = ErrorContext::gs();
            let page: HmacKeysListResponse = self
                .send_json_request(Method::GET, &url, &query, None, None, &ctx)
                .await?;
            items.extend(page.items);

            match page.next_page_token {
                Some(tok) if !tok.is_empty() => next_page_token = Some(tok),
                _ => break,
            }
        }

        Ok(items)
    }

    async fn update_hmac_key(
        &self,
        project_id: &str,
        access_id: &str,
        state: &str,
        etag: Option<&str>,
    ) -> Result<HmacKeyMetadata> {
        let url = format!(
            "{}/projects/{}/hmacKeys/{}",
            self.config.storage_base_url,
            encode_path_segment(project_id),
            encode_path_segment(access_id)
        );
        let metadata = HmacKeyMetadata {
            state: Some(state.to_string()),
            etag: etag.map(ToString::to_string),
            ..Default::default()
        };
        let body_val = serde_json::to_value(&metadata)
            .map_err(|e| GsutilError::command(format!("Failed to serialize HMAC update: {e}")))?;
        let ctx = ErrorContext::gs();
        self.send_json_request(Method::PUT, &url, &[], Some(&body_val), None, &ctx)
            .await
    }

    // -----------------------------------------------------------------------
    // Signed URLs (V4)
    // -----------------------------------------------------------------------

    async fn sign_url(&self, options: &SignUrlOptions) -> Result<String> {
        let sa_email = self.get_service_account_id().await?;
        let now = Utc::now();
        let request_timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let datestamp = now.format("%Y%m%d").to_string();
        let region = options.region.as_deref().unwrap_or("auto");
        let credential_scope = format!("{datestamp}/{region}/storage/goog4_request");
        let credential = format!("{sa_email}/{credential_scope}");

        let mut canonical_headers_map: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &options.signed_headers {
            canonical_headers_map.insert(k.to_ascii_lowercase(), v.trim().to_string());
        }
        let host = canonical_headers_map
            .entry("host".to_string())
            .or_insert_with(|| DEFAULT_GCS_HOST.to_string())
            .clone();

        let signed_headers_str = canonical_headers_map
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(";");
        let canonical_headers_str = canonical_headers_map
            .iter()
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect::<String>();

        let mut query_params: BTreeMap<String, String> = BTreeMap::new();
        query_params.insert(
            "X-Goog-Algorithm".to_string(),
            "GOOG4-RSA-SHA256".to_string(),
        );
        query_params.insert("X-Goog-Credential".to_string(), credential);
        query_params.insert("X-Goog-Date".to_string(), request_timestamp.clone());
        query_params.insert(
            "X-Goog-Expires".to_string(),
            options.duration_secs.to_string(),
        );
        query_params.insert(
            "X-Goog-SignedHeaders".to_string(),
            signed_headers_str.clone(),
        );
        if let Some(ref gen) = options.generation {
            query_params.insert("generation".to_string(), gen.clone());
        }

        let canonical_query_string = query_params
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let canonical_uri = if options.path.starts_with('/') {
            options.path.clone()
        } else {
            format!("/{}", options.path)
        };

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
            options.method.to_ascii_uppercase(),
            canonical_uri,
            canonical_query_string,
            canonical_headers_str,
            signed_headers_str
        );
        let hashed_canonical_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign = format!(
            "GOOG4-RSA-SHA256\n{request_timestamp}\n{credential_scope}\n{hashed_canonical_request}"
        );

        let (_key_id, raw_sig) = self
            .credentials
            .sign_blob(string_to_sign.as_bytes())
            .await?;
        let signature_hex = hex::encode(raw_sig);

        Ok(format!(
            "https://{host}{canonical_uri}?{canonical_query_string}&X-Goog-Signature={signature_hex}"
        ))
    }
}

impl GcsJsonClient {
    fn find_matching_csek(&self, key_sha256: &str) -> Option<EncryptionKey> {
        self.config
            .csek_keys
            .iter()
            .find(|(_, sha)| sha == key_sha256)
            .map(|(key_b64, sha)| EncryptionKey::Csek {
                key_b64: key_b64.clone(),
                key_sha256_b64: sha.clone(),
            })
    }

    async fn resolve_csek_for_object(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
    ) -> Result<EncryptionKey> {
        let fields = vec!["customerEncryption".to_string()];
        let meta = self
            .get_object_metadata_with_key(bucket_name, object_name, generation, Some(&fields), None)
            .await?;
        let key_sha256 = meta
            .customer_encryption
            .and_then(|ce| ce.key_sha256)
            .ok_or_else(|| {
                GsutilError::Encryption(format!(
                    "Object gs://{bucket_name}/{object_name} requires a decryption key."
                ))
            })?;
        self.find_matching_csek(&key_sha256).ok_or_else(|| {
            GsutilError::Encryption(format!(
                "Missing decryption key with SHA256 hash {key_sha256}. \
                 No decryption key matches object gs://{bucket_name}/{object_name}"
            ))
        })
    }

    async fn get_object_metadata_with_key(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
        fields: Option<&[String]>,
        decryption_key: Option<&EncryptionKey>,
    ) -> Result<Object> {
        let url = format!(
            "{}/b/{}/o/{}",
            self.config.storage_base_url,
            encode_path_segment(bucket_name),
            encode_path_segment(object_name)
        );
        let mut query = vec![(
            "projection".to_string(),
            projection_for_fields(fields).to_string(),
        )];
        if let Some(gen) = generation {
            query.push(("generation".to_string(), gen.to_string()));
        }
        add_user_project(&mut query, self.effective_user_project());
        add_fields_param(&mut query, fields, false);

        let mut extra = HeaderMap::new();
        apply_encryption_headers(&mut extra, decryption_key);
        let extra_opt = if extra.is_empty() { None } else { Some(&extra) };

        let ctx = ErrorContext::object(bucket_name, object_name, generation);
        self.send_json_request(Method::GET, &url, &query, None, extra_opt, &ctx)
            .await
    }

    fn rewrite_for_ecp(&self, uri: &str) -> String {
        match &self.ecp_proxy {
            Some(proxy) => proxy.rewrite_gcs_url(uri),
            None => uri.to_string(),
        }
    }

    async fn initiate_resumable_upload(
        &self,
        bucket_name: &str,
        object_name: &str,
        object_metadata: &Object,
        options: &UploadOptions,
        content_length: Option<u64>,
    ) -> Result<String> {
        let init_url = format!(
            "{}/b/{}/o",
            self.config.upload_base_url,
            encode_path_segment(bucket_name)
        );

        let mut query = vec![("uploadType".to_string(), "resumable".to_string())];
        add_preconditions(&mut query, options.preconditions.as_ref());
        if let Some(ref acl) = options.canned_acl {
            query.push((
                "predefinedAcl".to_string(),
                object_canned_acl_to_json(acl)?.to_string(),
            ));
        }
        if let Some(EncryptionKey::Cmek { kms_key_name }) = &options.encryption_key {
            query.push(("kmsKeyName".to_string(), kms_key_name.clone()));
        }
        add_user_project(&mut query, self.effective_user_project());
        add_fields_param(&mut query, options.fields.as_deref(), false);

        let content_type = object_metadata
            .content_type
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_CONTENT_TYPE);
        let mut init_headers = HeaderMap::new();
        if let Ok(ct_val) = HeaderValue::from_str(content_type) {
            init_headers.insert(HeaderName::from_static("x-upload-content-type"), ct_val);
        }
        if let Some(len) = content_length {
            if let Ok(len_val) = HeaderValue::from_str(&len.to_string()) {
                init_headers.insert(HeaderName::from_static("x-upload-content-length"), len_val);
            }
        }
        apply_encryption_headers(&mut init_headers, options.encryption_key.as_ref());

        let meta_val = serde_json::to_value(object_metadata).map_err(|e| {
            GsutilError::command(format!("Failed to serialize object metadata: {e}"))
        })?;

        let init_ctx = ErrorContext {
            provider: "gs",
            bucket_name: Some(bucket_name),
            object_name: Some(object_name),
            generation: None,
            not_found_override: Some(create_not_found_for_object_write(
                "gs",
                bucket_name,
                None,
                None,
                None,
            )),
        };

        self.config
            .retry_policy
            .execute(
                || async {
                    let req = self
                        .prepare_request(Method::POST, &init_url, &query, Some(&init_headers))
                        .await?
                        .json(&meta_val);
                    let resp = req.send().await.map_err(reqwest_to_service_error)?;
                    let status = resp.status().as_u16();
                    if self.config.debug_level >= 2 {
                        log_wire_response(status, resp.headers());
                    }
                    let www_auth = resp
                        .headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .map(ToString::to_string);
                    let location = resp
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .map(ToString::to_string);
                    let text = resp.text().await.unwrap_or_default();
                    if (200..300).contains(&status) {
                        location.ok_or_else(|| {
                            GsutilError::Service(ServiceError::resumable_upload_abort(
                                "Resumable upload initiation response missing Location header.",
                                Some(status),
                                None,
                            ))
                        })
                    } else {
                        Err(translate_http_error(
                            status,
                            &text,
                            www_auth.as_deref(),
                            &init_ctx,
                        ))
                    }
                },
                is_retryable_gsutil_error,
            )
            .await
    }

    async fn query_resumable_upload_status(
        &self,
        session_uri: &str,
        total_size: Option<u64>,
        base_headers: &HeaderMap,
    ) -> Result<ResumableQueryStatus> {
        let mut hdrs = base_headers.clone();
        let range_val = match total_size {
            Some(total) => format!("bytes */{total}"),
            None => "bytes */*".to_string(),
        };
        if let Ok(v) = HeaderValue::from_str(&range_val) {
            hdrs.insert(HeaderName::from_static("content-range"), v);
        }

        let req = self
            .prepare_request(Method::PUT, session_uri, &[], Some(&hdrs))
            .await?
            .body(Bytes::new());
        let resp = req.send().await.map_err(reqwest_to_service_error)?;
        let status = resp.status().as_u16();
        if self.config.debug_level >= 2 {
            log_wire_response(status, resp.headers());
        }
        let range_hdr = resp
            .headers()
            .get("range")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        let body_text = resp.text().await.unwrap_or_default();

        if status == 308 {
            let committed = range_hdr
                .as_deref()
                .and_then(parse_resume_range_next_offset)
                .map(|n| n as u64)
                .unwrap_or(0);
            Ok(ResumableQueryStatus::Incomplete(committed))
        } else if (200..300).contains(&status) {
            let obj: Object = serde_json::from_str(&body_text).map_err(|e| {
                GsutilError::Service(ServiceError::service(
                    format!("Failed to parse finalized resumable upload object: {e}"),
                    Some(status),
                    None,
                ))
            })?;
            Ok(ResumableQueryStatus::Complete(Box::new(obj)))
        } else if status == 404 || status == 410 {
            Ok(ResumableQueryStatus::Expired)
        } else {
            Err(translate_resumable_upload_error(status, &body_text))
        }
    }

    async fn send_resumable_put(
        &self,
        session_uri: &str,
        chunk: Bytes,
        headers: &HeaderMap,
    ) -> std::result::Result<ResumablePutOutcome, ResumablePutError> {
        let req = self
            .prepare_request(Method::PUT, session_uri, &[], Some(headers))
            .await
            .map_err(ResumablePutError::Fatal)?
            .body(chunk);
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                let ge = reqwest_to_service_error(e);
                if is_retryable_gsutil_error(&ge) {
                    return Err(ResumablePutError::Retryable {
                        err: ge,
                        retry_after_secs: None,
                    });
                }
                return Err(ResumablePutError::Fatal(ge));
            }
        };

        let status = resp.status().as_u16();
        if self.config.debug_level >= 2 {
            log_wire_response(status, resp.headers());
        }
        let range_hdr = resp
            .headers()
            .get("range")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string);
        let retry_after_secs = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        let body_text = resp.text().await.unwrap_or_default();

        if status == 308 {
            let next_off = range_hdr
                .as_deref()
                .and_then(parse_resume_range_next_offset)
                .map(|n| n as u64);
            Ok(ResumablePutOutcome::Continue(next_off))
        } else if (200..300).contains(&status) {
            let obj: Object = serde_json::from_str(&body_text).map_err(|e| {
                ResumablePutError::Fatal(GsutilError::Service(ServiceError::service(
                    format!("Failed to parse completed resumable upload object: {e}"),
                    Some(status),
                    None,
                )))
            })?;
            Ok(ResumablePutOutcome::Complete(Box::new(obj)))
        } else {
            let translated = translate_resumable_upload_error(status, &body_text);
            if status == 429 || status >= 500 || is_retryable_gsutil_error(&translated) {
                Err(ResumablePutError::Retryable {
                    err: translated,
                    retry_after_secs,
                })
            } else {
                Err(ResumablePutError::Fatal(translated))
            }
        }
    }

    async fn upload_resumable_chunk(
        &self,
        session_uri: &str,
        body: Bytes,
        headers: &HeaderMap,
    ) -> Result<String> {
        self.config
            .retry_policy
            .execute(
                || async {
                    let req = self
                        .prepare_request(Method::PUT, session_uri, &[], Some(headers))
                        .await?
                        .body(body.clone());
                    let resp = req.send().await.map_err(reqwest_to_service_error)?;
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    if (200..300).contains(&status) {
                        Ok(text)
                    } else {
                        Err(translate_resumable_upload_error(status, &text))
                    }
                },
                is_retryable_gsutil_error,
            )
            .await
    }
}

enum ResumableChunkOutcome {
    Continue(usize),
    Complete(String),
}

enum ResumableQueryStatus {
    Complete(Box<Object>),
    Incomplete(u64),
    Expired,
}

enum ResumablePutOutcome {
    Complete(Box<Object>),
    Continue(Option<u64>),
}

enum ResumablePutError {
    Retryable {
        err: GsutilError,
        retry_after_secs: Option<u64>,
    },
    Fatal(GsutilError),
}

/// Default bounded chunk size for streaming/file resumable uploads (8 MiB = 32 * 256 KiB).
const DEFAULT_STREAMING_CHUNK_SIZE: usize = 8 * 1024 * 1024;

fn effective_streaming_chunk_size(override_size: Option<usize>, config_size: usize) -> usize {
    let quantum = RESUMABLE_CHUNK_QUANTUM as usize;
    let raw = match override_size {
        Some(s) if s > 0 => s,
        _ => config_size.min(DEFAULT_STREAMING_CHUNK_SIZE),
    };
    let rem = raw % quantum;
    if rem == 0 {
        raw.max(quantum)
    } else {
        raw + (quantum - rem)
    }
}

async fn read_exact_async<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut buf: &mut [u8],
) -> std::io::Result<()> {
    while !buf.is_empty() {
        let n = reader.read(buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading upload chunk",
            ));
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fields_request_hashes(fields: Option<&[String]>) -> bool {
    match fields {
        None => true,
        Some(list) => list.iter().any(|f| {
            matches!(
                f.as_str(),
                "crc32c" | "md5Hash" | "items/crc32c" | "items/md5Hash"
            )
        }),
    }
}

fn load_csek_keys_from_boto(config: &BotoConfig) -> Vec<(String, String)> {
    let mut keys = Vec::new();
    let mut try_push = |raw: &str| {
        let trimmed = raw.trim();
        if trimmed.len() == 44 {
            if let Ok(decoded) = BASE64_STANDARD.decode(trimmed) {
                if decoded.len() == 32 {
                    let sha = BASE64_STANDARD.encode(Sha256::digest(&decoded));
                    keys.push((trimmed.to_string(), sha));
                }
            }
        }
    };
    if let Some(enc) = config.get("GSUtil", "encryption_key") {
        try_push(enc);
    }
    for i in 1..=100 {
        let key_name = format!("decryption_key{i}");
        match config.get("GSUtil", &key_name) {
            Some(v) => try_push(v),
            None => break,
        }
    }
    keys
}

fn projection_for_fields(fields: Option<&[String]>) -> &'static str {
    match fields {
        None => "full",
        Some(list) => {
            if list.iter().any(|f| ACL_FIELDS.contains(&f.as_str())) {
                "full"
            } else {
                "noAcl"
            }
        }
    }
}

fn add_user_project(query: &mut Vec<(String, String)>, user_project: Option<&str>) {
    if let Some(up) = user_project.filter(|s| !s.trim().is_empty()) {
        query.push(("userProject".to_string(), up.to_string()));
    }
}

fn add_fields_param(
    query: &mut Vec<(String, String)>,
    fields: Option<&[String]>,
    include_next_page_token: bool,
) {
    if let Some(list) = fields {
        if !list.is_empty() {
            let mut set: HashSet<&str> = list.iter().map(String::as_str).collect();
            if include_next_page_token {
                set.insert("nextPageToken");
            }
            let mut sorted: Vec<&str> = set.into_iter().collect();
            sorted.sort_unstable();
            query.push(("fields".to_string(), sorted.join(",")));
        }
    }
}

/// Normalize `?fields=` for GCS JSON v1 `list` endpoints (`buckets.list` / `objects.list`).
///
/// Callers may pass either raw resource fields (`["name", "size", "generation"]`) or
/// list-prefixed fields (`["items/name", "prefixes"]`). Raw resource fields are prefixed
/// with `items/` so GCS accepts the partial-response selector, and `nextPageToken` (plus
/// `prefixes` for `objects.list`) is always included.
fn add_list_fields_param(
    query: &mut Vec<(String, String)>,
    fields: Option<&[String]>,
    include_prefixes: bool,
) {
    if let Some(list) = fields {
        if !list.is_empty() {
            let mut set: HashSet<String> = HashSet::new();
            for raw in list {
                let f = raw.trim();
                if f.is_empty() {
                    continue;
                }
                if matches!(f, "nextPageToken" | "prefixes" | "kind" | "items")
                    || f.starts_with("items/")
                    || f.starts_with("items(")
                {
                    set.insert(f.to_string());
                } else {
                    set.insert(format!("items/{f}"));
                }
            }
            set.insert("nextPageToken".to_string());
            if include_prefixes {
                set.insert("prefixes".to_string());
            }
            let mut sorted: Vec<String> = set.into_iter().collect();
            sorted.sort_unstable();
            query.push(("fields".to_string(), sorted.join(",")));
        }
    }
}

fn add_preconditions(query: &mut Vec<(String, String)>, preconditions: Option<&Preconditions>) {
    if let Some(pre) = preconditions {
        if let Some(g) = pre.gen_match {
            query.push(("ifGenerationMatch".to_string(), g.to_string()));
        }
        if let Some(mg) = pre.meta_gen_match {
            query.push(("ifMetagenerationMatch".to_string(), mg.to_string()));
        }
    }
}

fn apply_encryption_headers(headers: &mut HeaderMap, key: Option<&EncryptionKey>) {
    if let Some(EncryptionKey::Csek {
        key_b64,
        key_sha256_b64,
    }) = key
    {
        headers.insert(
            HeaderName::from_static("x-goog-encryption-algorithm"),
            HeaderValue::from_static("AES256"),
        );
        if let Ok(v) = HeaderValue::from_str(key_b64) {
            headers.insert(HeaderName::from_static("x-goog-encryption-key"), v);
        }
        if let Ok(v) = HeaderValue::from_str(key_sha256_b64) {
            headers.insert(HeaderName::from_static("x-goog-encryption-key-sha256"), v);
        }
    }
}

fn apply_rewrite_crypto_headers(
    headers: &mut HeaderMap,
    decryption_key: Option<&EncryptionKey>,
    encryption_key: Option<&EncryptionKey>,
) {
    if let Some(EncryptionKey::Csek {
        key_b64,
        key_sha256_b64,
    }) = decryption_key
    {
        headers.insert(
            HeaderName::from_static("x-goog-copy-source-encryption-algorithm"),
            HeaderValue::from_static("AES256"),
        );
        if let Ok(v) = HeaderValue::from_str(key_b64) {
            headers.insert(
                HeaderName::from_static("x-goog-copy-source-encryption-key"),
                v,
            );
        }
        if let Ok(v) = HeaderValue::from_str(key_sha256_b64) {
            headers.insert(
                HeaderName::from_static("x-goog-copy-source-encryption-key-sha256"),
                v,
            );
        }
    }
    apply_encryption_headers(headers, encryption_key);
}

fn format_range_header(start_byte: Option<i64>, end_byte: Option<u64>) -> Option<String> {
    match (start_byte, end_byte) {
        (Some(s), Some(e)) if s >= 0 => Some(format!("bytes={s}-{e}")),
        (Some(s), None) if s > 0 => Some(format!("bytes={s}-")),
        (Some(s), None) if s < 0 => Some(format!("bytes={s}")),
        (None, Some(e)) => Some(format!("bytes=0-{e}")),
        _ => None,
    }
}

fn parse_resume_range_next_offset(range_header: &str) -> Option<usize> {
    // Format: `bytes=0-262143` -> next offset is 262144.
    let stripped = range_header.strip_prefix("bytes=").unwrap_or(range_header);
    let (_start, end_str) = stripped.split_once('-')?;
    let end: usize = end_str.trim().parse().ok()?;
    Some(end + 1)
}

fn bucket_canned_acl_to_json(acl: &str) -> Result<&'static str> {
    match acl {
        "authenticated-read" | "authenticatedRead" => Ok("authenticatedRead"),
        "private" => Ok("private"),
        "project-private" | "projectPrivate" => Ok("projectPrivate"),
        "public-read" | "publicRead" => Ok("publicRead"),
        "public-read-write" | "publicReadWrite" => Ok("publicReadWrite"),
        other => Err(GsutilError::argument(format!("Invalid canned ACL {other}"))),
    }
}

fn object_canned_acl_to_json(acl: &str) -> Result<&'static str> {
    match acl {
        "authenticated-read" | "authenticatedRead" => Ok("authenticatedRead"),
        "bucket-owner-read" | "bucketOwnerRead" => Ok("bucketOwnerRead"),
        "bucket-owner-full-control" | "bucketOwnerFullControl" => Ok("bucketOwnerFullControl"),
        "private" => Ok("private"),
        "project-private" | "projectPrivate" => Ok("projectPrivate"),
        "public-read" | "publicRead" => Ok("publicRead"),
        other => Err(GsutilError::argument(format!("Invalid canned ACL {other}"))),
    }
}

fn encode_path_segment(s: &str) -> String {
    percent_encode(s)
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn reqwest_to_service_error(err: reqwest::Error) -> GsutilError {
    if RetryPolicy::is_retryable_reqwest_error(&err) {
        GsutilError::Service(ServiceError::retryable(
            format!("HTTP transport error: {err}"),
            None,
            None,
        ))
    } else {
        GsutilError::Service(ServiceError::service(
            format!("HTTP request error: {err}"),
            None,
            None,
        ))
    }
}

fn is_retryable_gsutil_error(err: &GsutilError) -> bool {
    matches!(err, GsutilError::Service(se) if se.is_retryable())
}

/// Attempt to load a combined PEM client certificate + private key for mTLS when configured
/// via `[Credentials] client_certificate_file` or `CLOUDSDK_CONTEXT_AWARE_CLIENT_CERT_PATH`.
fn resolve_client_identity_pem(config: &BotoConfig) -> Option<Vec<u8>> {
    let path = config
        .get("Credentials", "client_certificate_file")
        .filter(|s| !s.trim().is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            env::var("CLOUDSDK_CONTEXT_AWARE_CLIENT_CERT_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })?;
    std::fs::read(path).ok()
}

fn build_reqwest_client(boto_config: &BotoConfig, no_gzip: bool) -> Result<Client> {
    let mut builder = Client::builder()
        .pool_max_idle_per_host(32)
        .tcp_keepalive(Duration::from_secs(60))
        .danger_accept_invalid_certs(!boto_config.https_validate_certificates());

    if no_gzip {
        builder = builder.no_gzip();
    }

    if let Some(ca_path) = boto_config.ca_certificates_file() {
        let pem = std::fs::read(ca_path).map_err(|e| {
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

    if is_mtls_enabled(boto_config) {
        if let Some(identity_pem) = resolve_client_identity_pem(boto_config) {
            let identity = reqwest::Identity::from_pem(&identity_pem).map_err(|e| {
                GsutilError::command(format!("Failed to load mTLS client identity: {e}"))
            })?;
            builder = builder.identity(identity);
        }
    }

    if let Some(proxy) = boto_config.resolve_proxy() {
        let proxy_url = format_proxy_url(&proxy);
        let reqwest_proxy = reqwest::Proxy::all(&proxy_url)
            .map_err(|e| GsutilError::command(format!("Invalid proxy config: {e}")))?;
        builder = builder.proxy(reqwest_proxy);
    }

    builder
        .build()
        .map_err(|e| GsutilError::command(format!("Failed to build GCS HTTP client: {e}")))
}

fn is_csek_required_error(err: &GsutilError) -> bool {
    match err {
        GsutilError::Service(se) if se.status == Some(400) => {
            let lower = se.reason.to_ascii_lowercase();
            lower.contains("customer-supplied encryption key")
                || lower.contains("encryption key")
                || lower.contains("encrypted")
        }
        _ => false,
    }
}

/// Log an outgoing HTTP request to stderr for `-D` / `-DD` with sensitive headers redacted.
pub(crate) fn log_wire_request(
    method: &Method,
    url: &str,
    query: &[(String, String)],
    headers: &HeaderMap,
) {
    if query.is_empty() {
        eprintln!("send: {} {}", method, url);
    } else {
        let q = query
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        eprintln!("send: {} {}?{}", method, url, q);
    }
    let mut dict_entries = Vec::new();
    for (k, v) in headers {
        let lower = k.as_str().to_ascii_lowercase();
        let val = if matches!(
            lower.as_str(),
            "authorization" | "x-goog-encryption-key" | "x-goog-copy-source-encryption-key"
        ) {
            "REDACTED"
        } else {
            v.to_str().unwrap_or("<binary>")
        };
        dict_entries.push(format!("'{}': '{}'", lower, val));
    }
    eprintln!("Headers: {{{}}}", dict_entries.join(", "));
}

/// Log an incoming HTTP response status & headers to stderr for `-D` / `-DD`.
pub(crate) fn log_wire_response(status: u16, headers: &HeaderMap) {
    let reason = reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("");
    eprintln!("reply: 'HTTP/1.1 {status} {reason}\\r\\n'");
    for (k, v) in headers {
        let display_name = canonical_header_name(k.as_str());
        eprintln!(
            "header: {display_name}: {}",
            v.to_str().unwrap_or("<binary>")
        );
    }
}

fn canonical_header_name(lower: &str) -> String {
    match lower {
        "etag" => "ETag".to_string(),
        "content-type" => "Content-Type".to_string(),
        "content-length" => "Content-Length".to_string(),
        "cache-control" => "Cache-Control".to_string(),
        "last-modified" => "Last-Modified".to_string(),
        "date" => "Date".to_string(),
        "expires" => "Expires".to_string(),
        other if other.starts_with("x-goog-") || other.starts_with("x-amz-") => other.to_string(),
        other => other
            .split('-')
            .map(|part| {
                let mut chars = part.chars();
                match chars.next() {
                    Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join("-"),
    }
}
