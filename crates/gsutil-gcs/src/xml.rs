//! XML / S3 interoperability backend implementing `gsutil_core::api::CloudApi`.
//!
//! Mirrors `gslib/boto_translation.py` for GCS XML (`gs://`) and Amazon S3 (`s3://`)
//! with AWS Signature Version 4 (HMAC), OAuth2 bearer auth (for GCS XML), XML
//! parsing/serialization for buckets/objects/ACLs/CORS/lifecycle, and
//! `_TranslateBotoException` parity.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use gsutil_auth::{HmacCredentials, TokenProvider};
use gsutil_core::api::{
    Bucket, BucketAccessControl, BucketCors, BucketLifecycle, BucketVersioning, Channel, CloudApi,
    ComposeSourceObject, CopyOptions, CreateNotificationOptions, CsObjectOrPrefix, DownloadOptions,
    DownloadStrategy, EncryptionKey, HmacKeyCreateResponse, HmacKeyMetadata, IamPolicy,
    LifecycleAction, LifecycleCondition, LifecycleRule, ListObjectsOptions, Notification, Object,
    Preconditions, ServiceAccount, SignUrlOptions, UploadOptions,
};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result, ServiceError};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE, HOST, RANGE, USER_AGENT};
use reqwest::{Client, Method};
use sha2::{Digest, Sha256};

use crate::client::{log_wire_request, log_wire_response, DEFAULT_USER_AGENT};
use crate::error_translation::{
    create_bucket_not_found, create_not_found_for_object_write, create_object_not_found,
    ErrorContext,
};
use crate::retry::RetryPolicy;

pub const DEFAULT_S3_HOST: &str = "s3.amazonaws.com";
pub const DEFAULT_GCS_XML_HOST: &str = "storage.googleapis.com";

/// Configuration for the XML / S3 interoperability client.
#[derive(Debug, Clone)]
pub struct XmlClientConfig {
    pub provider: String,
    pub endpoint: String,
    pub host_header: String,
    pub region: String,
    pub api_version: String,
    pub default_project_id: Option<String>,
    pub custom_headers: BTreeMap<String, String>,
    pub retry_policy: RetryPolicy,
    pub debug_level: u8,
}

impl XmlClientConfig {
    pub fn from_boto_config(provider: &str, config: &BotoConfig) -> Self {
        let (default_host, host_key, port_key, host_hdr_key) = if provider == "s3" {
            (DEFAULT_S3_HOST, "s3_host", "s3_port", "s3_host_header")
        } else {
            (DEFAULT_GCS_XML_HOST, "gs_host", "gs_port", "gs_host_header")
        };

        let host = config.get_or("Credentials", host_key, default_host);
        let port = config
            .get("Credentials", port_key)
            .filter(|p| !p.is_empty());
        let scheme = if host.starts_with("http://") || host.starts_with("https://") {
            ""
        } else if config.is_secure() {
            "https://"
        } else {
            "http://"
        };
        let endpoint = match port {
            Some(p) => format!("{scheme}{host}:{p}"),
            None => format!("{scheme}{host}"),
        };

        let stripped_host = host
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        let host_header = config
            .get("Credentials", host_hdr_key)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| match port {
                Some(p) => format!("{stripped_host}:{p}"),
                None => stripped_host.to_string(),
            });

        let region = config
            .get("s3", "calling_format_region")
            .unwrap_or("us-east-1")
            .to_string();
        let api_version = config
            .get_or("GSUtil", "default_api_version", "2")
            .to_string();

        Self {
            provider: provider.to_string(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
            host_header,
            region,
            api_version,
            default_project_id: config.default_project_id().map(ToString::to_string),
            custom_headers: BTreeMap::new(),
            retry_policy: RetryPolicy::from_config(config),
            debug_level: 0,
        }
    }

    pub fn for_mock_server(provider: &str, base_url: impl Into<String>) -> Self {
        let base = base_url.into().trim_end_matches('/').to_string();
        let host_header = base
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .to_string();
        Self {
            provider: provider.to_string(),
            endpoint: base,
            host_header,
            region: "us-east-1".to_string(),
            api_version: "2".to_string(),
            default_project_id: Some("test-project".to_string()),
            custom_headers: BTreeMap::new(),
            retry_policy: RetryPolicy::fast_for_tests(3),
            debug_level: 0,
        }
    }

    fn header_prefix(&self) -> &'static str {
        if self.provider == "s3" {
            "x-amz-"
        } else {
            "x-goog-"
        }
    }
}

/// XML / S3 interoperability API client implementing [`CloudApi`].
#[derive(Clone)]
pub struct XmlApiClient {
    config: XmlClientConfig,
    http: Client,
    credentials: Arc<dyn TokenProvider>,
}

impl XmlApiClient {
    pub fn new(
        provider: &str,
        boto_config: &BotoConfig,
        credentials: Arc<dyn TokenProvider>,
    ) -> Self {
        let cfg = XmlClientConfig::from_boto_config(provider, boto_config);
        let mut builder = Client::builder()
            .pool_max_idle_per_host(32)
            .tcp_keepalive(Duration::from_secs(60))
            .danger_accept_invalid_certs(!boto_config.https_validate_certificates());
        if let Some(ca_path) = boto_config.ca_certificates_file() {
            if let Ok(pem) = std::fs::read(ca_path) {
                if let Ok(certs) = reqwest::Certificate::from_pem_bundle(&pem) {
                    for cert in certs {
                        builder = builder.add_root_certificate(cert);
                    }
                }
            }
        }
        if let Some(proxy) = boto_config.resolve_proxy() {
            if let Ok(p) = reqwest::Proxy::all(proxy.to_url()) {
                builder = builder.proxy(p);
            }
        }
        let http = builder.build().unwrap_or_else(|_| Client::new());
        Self {
            config: cfg,
            http,
            credentials,
        }
    }

    pub fn with_config(config: XmlClientConfig, credentials: Arc<dyn TokenProvider>) -> Self {
        Self {
            config,
            http: Client::new(),
            credentials,
        }
    }

    pub fn config(&self) -> &XmlClientConfig {
        &self.config
    }

    pub fn hmac_credentials(&self) -> Option<&HmacCredentials> {
        self.credentials.hmac_credentials()
    }

    /// Compute lowercase hex SHA-256 hash of a payload (used by AWS SigV4 `x-amz-content-sha256`).
    pub fn sha256_hex(payload: &[u8]) -> String {
        hex::encode(Sha256::digest(payload))
    }

    /// Compute HMAC-SHA256 using RFC 2104 (used for AWS SigV4 signing key derivation).
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        const BLOCK_SIZE: usize = 64;
        let mut key_block = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            let hashed = Sha256::digest(key);
            key_block[..32].copy_from_slice(&hashed);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; BLOCK_SIZE];
        let mut opad = [0x5cu8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            ipad[i] ^= key_block[i];
            opad[i] ^= key_block[i];
        }

        let mut inner = Sha256::new();
        inner.update(ipad);
        inner.update(data);
        let inner_hash = inner.finalize();

        let mut outer = Sha256::new();
        outer.update(opad);
        outer.update(inner_hash);
        let out = outer.finalize();

        let mut result = [0u8; 32];
        result.copy_from_slice(&out);
        result
    }

    /// Derive AWS SigV4 signing key (`kSigning`) for a given date (`YYYYMMDD`), region, and service.
    pub fn derive_sigv4_signing_key(
        secret_access_key: &str,
        date_stamp: &str,
        region: &str,
        service: &str,
    ) -> [u8; 32] {
        let k_secret = format!("AWS4{secret_access_key}");
        let k_date = Self::hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
        let k_region = Self::hmac_sha256(&k_date, region.as_bytes());
        let k_service = Self::hmac_sha256(&k_region, service.as_bytes());
        Self::hmac_sha256(&k_service, b"aws4_request")
    }

    /// Sign an HTTP request with AWS Signature Version 4 headers (`Authorization`, `x-amz-date`,
    /// `x-amz-content-sha256`).
    pub fn apply_sigv4_headers(
        &self,
        hmac: &HmacCredentials,
        method: &Method,
        canonical_uri: &str,
        query: &[(String, String)],
        headers: &mut HeaderMap,
        payload: &[u8],
    ) {
        let now = Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let payload_hash = Self::sha256_hex(payload);

        if let Ok(v) = HeaderValue::from_str(&self.config.host_header) {
            headers.insert(HOST, v);
        }
        if let Ok(v) = HeaderValue::from_str(&amz_date) {
            headers.insert(HeaderName::from_static("x-amz-date"), v);
        }
        if let Ok(v) = HeaderValue::from_str(&payload_hash) {
            headers.insert(HeaderName::from_static("x-amz-content-sha256"), v);
        }

        let mut canonical_headers_map: BTreeMap<String, String> = BTreeMap::new();
        for (name, val) in headers.iter() {
            let lower = name.as_str().to_ascii_lowercase();
            if lower == "host" || lower.starts_with("x-amz-") || lower.starts_with("x-goog-") {
                if let Ok(s) = val.to_str() {
                    canonical_headers_map.insert(lower, s.trim().to_string());
                }
            }
        }
        let signed_headers: String = canonical_headers_map
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(";");
        let canonical_headers: String = canonical_headers_map
            .iter()
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect();

        let mut sorted_query = query.to_vec();
        sorted_query.sort();
        let canonical_query = sorted_query
            .iter()
            .map(|(k, v)| format!("{}={}", percent_encode_uri(k), percent_encode_uri(v)))
            .collect::<Vec<_>>()
            .join("&");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash
        );
        let credential_scope = format!("{}/{}/s3/aws4_request", date_stamp, self.config.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            credential_scope,
            Self::sha256_hex(canonical_request.as_bytes())
        );

        let signing_key = Self::derive_sigv4_signing_key(
            &hmac.secret_access_key,
            &date_stamp,
            &self.config.region,
            "s3",
        );
        let signature = hex::encode(Self::hmac_sha256(&signing_key, string_to_sign.as_bytes()));
        let auth_value = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            hmac.access_key_id, credential_scope, signed_headers, signature
        );
        if let Ok(v) = HeaderValue::from_str(&auth_value) {
            headers.insert(HeaderName::from_static("authorization"), v);
        }
    }

    /// Ensure HMAC credentials are available before issuing signed S3/XML calls.
    pub fn require_hmac(&self) -> Result<&HmacCredentials> {
        self.hmac_credentials().ok_or_else(|| {
            GsutilError::command(format!(
                "No HMAC credentials configured for provider '{}'. \
                 Configure aws_access_key_id/aws_secret_access_key or \
                 gs_access_key_id/gs_secret_access_key in your .boto file.",
                self.config.provider
            ))
        })
    }

    fn base_headers(&self, extra: Option<&HeaderMap>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(DEFAULT_USER_AGENT));
        if self.config.provider == "gs" {
            if let Ok(v) = HeaderValue::from_str(&self.config.api_version) {
                headers.insert(HeaderName::from_static("x-goog-api-version"), v);
            }
        }
        for (k, v) in &self.config.custom_headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                headers.insert(name, val);
            }
        }
        if let Some(e) = extra {
            for (k, v) in e {
                headers.insert(k.clone(), v.clone());
            }
        }
        headers
    }

    async fn send_xml_request(
        &self,
        method: Method,
        canonical_uri: &str,
        query: &[(String, String)],
        body: Bytes,
        extra_headers: Option<&HeaderMap>,
        ctx: &ErrorContext<'_>,
    ) -> Result<(u16, HeaderMap, Bytes)> {
        let url = format!("{}{}", self.config.endpoint, canonical_uri);

        self.config
            .retry_policy
            .execute(
                || async {
                    let mut headers = self.base_headers(extra_headers);
                    let mut req = self.http.request(method.clone(), &url);
                    if !query.is_empty() {
                        req = req.query(query);
                    }

                    if let Some(hmac) = self.credentials.hmac_credentials() {
                        self.apply_sigv4_headers(
                            hmac,
                            &method,
                            canonical_uri,
                            query,
                            &mut headers,
                            &body,
                        );
                    } else if let Some(tok) = self.credentials.token().await? {
                        req = req.bearer_auth(&tok.token);
                    }

                    if self.config.debug_level >= 2 {
                        log_wire_request(&method, &url, query, &headers);
                    }
                    req = req.headers(headers);
                    if !body.is_empty() {
                        if self.config.debug_level >= 3 {
                            eprintln!("send body: {}", String::from_utf8_lossy(&body));
                        }
                        req = req.body(body.clone());
                    }

                    let resp = req.send().await.map_err(|e| {
                        if RetryPolicy::is_retryable_reqwest_error(&e) {
                            GsutilError::Service(ServiceError::retryable(
                                format!("XML HTTP transport error: {e}"),
                                None,
                                None,
                            ))
                        } else {
                            GsutilError::Service(ServiceError::service(
                                format!("XML HTTP request error: {e}"),
                                None,
                                None,
                            ))
                        }
                    })?;

                    let status = resp.status().as_u16();
                    let resp_headers = resp.headers().clone();
                    if self.config.debug_level >= 2 {
                        log_wire_response(status, &resp_headers);
                    }
                    let resp_bytes = resp.bytes().await.unwrap_or_default();
                    if self.config.debug_level >= 3 && !resp_bytes.is_empty() {
                        eprintln!("reply body: {}", String::from_utf8_lossy(&resp_bytes));
                    }
                    if (200..300).contains(&status) {
                        Ok((status, resp_headers, resp_bytes))
                    } else {
                        let body_str = String::from_utf8_lossy(&resp_bytes);
                        Err(translate_xml_error(status, &body_str, ctx))
                    }
                },
                |e| matches!(e, GsutilError::Service(se) if se.is_retryable()),
            )
            .await
    }

    fn require_project_id<'a>(&'a self, project_id: Option<&'a str>) -> Result<&'a str> {
        project_id
            .filter(|s| !s.trim().is_empty())
            .or(self.config.default_project_id.as_deref())
            .ok_or_else(|| GsutilError::project_id("No project ID configured for this operation."))
    }
}

#[async_trait]
impl CloudApi for XmlApiClient {
    async fn get_service_account_id(&self) -> Result<String> {
        Err(GsutilError::command(
            "Service account ID is not supported by the XML API.",
        ))
    }

    async fn get_bucket(&self, bucket_name: &str, _fields: Option<&[String]>) -> Result<Bucket> {
        let uri = format!("/{}", percent_encode_segment(bucket_name));
        let query = vec![("max-keys".to_string(), "0".to_string())];
        let ctx = ErrorContext {
            provider: &self.config.provider,
            bucket_name: Some(bucket_name),
            ..Default::default()
        };
        let (_status, headers, _body) = self
            .send_xml_request(Method::GET, &uri, &query, Bytes::new(), None, &ctx)
            .await?;

        let mut bucket = Bucket {
            name: Some(bucket_name.to_string()),
            id: Some(bucket_name.to_string()),
            metageneration: header_str(&headers, "x-goog-metageneration"),
            ..Default::default()
        };

        // Best-effort versioning query if supported.
        if let Ok((_s, _h, vbytes)) = self
            .send_xml_request(
                Method::GET,
                &uri,
                &[("versioning".to_string(), String::new())],
                Bytes::new(),
                None,
                &ctx,
            )
            .await
        {
            let xml = String::from_utf8_lossy(&vbytes);
            if let Some(status_str) = extract_xml_tag(&xml, "Status") {
                bucket.versioning = Some(BucketVersioning {
                    enabled: Some(status_str.eq_ignore_ascii_case("Enabled")),
                });
            }
        }

        Ok(bucket)
    }

    async fn list_buckets(
        &self,
        project_id: Option<&str>,
        _fields: Option<&[String]>,
    ) -> Result<Vec<Bucket>> {
        let mut extra = HeaderMap::new();
        if self.config.provider == "gs" {
            let proj = self.require_project_id(project_id)?;
            if let Ok(v) = HeaderValue::from_str(proj) {
                extra.insert(HeaderName::from_static("x-goog-project-id"), v);
            }
        }
        let ctx = ErrorContext {
            provider: &self.config.provider,
            ..Default::default()
        };
        let (_status, _headers, body) = self
            .send_xml_request(Method::GET, "/", &[], Bytes::new(), Some(&extra), &ctx)
            .await?;
        let xml = String::from_utf8_lossy(&body);
        Ok(parse_list_buckets_xml(&xml))
    }

    async fn create_bucket(
        &self,
        bucket_name: &str,
        project_id: Option<&str>,
        metadata: Option<&Bucket>,
        _fields: Option<&[String]>,
    ) -> Result<Bucket> {
        let uri = format!("/{}", percent_encode_segment(bucket_name));
        let mut extra = HeaderMap::new();
        if self.config.provider == "gs" {
            let proj = self.require_project_id(project_id)?;
            if let Ok(v) = HeaderValue::from_str(proj) {
                extra.insert(HeaderName::from_static("x-goog-project-id"), v);
            }
        }

        let xml_body = build_create_bucket_xml(metadata);
        if !xml_body.is_empty() {
            extra.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
        }

        let ctx = ErrorContext {
            provider: &self.config.provider,
            bucket_name: Some(bucket_name),
            ..Default::default()
        };
        self.send_xml_request(
            Method::PUT,
            &uri,
            &[],
            Bytes::from(xml_body),
            Some(&extra),
            &ctx,
        )
        .await?;

        Ok(Bucket {
            name: Some(bucket_name.to_string()),
            id: Some(bucket_name.to_string()),
            location: metadata.and_then(|m| m.location.clone()),
            storage_class: metadata.and_then(|m| m.storage_class.clone()),
            ..Default::default()
        })
    }

    async fn patch_bucket(
        &self,
        bucket_name: &str,
        metadata: &Bucket,
        canned_acl: Option<&str>,
        _canned_def_acl: Option<&str>,
        _preconditions: Option<&Preconditions>,
        _fields: Option<&[String]>,
    ) -> Result<Bucket> {
        let uri = format!("/{}", percent_encode_segment(bucket_name));
        let ctx = ErrorContext {
            provider: &self.config.provider,
            bucket_name: Some(bucket_name),
            ..Default::default()
        };

        if let Some(ref versioning) = metadata.versioning {
            let status = if versioning.enabled == Some(true) {
                "Enabled"
            } else {
                "Suspended"
            };
            let xml = format!(
                "<VersioningConfiguration><Status>{status}</Status></VersioningConfiguration>"
            );
            let mut extra = HeaderMap::new();
            extra.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
            self.send_xml_request(
                Method::PUT,
                &uri,
                &[("versioning".to_string(), String::new())],
                Bytes::from(xml),
                Some(&extra),
                &ctx,
            )
            .await?;
        }

        if let Some(ref cors) = metadata.cors {
            let xml = serialize_cors_xml(cors, &self.config.provider);
            let mut extra = HeaderMap::new();
            extra.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
            self.send_xml_request(
                Method::PUT,
                &uri,
                &[("cors".to_string(), String::new())],
                Bytes::from(xml),
                Some(&extra),
                &ctx,
            )
            .await?;
        }

        if let Some(ref lifecycle) = metadata.lifecycle {
            let xml = serialize_lifecycle_xml(lifecycle);
            let mut extra = HeaderMap::new();
            extra.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
            self.send_xml_request(
                Method::PUT,
                &uri,
                &[("lifecycle".to_string(), String::new())],
                Bytes::from(xml),
                Some(&extra),
                &ctx,
            )
            .await?;
        }

        if let Some(acl) = canned_acl {
            let mut extra = HeaderMap::new();
            let hdr_name = format!("{}acl", self.config.header_prefix());
            if let (Ok(k), Ok(v)) = (
                HeaderName::from_bytes(hdr_name.as_bytes()),
                HeaderValue::from_str(acl),
            ) {
                extra.insert(k, v);
            }
            self.send_xml_request(
                Method::PUT,
                &uri,
                &[("acl".to_string(), String::new())],
                Bytes::new(),
                Some(&extra),
                &ctx,
            )
            .await?;
        }

        Ok(Bucket {
            name: Some(bucket_name.to_string()),
            ..metadata.clone()
        })
    }

    async fn delete_bucket(
        &self,
        bucket_name: &str,
        preconditions: Option<&Preconditions>,
    ) -> Result<()> {
        let uri = format!("/{}", percent_encode_segment(bucket_name));
        let mut extra = HeaderMap::new();
        apply_xml_preconditions(&mut extra, preconditions, self.config.header_prefix());
        let ctx = ErrorContext {
            provider: &self.config.provider,
            bucket_name: Some(bucket_name),
            ..Default::default()
        };
        self.send_xml_request(Method::DELETE, &uri, &[], Bytes::new(), Some(&extra), &ctx)
            .await
            .map(|_| ())
    }

    async fn lock_retention_policy(
        &self,
        _bucket_name: &str,
        _metageneration: i64,
    ) -> Result<Bucket> {
        Err(GsutilError::command(
            "Retention policy lock is only supported by the GCS JSON API.",
        ))
    }

    async fn get_bucket_iam_policy(
        &self,
        _bucket_name: &str,
        _fields: Option<&[String]>,
    ) -> Result<IamPolicy> {
        Err(GsutilError::command(
            "IAM operations are only supported by the GCS JSON API.",
        ))
    }

    async fn set_bucket_iam_policy(
        &self,
        _bucket_name: &str,
        _policy: &IamPolicy,
    ) -> Result<IamPolicy> {
        Err(GsutilError::command(
            "IAM operations are only supported by the GCS JSON API.",
        ))
    }

    async fn list_objects(
        &self,
        bucket_name: &str,
        options: &ListObjectsOptions,
    ) -> Result<Vec<CsObjectOrPrefix>> {
        let uri = format!("/{}", percent_encode_segment(bucket_name));
        let ctx = ErrorContext {
            provider: &self.config.provider,
            bucket_name: Some(bucket_name),
            ..Default::default()
        };

        let mut results = Vec::new();
        let mut marker: Option<String> = None;

        loop {
            let mut query = Vec::new();
            if let Some(ref prefix) = options.prefix {
                query.push(("prefix".to_string(), prefix.clone()));
            }
            if let Some(ref delimiter) = options.delimiter {
                query.push(("delimiter".to_string(), delimiter.clone()));
            }
            if options.all_versions {
                query.push(("versions".to_string(), String::new()));
            }
            if let Some(ref m) = marker {
                query.push(("marker".to_string(), m.clone()));
            }

            let (_status, _headers, body) = self
                .send_xml_request(Method::GET, &uri, &query, Bytes::new(), None, &ctx)
                .await?;
            let xml = String::from_utf8_lossy(&body);
            let parsed = parse_list_objects_xml(bucket_name, &xml);

            let last_key = parsed.objects.last().and_then(|o| o.name.clone());

            for obj in parsed.objects {
                results.push(CsObjectOrPrefix::Object(Box::new(obj)));
            }
            for pref in parsed.prefixes {
                results.push(CsObjectOrPrefix::Prefix(pref));
            }

            if parsed.is_truncated {
                marker = parsed.next_marker.or(last_key);
                if marker.is_none() {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(results)
    }

    async fn get_object_metadata(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
        _fields: Option<&[String]>,
    ) -> Result<Object> {
        let uri = format!(
            "/{}/{}",
            percent_encode_segment(bucket_name),
            encode_object_path(object_name)
        );
        let mut query = Vec::new();
        if let Some(gen) = generation {
            let key = if self.config.provider == "s3" {
                "versionId"
            } else {
                "generation"
            };
            query.push((key.to_string(), gen.to_string()));
        }
        let ctx = ErrorContext {
            provider: &self.config.provider,
            bucket_name: Some(bucket_name),
            object_name: Some(object_name),
            generation,
            not_found_override: None,
        };
        let (_status, headers, _body) = self
            .send_xml_request(Method::HEAD, &uri, &query, Bytes::new(), None, &ctx)
            .await?;

        Ok(object_from_xml_headers(
            bucket_name,
            object_name,
            &headers,
            self.config.header_prefix(),
        ))
    }

    async fn patch_object_metadata(
        &self,
        bucket_name: &str,
        object_name: &str,
        metadata: &Object,
        canned_acl: Option<&str>,
        generation: Option<&str>,
        preconditions: Option<&Preconditions>,
        _fields: Option<&[String]>,
    ) -> Result<Object> {
        let uri = format!(
            "/{}/{}",
            percent_encode_segment(bucket_name),
            encode_object_path(object_name)
        );
        let prefix = self.config.header_prefix();
        let mut extra = HeaderMap::new();
        let copy_src = match generation {
            Some(g) => format!("/{bucket_name}/{object_name}?generation={g}"),
            None => format!("/{bucket_name}/{object_name}"),
        };
        insert_hdr(&mut extra, &format!("{prefix}copy-source"), &copy_src);
        insert_hdr(
            &mut extra,
            &format!("{prefix}metadata-directive"),
            "REPLACE",
        );
        apply_object_metadata_headers(&mut extra, metadata, prefix);
        if let Some(acl) = canned_acl {
            insert_hdr(&mut extra, &format!("{prefix}acl"), acl);
        }
        apply_xml_preconditions(&mut extra, preconditions, prefix);

        let ctx = ErrorContext {
            provider: &self.config.provider,
            bucket_name: Some(bucket_name),
            object_name: Some(object_name),
            generation,
            not_found_override: None,
        };
        self.send_xml_request(Method::PUT, &uri, &[], Bytes::new(), Some(&extra), &ctx)
            .await?;
        Ok(Object {
            bucket: Some(bucket_name.to_string()),
            name: Some(object_name.to_string()),
            ..metadata.clone()
        })
    }

    async fn get_object_iam_policy(
        &self,
        _bucket_name: &str,
        _object_name: &str,
        _generation: Option<&str>,
        _fields: Option<&[String]>,
    ) -> Result<IamPolicy> {
        Err(GsutilError::command(
            "IAM operations are only supported by the GCS JSON API.",
        ))
    }

    async fn set_object_iam_policy(
        &self,
        _bucket_name: &str,
        _object_name: &str,
        _policy: &IamPolicy,
        _generation: Option<&str>,
    ) -> Result<IamPolicy> {
        Err(GsutilError::command(
            "IAM operations are only supported by the GCS JSON API.",
        ))
    }

    async fn get_object_media(
        &self,
        bucket_name: &str,
        object_name: &str,
        options: &DownloadOptions,
    ) -> Result<Bytes> {
        let uri = format!(
            "/{}/{}",
            percent_encode_segment(bucket_name),
            encode_object_path(object_name)
        );
        let mut query = Vec::new();
        if let Some(ref gen) = options.generation {
            let key = if self.config.provider == "s3" {
                "versionId"
            } else {
                "generation"
            };
            query.push((key.to_string(), gen.clone()));
        }
        let mut extra = HeaderMap::new();
        match (options.start_byte, options.end_byte) {
            (Some(s), Some(e)) if s >= 0 => {
                if let Ok(v) = HeaderValue::from_str(&format!("bytes={s}-{e}")) {
                    extra.insert(RANGE, v);
                }
            }
            (Some(s), None) if s > 0 => {
                if let Ok(v) = HeaderValue::from_str(&format!("bytes={s}-")) {
                    extra.insert(RANGE, v);
                }
            }
            (None, Some(e)) => {
                if let Ok(v) = HeaderValue::from_str(&format!("bytes=0-{e}")) {
                    extra.insert(RANGE, v);
                }
            }
            _ => {}
        }
        if options.compressed_encoding {
            extra.insert(
                HeaderName::from_static("accept-encoding"),
                HeaderValue::from_static("gzip"),
            );
        }

        let ctx = ErrorContext {
            provider: &self.config.provider,
            bucket_name: Some(bucket_name),
            object_name: Some(object_name),
            generation: options.generation.as_deref(),
            not_found_override: None,
        };

        let _ = options.strategy == DownloadStrategy::Resumable;
        let (_status, _headers, body) = self
            .send_xml_request(Method::GET, &uri, &query, Bytes::new(), Some(&extra), &ctx)
            .await?;
        Ok(body)
    }

    async fn upload_object(
        &self,
        data: Bytes,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        let bucket_name = object_metadata
            .bucket
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Object metadata missing bucket."))?;
        let object_name = object_metadata
            .name
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Object metadata missing name."))?;

        let uri = format!(
            "/{}/{}",
            percent_encode_segment(bucket_name),
            encode_object_path(object_name)
        );
        let prefix = self.config.header_prefix();
        let mut extra = HeaderMap::new();
        apply_object_metadata_headers(&mut extra, object_metadata, prefix);
        if let Some(ref acl) = options.canned_acl {
            insert_hdr(&mut extra, &format!("{prefix}acl"), acl);
        }
        if options.gzip_encoded {
            extra.insert(
                HeaderName::from_static("content-encoding"),
                HeaderValue::from_static("gzip"),
            );
        }
        apply_xml_preconditions(&mut extra, options.preconditions.as_ref(), prefix);

        let ctx = ErrorContext {
            provider: &self.config.provider,
            bucket_name: Some(bucket_name),
            object_name: Some(object_name),
            generation: None,
            not_found_override: Some(create_not_found_for_object_write(
                &self.config.provider,
                bucket_name,
                None,
                None,
                None,
            )),
        };

        let data_len = data.len();
        let (_status, headers, _body) = self
            .send_xml_request(Method::PUT, &uri, &[], data, Some(&extra), &ctx)
            .await?;

        let mut obj = object_from_xml_headers(bucket_name, object_name, &headers, prefix);
        if obj.size.is_none() {
            obj.size = Some(data_len.to_string());
        }
        Ok(obj)
    }

    async fn upload_object_resumable(
        &self,
        data: Bytes,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        self.upload_object(data, object_metadata, options).await
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
            .ok_or_else(|| GsutilError::argument("Source object missing bucket."))?;
        let src_object = src_obj_metadata
            .name
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Source object missing name."))?;
        let dst_bucket = dst_obj_metadata
            .bucket
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Destination object missing bucket."))?;
        let dst_object = dst_obj_metadata
            .name
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Destination object missing name."))?;

        let uri = format!(
            "/{}/{}",
            percent_encode_segment(dst_bucket),
            encode_object_path(dst_object)
        );
        let prefix = self.config.header_prefix();
        let mut extra = HeaderMap::new();
        let copy_src = match &options.src_generation {
            Some(g) => format!("/{src_bucket}/{src_object}?generation={g}"),
            None => format!("/{src_bucket}/{src_object}"),
        };
        insert_hdr(&mut extra, &format!("{prefix}copy-source"), &copy_src);
        if let Some(ref acl) = options.canned_acl {
            insert_hdr(&mut extra, &format!("{prefix}acl"), acl);
        }
        apply_xml_preconditions(&mut extra, options.preconditions.as_ref(), prefix);

        let ctx = ErrorContext {
            provider: &self.config.provider,
            bucket_name: Some(dst_bucket),
            object_name: Some(dst_object),
            generation: None,
            not_found_override: Some(create_not_found_for_object_write(
                &self.config.provider,
                dst_bucket,
                Some(src_bucket),
                Some(src_object),
                options.src_generation.as_deref(),
            )),
        };

        let (_status, headers, _body) = self
            .send_xml_request(Method::PUT, &uri, &[], Bytes::new(), Some(&extra), &ctx)
            .await?;

        Ok(object_from_xml_headers(
            dst_bucket, dst_object, &headers, prefix,
        ))
    }

    async fn compose_object(
        &self,
        src_objs: &[ComposeSourceObject],
        dst_obj_metadata: &Object,
        preconditions: Option<&Preconditions>,
        _encryption_key: Option<&EncryptionKey>,
        _fields: Option<&[String]>,
    ) -> Result<Object> {
        if self.config.provider == "s3" {
            return Err(GsutilError::command(
                "Compose is not supported for s3:// URLs.",
            ));
        }
        let dst_bucket = dst_obj_metadata
            .bucket
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Compose destination missing bucket."))?;
        let dst_object = dst_obj_metadata
            .name
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Compose destination missing name."))?;

        let uri = format!(
            "/{}/{}",
            percent_encode_segment(dst_bucket),
            encode_object_path(dst_object)
        );
        let mut xml = String::from("<ComposeRequest>");
        for src in src_objs {
            xml.push_str("<Component><Name>");
            xml.push_str(&escape_xml(&src.name));
            xml.push_str("</Name>");
            if let Some(ref gen) = src.generation {
                xml.push_str("<Generation>");
                xml.push_str(&escape_xml(gen));
                xml.push_str("</Generation>");
            }
            xml.push_str("</Component>");
        }
        xml.push_str("</ComposeRequest>");

        let mut extra = HeaderMap::new();
        extra.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
        apply_xml_preconditions(&mut extra, preconditions, "x-goog-");

        let ctx = ErrorContext {
            provider: &self.config.provider,
            bucket_name: Some(dst_bucket),
            object_name: Some(dst_object),
            generation: None,
            not_found_override: Some(ServiceError::not_found(
                "One of the source objects does not exist.",
                None,
                None,
            )),
        };

        let (_status, headers, _body) = self
            .send_xml_request(
                Method::PUT,
                &uri,
                &[("compose".to_string(), String::new())],
                Bytes::from(xml),
                Some(&extra),
                &ctx,
            )
            .await?;

        Ok(object_from_xml_headers(
            dst_bucket, dst_object, &headers, "x-goog-",
        ))
    }

    async fn delete_object(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
        preconditions: Option<&Preconditions>,
    ) -> Result<()> {
        let uri = format!(
            "/{}/{}",
            percent_encode_segment(bucket_name),
            encode_object_path(object_name)
        );
        let mut query = Vec::new();
        if let Some(gen) = generation {
            let key = if self.config.provider == "s3" {
                "versionId"
            } else {
                "generation"
            };
            query.push((key.to_string(), gen.to_string()));
        }
        let mut extra = HeaderMap::new();
        apply_xml_preconditions(&mut extra, preconditions, self.config.header_prefix());

        let ctx = ErrorContext {
            provider: &self.config.provider,
            bucket_name: Some(bucket_name),
            object_name: Some(object_name),
            generation,
            not_found_override: None,
        };
        self.send_xml_request(
            Method::DELETE,
            &uri,
            &query,
            Bytes::new(),
            Some(&extra),
            &ctx,
        )
        .await
        .map(|_| ())
    }

    async fn watch_bucket(
        &self,
        _bucket_name: &str,
        _address: &str,
        _channel_id: &str,
        _token: Option<&str>,
    ) -> Result<Channel> {
        Err(GsutilError::command(
            "WatchBucket is only supported by the GCS JSON API.",
        ))
    }

    async fn stop_channel(&self, _channel_id: &str, _resource_id: &str) -> Result<()> {
        Err(GsutilError::command(
            "StopChannel is only supported by the GCS JSON API.",
        ))
    }

    async fn get_project_service_account(&self, _project_id: &str) -> Result<ServiceAccount> {
        Err(GsutilError::command(
            "GetProjectServiceAccount is only supported by the GCS JSON API.",
        ))
    }

    async fn create_notification_config(
        &self,
        _bucket_name: &str,
        _options: &CreateNotificationOptions,
    ) -> Result<Notification> {
        Err(GsutilError::command(
            "Pub/Sub notifications are only supported by the GCS JSON API.",
        ))
    }

    async fn delete_notification_config(
        &self,
        _bucket_name: &str,
        _notification_id: &str,
    ) -> Result<()> {
        Err(GsutilError::command(
            "Pub/Sub notifications are only supported by the GCS JSON API.",
        ))
    }

    async fn list_notification_configs(&self, _bucket_name: &str) -> Result<Vec<Notification>> {
        Err(GsutilError::command(
            "Pub/Sub notifications are only supported by the GCS JSON API.",
        ))
    }

    async fn create_hmac_key(
        &self,
        _project_id: &str,
        _service_account_email: &str,
    ) -> Result<HmacKeyCreateResponse> {
        Err(GsutilError::command(
            "HMAC key management is only supported by the GCS JSON API.",
        ))
    }

    async fn delete_hmac_key(&self, _project_id: &str, _access_id: &str) -> Result<()> {
        Err(GsutilError::command(
            "HMAC key management is only supported by the GCS JSON API.",
        ))
    }

    async fn get_hmac_key(&self, _project_id: &str, _access_id: &str) -> Result<HmacKeyMetadata> {
        Err(GsutilError::command(
            "HMAC key management is only supported by the GCS JSON API.",
        ))
    }

    async fn list_hmac_keys(
        &self,
        _project_id: &str,
        _service_account_email: Option<&str>,
        _show_deleted_keys: bool,
    ) -> Result<Vec<HmacKeyMetadata>> {
        Err(GsutilError::command(
            "HMAC key management is only supported by the GCS JSON API.",
        ))
    }

    async fn update_hmac_key(
        &self,
        _project_id: &str,
        _access_id: &str,
        _state: &str,
        _etag: Option<&str>,
    ) -> Result<HmacKeyMetadata> {
        Err(GsutilError::command(
            "HMAC key management is only supported by the GCS JSON API.",
        ))
    }

    async fn sign_url(&self, _options: &SignUrlOptions) -> Result<String> {
        Err(GsutilError::command(
            "Signed URL generation via XML API is not supported.",
        ))
    }
}

// ---------------------------------------------------------------------------
// XML Error Translation (matching BotoTranslation::_TranslateBotoException)
// ---------------------------------------------------------------------------

/// Translate an HTTP XML error response (`<Error><Code>...</Code><Message>...</Message></Error>`)
/// into the exact `GsutilError` matching `gslib/boto_translation.py::_TranslateBotoException`.
pub fn translate_xml_error(status: u16, body: &str, ctx: &ErrorContext<'_>) -> GsutilError {
    let code = extract_xml_tag(body, "Code").unwrap_or_default();
    let message = extract_xml_tag(body, "Message").unwrap_or_default();
    let body_opt = if body.trim().is_empty() {
        None
    } else {
        Some(body.to_string())
    };
    let provider = if ctx.provider.is_empty() {
        "gs"
    } else {
        ctx.provider
    };

    let err = match status {
        400 => ServiceError::bad_request(
            if code.is_empty() { "BadRequest" } else { &code },
            Some(status),
            body_opt,
        ),
        401 | 403 => ServiceError::access_denied(
            if code.is_empty() {
                "AccessDenied"
            } else {
                &code
            },
            Some(status),
            body_opt,
        ),
        404 => {
            if let Some(mut ov) = ctx.not_found_override.clone() {
                ov.status = Some(status);
                ov
            } else if let Some(bkt) = ctx.bucket_name {
                if let Some(obj) = ctx.object_name {
                    create_object_not_found(status, provider, bkt, obj, ctx.generation)
                } else {
                    create_bucket_not_found(status, provider, bkt)
                }
            } else {
                ServiceError::not_found(
                    if message.is_empty() {
                        "NotFound"
                    } else {
                        &message
                    },
                    Some(status),
                    body_opt,
                )
            }
        }
        409 => {
            if code.contains("BucketNotEmpty") {
                let bkt = ctx.bucket_name.unwrap_or("");
                ServiceError::not_empty(format!("BucketNotEmpty ({bkt})"), Some(status), body_opt)
            } else if code.contains("BucketAlreadyOwnedByYou")
                || code.contains("BucketAlreadyExists")
            {
                ServiceError::service("Bucket already exists.", Some(status), body_opt)
            } else {
                ServiceError::service(
                    if message.is_empty() {
                        "Conflict"
                    } else {
                        &message
                    },
                    Some(status),
                    body_opt,
                )
            }
        }
        410 => ServiceError::resumable_upload_start_over(
            if message.is_empty() { "Gone" } else { &message },
            Some(status),
            None,
        ),
        412 => ServiceError::precondition(
            if code.is_empty() {
                "PreconditionFailed"
            } else {
                &code
            },
            Some(status),
            body_opt,
        ),
        429 | 500..=599 => ServiceError::retryable(
            if message.is_empty() {
                format!("HTTP {status}")
            } else {
                message
            },
            Some(status),
            body_opt,
        ),
        _ => ServiceError::service(
            if message.is_empty() {
                format!("HTTP {status}")
            } else {
                message
            },
            Some(status),
            body_opt,
        ),
    };
    GsutilError::Service(err)
}

// ---------------------------------------------------------------------------
// XML Parsing & Serialization Helpers
// ---------------------------------------------------------------------------

struct ParsedListObjects {
    objects: Vec<Object>,
    prefixes: Vec<String>,
    is_truncated: bool,
    next_marker: Option<String>,
}

fn parse_list_buckets_xml(xml: &str) -> Vec<Bucket> {
    let mut buckets = Vec::new();
    for block in extract_xml_blocks(xml, "Bucket") {
        let name = extract_xml_tag(block, "Name");
        let creation = extract_xml_tag(block, "CreationDate");
        if name.is_some() {
            buckets.push(Bucket {
                name: name.clone(),
                id: name,
                time_created: creation,
                ..Default::default()
            });
        }
    }
    buckets
}

fn parse_list_objects_xml(bucket_name: &str, xml: &str) -> ParsedListObjects {
    let mut objects = Vec::new();
    for block in extract_xml_blocks(xml, "Contents") {
        let key = extract_xml_tag(block, "Key");
        let size = extract_xml_tag(block, "Size");
        let etag = extract_xml_tag(block, "ETag").map(|e| e.trim_matches('"').to_string());
        let last_mod = extract_xml_tag(block, "LastModified");
        let storage_class = extract_xml_tag(block, "StorageClass");
        let generation =
            extract_xml_tag(block, "Generation").or_else(|| extract_xml_tag(block, "VersionId"));
        if key.is_some() {
            objects.push(Object {
                bucket: Some(bucket_name.to_string()),
                name: key,
                size,
                etag,
                updated: last_mod,
                storage_class,
                generation,
                ..Default::default()
            });
        }
    }

    let mut prefixes = Vec::new();
    for block in extract_xml_blocks(xml, "CommonPrefixes") {
        if let Some(p) = extract_xml_tag(block, "Prefix") {
            prefixes.push(p);
        }
    }

    let is_truncated = extract_xml_tag(xml, "IsTruncated")
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let next_marker = extract_xml_tag(xml, "NextMarker")
        .or_else(|| extract_xml_tag(xml, "NextContinuationToken"));

    ParsedListObjects {
        objects,
        prefixes,
        is_truncated,
        next_marker,
    }
}

fn build_create_bucket_xml(metadata: Option<&Bucket>) -> String {
    let Some(m) = metadata else {
        return String::new();
    };
    if m.location.is_none() && m.storage_class.is_none() {
        return String::new();
    }
    let mut xml = String::from("<CreateBucketConfiguration>");
    if let Some(ref loc) = m.location {
        xml.push_str("<LocationConstraint>");
        xml.push_str(&escape_xml(loc));
        xml.push_str("</LocationConstraint>");
    }
    if let Some(ref sc) = m.storage_class {
        xml.push_str("<StorageClass>");
        xml.push_str(&escape_xml(sc));
        xml.push_str("</StorageClass>");
    }
    xml.push_str("</CreateBucketConfiguration>");
    xml
}

/// Serialize `BucketCors` list to GCS XML (`<Cors>`) or S3 XML (`<CORSConfiguration>`).
pub fn serialize_cors_xml(cors: &[BucketCors], provider: &str) -> String {
    if provider == "s3" {
        let mut xml = String::from("<CORSConfiguration>");
        for entry in cors {
            xml.push_str("<CORSRule>");
            for o in entry.origin.iter().flatten() {
                xml.push_str(&format!("<AllowedOrigin>{}</AllowedOrigin>", escape_xml(o)));
            }
            for m in entry.method.iter().flatten() {
                xml.push_str(&format!("<AllowedMethod>{}</AllowedMethod>", escape_xml(m)));
            }
            for h in entry.response_header.iter().flatten() {
                xml.push_str(&format!("<ExposeHeader>{}</ExposeHeader>", escape_xml(h)));
            }
            if let Some(age) = entry.max_age_seconds {
                xml.push_str(&format!("<MaxAgeSeconds>{age}</MaxAgeSeconds>"));
            }
            xml.push_str("</CORSRule>");
        }
        xml.push_str("</CORSConfiguration>");
        xml
    } else {
        let mut xml = String::from("<Cors>");
        for entry in cors {
            xml.push_str("<CorsConfig>");
            if let Some(ref origins) = entry.origin {
                xml.push_str("<Origins>");
                for o in origins {
                    xml.push_str(&format!("<Origin>{}</Origin>", escape_xml(o)));
                }
                xml.push_str("</Origins>");
            }
            if let Some(ref methods) = entry.method {
                xml.push_str("<Methods>");
                for m in methods {
                    xml.push_str(&format!("<Method>{}</Method>", escape_xml(m)));
                }
                xml.push_str("</Methods>");
            }
            if let Some(ref hdrs) = entry.response_header {
                xml.push_str("<ResponseHeaders>");
                for h in hdrs {
                    xml.push_str(&format!(
                        "<ResponseHeader>{}</ResponseHeader>",
                        escape_xml(h)
                    ));
                }
                xml.push_str("</ResponseHeaders>");
            }
            if let Some(age) = entry.max_age_seconds {
                xml.push_str(&format!("<MaxAgeSec>{age}</MaxAgeSec>"));
            }
            xml.push_str("</CorsConfig>");
        }
        xml.push_str("</Cors>");
        xml
    }
}

/// Serialize `BucketLifecycle` to GCS/S3 XML `<LifecycleConfiguration>`.
pub fn serialize_lifecycle_xml(lifecycle: &BucketLifecycle) -> String {
    let mut xml = String::from("<LifecycleConfiguration>");
    for rule in lifecycle.rule.iter().flatten() {
        xml.push_str("<Rule>");
        if let Some(ref action) = rule.action {
            let t = action.action_type.as_deref().unwrap_or("Delete");
            if t.eq_ignore_ascii_case("SetStorageClass") {
                let sc = action.storage_class.as_deref().unwrap_or("NEARLINE");
                xml.push_str(&format!(
                    "<Action><SetStorageClass>{}</SetStorageClass></Action>",
                    escape_xml(sc)
                ));
            } else {
                xml.push_str("<Action><Delete/></Action>");
            }
        }
        if let Some(ref cond) = rule.condition {
            xml.push_str("<Condition>");
            if let Some(age) = cond.age {
                xml.push_str(&format!("<Age>{age}</Age>"));
            }
            if let Some(ref cb) = cond.created_before {
                xml.push_str(&format!(
                    "<CreatedBefore>{}</CreatedBefore>",
                    escape_xml(cb)
                ));
            }
            if let Some(is_live) = cond.is_live {
                xml.push_str(&format!("<IsLive>{is_live}</IsLive>"));
            }
            if let Some(nnv) = cond.num_newer_versions {
                xml.push_str(&format!(
                    "<NumberOfNewerVersions>{nnv}</NumberOfNewerVersions>"
                ));
            }
            xml.push_str("</Condition>");
        }
        xml.push_str("</Rule>");
    }
    xml.push_str("</LifecycleConfiguration>");
    xml
}

/// Parse a GCS XML `<LifecycleConfiguration>` into a `BucketLifecycle` model.
pub fn parse_lifecycle_xml(xml: &str) -> BucketLifecycle {
    let mut rules = Vec::new();
    for block in extract_xml_blocks(xml, "Rule") {
        let action = if let Some(sc) = extract_xml_tag(block, "SetStorageClass") {
            Some(LifecycleAction {
                action_type: Some("SetStorageClass".to_string()),
                storage_class: Some(sc),
            })
        } else if block.contains("<Delete") {
            Some(LifecycleAction {
                action_type: Some("Delete".to_string()),
                storage_class: None,
            })
        } else {
            None
        };
        let cond = LifecycleCondition {
            age: extract_xml_tag(block, "Age").and_then(|s| s.parse().ok()),
            created_before: extract_xml_tag(block, "CreatedBefore"),
            is_live: extract_xml_tag(block, "IsLive").and_then(|s| s.parse().ok()),
            num_newer_versions: extract_xml_tag(block, "NumberOfNewerVersions")
                .and_then(|s| s.parse().ok()),
            ..Default::default()
        };
        rules.push(LifecycleRule {
            action,
            condition: Some(cond),
        });
    }
    BucketLifecycle { rule: Some(rules) }
}

/// Parse GCS XML `<AccessControlList>` entries into `BucketAccessControl` list.
pub fn parse_acl_xml(xml: &str) -> Vec<BucketAccessControl> {
    let mut entries = Vec::new();
    for block in extract_xml_blocks(xml, "Entry") {
        let role = extract_xml_tag(block, "Permission").map(|p| match p.as_str() {
            "FULL_CONTROL" => "OWNER".to_string(),
            "READ" => "READER".to_string(),
            "WRITE" => "WRITER".to_string(),
            other => other.to_string(),
        });
        let email = extract_xml_tag(block, "EmailAddress");
        let entity_id = extract_xml_tag(block, "ID");
        let domain = extract_xml_tag(block, "Domain");
        let entity = if block.contains("AllUsers") {
            Some("allUsers".to_string())
        } else if block.contains("AllAuthenticatedUsers") {
            Some("allAuthenticatedUsers".to_string())
        } else if let Some(ref e) = email {
            if block.contains("GroupByEmail") {
                Some(format!("group-{e}"))
            } else {
                Some(format!("user-{e}"))
            }
        } else if let Some(ref d) = domain {
            Some(format!("domain-{d}"))
        } else {
            entity_id.as_ref().map(|id| format!("user-{id}"))
        };
        if entity.is_some() || role.is_some() {
            entries.push(BucketAccessControl {
                entity,
                role,
                email,
                entity_id,
                domain,
                ..Default::default()
            });
        }
    }
    entries
}

fn object_from_xml_headers(
    bucket_name: &str,
    object_name: &str,
    headers: &HeaderMap,
    prefix: &str,
) -> Object {
    let mut custom_meta = BTreeMap::new();
    let meta_prefix = format!("{prefix}meta-");
    for (k, v) in headers {
        let lower = k.as_str().to_ascii_lowercase();
        if let Some(meta_key) = lower.strip_prefix(&meta_prefix) {
            if let Ok(s) = v.to_str() {
                custom_meta.insert(meta_key.to_string(), s.to_string());
            }
        }
    }

    let mut crc32c = None;
    let mut md5_hash = None;
    for val in headers.get_all("x-goog-hash") {
        if let Ok(s) = val.to_str() {
            for part in s.split(',') {
                let p = part.trim();
                if let Some(c) = p.strip_prefix("crc32c=") {
                    crc32c = Some(c.to_string());
                } else if let Some(m) = p.strip_prefix("md5=") {
                    md5_hash = Some(m.to_string());
                }
            }
        }
    }

    Object {
        bucket: Some(bucket_name.to_string()),
        name: Some(object_name.to_string()),
        size: header_str(headers, "content-length"),
        content_type: header_str(headers, "content-type"),
        cache_control: header_str(headers, "cache-control"),
        content_disposition: header_str(headers, "content-disposition"),
        content_encoding: header_str(headers, "content-encoding"),
        content_language: header_str(headers, "content-language"),
        etag: header_str(headers, "etag").map(|e| e.trim_matches('"').to_string()),
        generation: header_str(headers, "x-goog-generation")
            .or_else(|| header_str(headers, "x-amz-version-id")),
        metageneration: header_str(headers, "x-goog-metageneration"),
        storage_class: header_str(headers, &format!("{prefix}storage-class")),
        crc32c,
        md5_hash,
        metadata: if custom_meta.is_empty() {
            None
        } else {
            Some(custom_meta)
        },
        ..Default::default()
    }
}

fn apply_object_metadata_headers(headers: &mut HeaderMap, meta: &Object, prefix: &str) {
    if let Some(ref ct) = meta.content_type {
        insert_hdr(headers, "content-type", ct);
    }
    if let Some(ref cc) = meta.cache_control {
        insert_hdr(headers, "cache-control", cc);
    }
    if let Some(ref cd) = meta.content_disposition {
        insert_hdr(headers, "content-disposition", cd);
    }
    if let Some(ref ce) = meta.content_encoding {
        insert_hdr(headers, "content-encoding", ce);
    }
    if let Some(ref cl) = meta.content_language {
        insert_hdr(headers, "content-language", cl);
    }
    if let Some(ref sc) = meta.storage_class {
        insert_hdr(headers, &format!("{prefix}storage-class"), sc);
    }
    if let Some(ref custom) = meta.metadata {
        for (k, v) in custom {
            insert_hdr(headers, &format!("{prefix}meta-{k}"), v);
        }
    }
}

fn apply_xml_preconditions(
    headers: &mut HeaderMap,
    preconditions: Option<&Preconditions>,
    prefix: &str,
) {
    if let Some(pre) = preconditions {
        if let Some(g) = pre.gen_match {
            insert_hdr(
                headers,
                &format!("{prefix}if-generation-match"),
                &g.to_string(),
            );
        }
        if let Some(mg) = pre.meta_gen_match {
            insert_hdr(
                headers,
                &format!("{prefix}if-metageneration-match"),
                &mg.to_string(),
            );
        }
    }
}

fn insert_hdr(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(k), Ok(v)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        headers.insert(k, v);
    }
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(unescape_xml(&xml[start..end]))
}

fn extract_xml_blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut blocks = Vec::new();
    let mut rest = xml;
    while let Some(start_idx) = rest.find(&open) {
        let after_open = &rest[start_idx + open.len()..];
        if let Some(end_idx) = after_open.find(&close) {
            blocks.push(&after_open[..end_idx]);
            rest = &after_open[end_idx + close.len()..];
        } else {
            break;
        }
    }
    blocks
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn percent_encode_segment(input: &str) -> String {
    percent_encode_uri(input)
}

fn encode_object_path(object_name: &str) -> String {
    object_name
        .split('/')
        .map(percent_encode_uri)
        .collect::<Vec<_>>()
        .join("/")
}

fn percent_encode_uri(input: &str) -> String {
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
