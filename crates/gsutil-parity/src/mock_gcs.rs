//! In-process deterministic Mock GCS JSON v1 (+ XML/S3) HTTP/HTTPS server for hermetic testing.
//!
//! Features:
//! - Both plain HTTP (`start()`) and self-signed localhost HTTPS (`start_tls()`) via
//!   `rcgen` + `tokio-rustls`, enabling true differential testing against native `/usr/bin/gsutil`.
//! - True JSON `PATCH` merge-with-`null` deletion for bucket configs, labels, and object metadata.
//! - `list_objects` pagination (`maxResults` / `pageToken` / `nextPageToken`).
//! - Multi-chunk `308 Resume Incomplete` resumable uploads + `Content-Range: bytes */*` probes
//!   + optional `fault-resumable-drop` first-chunk disconnect injection.
//! - `rewriteTo` applying `req.body` (`storageClass`, `contentType`, `metadata`) + multi-step
//!   `rewriteToken` when `maxBytesRewrittenPerCall` is set.
//! - Transparent gzip decompression on `GET ?alt=media` when `content_encoding == "gzip"` and
//!   `Accept-Encoding: gzip` is absent (matching real GCS behavior!).
//! - Preconditions (`ifGenerationMatch`, `ifMetagenerationMatch` -> `412`), UBLA enforcement
//!   (`400` on ACL mutations when UBLA is enabled), retention lock & object holds (`403`).
//! - Endpoints: `lockRetentionPolicy`, `hmacKeys`, `serviceAccount`, `o/watch`, `channels/stop`,
//!   `o/{obj}/iam`, bucket/defaultObject/object `acl`, `notificationConfigs/{id}`, plus basic
//!   Mock XML/S3 routes (`GET /`, `GET /{bucket}`, `HEAD/GET/PUT/DELETE /{bucket}/{object}`).

use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use flate2::read::GzDecoder;
use md5::{Digest, Md5};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

fn fmt_gcs_ts(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Stored mock object version.
#[derive(Debug, Clone)]
pub struct MockObject {
    pub bucket: String,
    pub name: String,
    pub generation: u64,
    pub metageneration: u64,
    pub content_type: String,
    pub cache_control: Option<String>,
    pub content_disposition: Option<String>,
    pub content_encoding: Option<String>,
    pub content_language: Option<String>,
    pub custom_time: Option<String>,
    pub temporary_hold: Option<bool>,
    pub event_based_hold: Option<bool>,
    pub data: Vec<u8>,
    pub time_created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: bool,
    pub storage_class: String,
    pub metadata: BTreeMap<String, String>,
    pub acl: Vec<Value>,
    pub iam_policy: Value,
    pub customer_encryption: Option<(String, String)>,
}

impl MockObject {
    pub fn crc32c_b64(&self) -> String {
        let crc = crc32c::crc32c(&self.data);
        base64::engine::general_purpose::STANDARD.encode(crc.to_be_bytes())
    }

    pub fn md5_b64(&self) -> String {
        let mut hasher = Md5::new();
        hasher.update(&self.data);
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    }

    pub fn md5_hex(&self) -> String {
        let mut hasher = Md5::new();
        hasher.update(&self.data);
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub fn to_json(&self) -> Value {
        self.to_json_with_key(None)
    }

    pub fn to_json_with_key(&self, provided_key_sha256: Option<&str>) -> Value {
        let include_hashes = match self.customer_encryption {
            Some((_, ref expected_sha)) => provided_key_sha256 == Some(expected_sha.as_str()),
            None => true,
        };
        let mut obj = json!({
            "kind": "storage#object",
            "id": format!("{}/{}/{}", self.bucket, self.name, self.generation),
            "name": self.name,
            "bucket": self.bucket,
            "generation": self.generation.to_string(),
            "metageneration": self.metageneration.to_string(),
            "contentType": self.content_type,
            "mediaLink": format!("/download/storage/v1/b/{}/o/{}?generation={}&alt=media", self.bucket, self.name, self.generation),
            "timeCreated": fmt_gcs_ts(self.time_created),
            "updated": fmt_gcs_ts(self.updated),
            "timeStorageClassUpdated": fmt_gcs_ts(self.time_created),
            "storageClass": self.storage_class,
            "size": self.data.len().to_string(),
            "etag": format!("etag-{}-{}", self.generation, self.metageneration),
        });
        if include_hashes {
            obj["md5Hash"] = json!(self.md5_b64());
            obj["crc32c"] = json!(self.crc32c_b64());
        }
        if let Some(ref v) = self.cache_control {
            obj["cacheControl"] = json!(v);
        }
        if let Some(ref v) = self.content_disposition {
            obj["contentDisposition"] = json!(v);
        }
        if let Some(ref v) = self.content_encoding {
            obj["contentEncoding"] = json!(v);
        }
        if let Some(ref v) = self.content_language {
            obj["contentLanguage"] = json!(v);
        }
        if let Some(ref v) = self.custom_time {
            obj["customTime"] = json!(v);
        }
        if let Some(v) = self.temporary_hold {
            obj["temporaryHold"] = json!(v);
        }
        if let Some(v) = self.event_based_hold {
            obj["eventBasedHold"] = json!(v);
        }
        if !self.metadata.is_empty() {
            obj["metadata"] = json!(self.metadata);
        }
        if !self.acl.is_empty() {
            obj["acl"] = json!(self.acl);
        }
        if let Some((ref alg, ref sha)) = self.customer_encryption {
            obj["customerEncryption"] = json!({
                "encryptionAlgorithm": alg,
                "keySha256": sha,
            });
        }
        if self.deleted {
            obj["timeDeleted"] = json!(self.updated.to_rfc3339());
        }
        obj
    }
}

/// Stored mock bucket.
#[derive(Debug, Clone)]
pub struct MockBucket {
    pub name: String,
    pub location: String,
    pub storage_class: String,
    pub versioning_enabled: bool,
    pub metageneration: u64,
    pub time_created: DateTime<Utc>,
    pub objects: Vec<MockObject>,
    pub extra_fields: BTreeMap<String, Value>,
    pub acl: Vec<Value>,
    pub default_object_acl: Vec<Value>,
    pub iam_policy: Value,
    pub notifications: Vec<Value>,
}

impl MockBucket {
    pub fn ubla_enabled(&self) -> bool {
        if let Some(iam_cfg) = self.extra_fields.get("iamConfiguration") {
            let ubla = iam_cfg
                .get("uniformBucketLevelAccess")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let bpo = iam_cfg
                .get("bucketPolicyOnly")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            return ubla || bpo;
        }
        false
    }

    pub fn retention_locked(&self) -> bool {
        self.extra_fields
            .get("retentionPolicy")
            .and_then(|v| v.get("isLocked"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    pub fn to_json(&self) -> Value {
        let mut obj = json!({
            "kind": "storage#bucket",
            "id": self.name,
            "name": self.name,
            "projectNumber": "1234567890",
            "location": self.location,
            "locationType": "multi-region",
            "storageClass": self.storage_class,
            "timeCreated": fmt_gcs_ts(self.time_created),
            "updated": fmt_gcs_ts(self.time_created),
            "metageneration": self.metageneration.to_string(),
            "versioning": { "enabled": self.versioning_enabled },
            "etag": format!("CAE={}", self.metageneration),
        });
        if !self.acl.is_empty() {
            obj["acl"] = json!(self.acl);
        }
        if !self.default_object_acl.is_empty() {
            obj["defaultObjectAcl"] = json!(self.default_object_acl);
        }
        if let Some(map) = obj.as_object_mut() {
            for (k, v) in &self.extra_fields {
                if v.is_null() {
                    map.remove(k);
                } else {
                    map.insert(k.clone(), v.clone());
                }
            }
        }
        obj
    }
}

#[derive(Debug, Clone)]
pub struct ResumableSession {
    pub bucket: String,
    pub name: String,
    pub content_type: String,
    pub content_encoding: Option<String>,
    pub metadata: BTreeMap<String, String>,
    pub accumulated: Vec<u8>,
    pub dropped_once: bool,
    pub customer_encryption: Option<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct RewriteSession {
    pub src_bucket: String,
    pub src_object: String,
    pub dst_bucket: String,
    pub dst_object: String,
    pub override_storage_class: Option<String>,
    pub override_content_type: Option<String>,
    pub override_metadata: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Default)]
pub struct MockGcsState {
    pub buckets: BTreeMap<String, MockBucket>,
    pub next_generation: u64,
    pub resumable_sessions: BTreeMap<String, ResumableSession>,
    pub rewrite_sessions: BTreeMap<String, RewriteSession>,
    pub hmac_keys: BTreeMap<String, Value>,
    pub watch_channels: BTreeMap<String, Value>,
    pub request_log: Vec<String>,
    /// Records every `Content-Range` header seen on resumable `PUT` requests.
    pub resumable_put_ranges: Vec<String>,
}

impl MockGcsState {
    pub fn new() -> Self {
        Self {
            buckets: BTreeMap::new(),
            next_generation: 1_700_000_000_000_000,
            resumable_sessions: BTreeMap::new(),
            rewrite_sessions: BTreeMap::new(),
            hmac_keys: BTreeMap::new(),
            watch_channels: BTreeMap::new(),
            request_log: Vec::new(),
            resumable_put_ranges: Vec::new(),
        }
    }

    pub fn next_gen(&mut self) -> u64 {
        self.next_generation += 1;
        self.next_generation
    }

    pub fn create_bucket(&mut self, name: &str, location: &str, storage_class: &str) -> bool {
        if self.buckets.contains_key(name) {
            return false;
        }
        let mut default_extra = BTreeMap::new();
        default_extra.insert(
            "iamConfiguration".into(),
            json!({
                "uniformBucketLevelAccess": { "enabled": false },
                "bucketPolicyOnly": { "enabled": false },
                "publicAccessPrevention": "inherited"
            }),
        );
        self.buckets.insert(
            name.to_string(),
            MockBucket {
                name: name.to_string(),
                location: location.to_ascii_uppercase(),
                storage_class: storage_class.to_ascii_uppercase(),
                versioning_enabled: false,
                metageneration: 1,
                time_created: Utc::now(),
                objects: Vec::new(),
                extra_fields: default_extra,
                acl: vec![json!({
                    "kind": "storage#bucketAccessControl",
                    "bucket": name,
                    "entity": "project-owners-123",
                    "role": "OWNER"
                })],
                default_object_acl: vec![json!({
                    "kind": "storage#objectAccessControl",
                    "bucket": name,
                    "entity": "project-owners-123",
                    "role": "OWNER"
                })],
                iam_policy: json!({
                    "kind": "storage#policy",
                    "resourceId": format!("projects/_/buckets/{name}"),
                    "version": 1,
                    "etag": "CAE=",
                    "bindings": [{
                        "role": "roles/storage.legacyBucketOwner",
                        "members": ["projectOwner:mock-project-123"]
                    }]
                }),
                notifications: Vec::new(),
            },
        );
        true
    }

    pub fn put_object(
        &mut self,
        bucket: &str,
        name: &str,
        data: Vec<u8>,
        content_type: &str,
    ) -> Option<MockObject> {
        self.put_object_full(
            bucket,
            name,
            data,
            content_type,
            None,
            BTreeMap::new(),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn put_object_full(
        &mut self,
        bucket: &str,
        name: &str,
        data: Vec<u8>,
        content_type: &str,
        content_encoding: Option<String>,
        metadata: BTreeMap<String, String>,
        storage_class_override: Option<String>,
    ) -> Option<MockObject> {
        let gen = self.next_gen();
        let b = self.buckets.get_mut(bucket)?;
        let now = Utc::now();
        if b.versioning_enabled {
            for obj in &mut b.objects {
                if obj.name == name && !obj.deleted {
                    obj.deleted = true;
                    obj.updated = now;
                }
            }
        } else {
            b.objects.retain(|o| o.name != name);
        }
        let sc = storage_class_override.unwrap_or_else(|| b.storage_class.clone());
        let obj = MockObject {
            bucket: bucket.to_string(),
            name: name.to_string(),
            generation: gen,
            metageneration: 1,
            content_type: content_type.to_string(),
            cache_control: None,
            content_disposition: None,
            content_encoding,
            content_language: None,
            custom_time: None,
            temporary_hold: None,
            event_based_hold: None,
            data,
            time_created: now,
            updated: now,
            deleted: false,
            storage_class: sc,
            metadata,
            acl: vec![json!({
                "kind": "storage#objectAccessControl",
                "bucket": bucket,
                "object": name,
                "entity": "project-owners-123",
                "role": "OWNER"
            })],
            iam_policy: json!({
                "kind": "storage#policy",
                "resourceId": format!("projects/_/buckets/{bucket}/objects/{name}"),
                "version": 1,
                "etag": "CAE=",
                "bindings": [{
                    "role": "roles/storage.legacyObjectOwner",
                    "members": ["projectOwner:mock-project-123"]
                }]
            }),
            customer_encryption: None,
        };
        b.objects.push(obj.clone());
        Some(obj)
    }
}

/// Running handle for the in-process Mock GCS server (HTTP or self-signed HTTPS).
pub struct MockGcsServer {
    pub addr: SocketAddr,
    pub is_tls: bool,
    pub ca_cert_pem: Option<String>,
    pub state: Arc<Mutex<MockGcsState>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl MockGcsServer {
    /// Start plain HTTP listener on `127.0.0.1:0`.
    pub async fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(MockGcsState::new()));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, _)) => {
                                let st = Arc::clone(&state_clone);
                                tokio::spawn(async move {
                                    let _ = handle_connection(stream, st, addr, false).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        Ok(Self {
            addr,
            is_tls: false,
            ca_cert_pem: None,
            state,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Start self-signed HTTPS listener on `127.0.0.1:0` so native `/usr/bin/gsutil` v5.38
    /// and Rust `gsutil` can both run true differential tests over TLS.
    pub async fn start_tls() -> std::io::Result<Self> {
        Self::start_tls_on_port(0).await
    }

    /// Start self-signed HTTPS listener on `127.0.0.1:<port>` (pass `0` for OS-assigned port).
    pub async fn start_tls_on_port(port: u16) -> std::io::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Generate a self-signed root CA + a leaf server cert signed by that CA
        // so both OpenSSL (Python httplib2) and rustls (Rust reqwest) verify cleanly.
        let mut ca_params = rcgen::CertificateParams::new(Vec::new())
            .map_err(|e| std::io::Error::other(format!("rcgen ca params error: {e}")))?;
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "gsutil-parity-mock-ca");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        ca_params.use_authority_key_identifier_extension = true;
        let ca_key = rcgen::KeyPair::generate()
            .map_err(|e| std::io::Error::other(format!("rcgen ca keygen error: {e}")))?;
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .map_err(|e| std::io::Error::other(format!("rcgen ca self_signed error: {e}")))?;
        let ca_pem = ca_cert.pem();

        let mut leaf_params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
                .map_err(|e| std::io::Error::other(format!("rcgen leaf params error: {e}")))?;
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "127.0.0.1");
        leaf_params.is_ca = rcgen::IsCa::NoCa;
        leaf_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.use_authority_key_identifier_extension = true;
        let leaf_key = rcgen::KeyPair::generate()
            .map_err(|e| std::io::Error::other(format!("rcgen leaf keygen error: {e}")))?;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .map_err(|e| std::io::Error::other(format!("rcgen leaf signed_by error: {e}")))?;
        let certs = vec![leaf_cert.der().clone(), ca_cert.der().clone()];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
        );

        let tls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| std::io::Error::other(format!("rustls ServerConfig error: {e}")))?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));

        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(MockGcsState::new()));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((tcp, _)) => {
                                let st = Arc::clone(&state_clone);
                                let acc = acceptor.clone();
                                tokio::spawn(async move {
                                    if let Ok(tls_stream) = acc.accept(tcp).await {
                                        let _ = handle_connection(tls_stream, st, addr, true).await;
                                    }
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        Ok(Self {
            addr,
            is_tls: true,
            ca_cert_pem: Some(ca_pem),
            state,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    pub fn scheme(&self) -> &'static str {
        if self.is_tls {
            "https"
        } else {
            "http"
        }
    }

    pub fn base_url(&self) -> String {
        format!("{}://{}", self.scheme(), self.addr)
    }

    /// Seed a bucket directly in memory.
    pub fn seed_bucket(&self, name: &str) {
        let mut st = self.state.lock().expect("lock poisoned");
        st.create_bucket(name, "US", "STANDARD");
    }

    /// Seed an object directly in memory.
    pub fn seed_object(&self, bucket: &str, name: &str, data: &[u8]) -> MockObject {
        let mut st = self.state.lock().expect("lock poisoned");
        st.create_bucket(bucket, "US", "STANDARD");
        st.put_object(bucket, name, data.to_vec(), "application/octet-stream")
            .expect("bucket exists")
    }

    /// Seed an object with `Content-Encoding: gzip` and custom metadata.
    pub fn seed_gzip_object(&self, bucket: &str, name: &str, gzipped_bytes: &[u8]) -> MockObject {
        let mut st = self.state.lock().expect("lock poisoned");
        st.create_bucket(bucket, "US", "STANDARD");
        st.put_object_full(
            bucket,
            name,
            gzipped_bytes.to_vec(),
            "text/plain",
            Some("gzip".into()),
            BTreeMap::new(),
            None,
        )
        .expect("bucket exists")
    }

    /// Write a `.boto` configuration file targeting this mock server.
    /// If TLS is enabled, writes `ca.pem` next to `path` and configures `ca_certificates_file`.
    pub fn write_boto_config(&self, path: &Path) -> std::io::Result<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("/tmp"));
        let ca_line = if let Some(ref pem) = self.ca_cert_pem {
            let ca_path = parent.join("mock_ca.pem");
            std::fs::write(&ca_path, pem)?;
            format!(
                "ca_certificates_file = {}\nhttps_validate_certificates = False\n",
                ca_path.display()
            )
        } else {
            String::new()
        };
        let host = if self.is_tls {
            self.addr.ip().to_string()
        } else {
            format!("http://{}", self.addr.ip())
        };
        let contents = format!(
            "[Boto]\n\
             {ca_line}\
             num_retries = 1\n\
             [Credentials]\n\
             use_client_certificate = False\n\
             gs_host = {host}\n\
             gs_json_host = {host}\n\
             gs_port = {port}\n\
             gs_json_port = {port}\n\
             [GSUtil]\n\
             prefer_api = json\n\
             default_project_id = mock-project-123\n\
             state_dir = {state_dir}\n",
            ca_line = ca_line,
            host = host,
            port = self.addr.port(),
            state_dir = parent.display(),
        );
        std::fs::write(path, contents)
    }
}

impl Drop for MockGcsServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

struct HttpRequest {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    reason: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(status: u16, reason: &'static str, val: Value) -> Self {
        let body = serde_json::to_vec(&val).unwrap_or_default();
        Self {
            status,
            reason,
            headers: vec![(
                "Content-Type".into(),
                "application/json; charset=UTF-8".into(),
            )],
            body,
        }
    }

    fn xml(status: u16, reason: &'static str, xml_body: String) -> Self {
        Self {
            status,
            reason,
            headers: vec![(
                "Content-Type".into(),
                "application/xml; charset=UTF-8".into(),
            )],
            body: xml_body.into_bytes(),
        }
    }

    fn error(status: u16, reason: &'static str, message: &str, err_reason: &str) -> Self {
        Self::json(
            status,
            reason,
            json!({
                "error": {
                    "code": status,
                    "message": message,
                    "errors": [{
                        "message": message,
                        "domain": "global",
                        "reason": err_reason,
                    }]
                }
            }),
        )
    }

    fn empty(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
}

async fn read_request<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
) -> std::io::Result<Option<HttpRequest>> {
    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line).await?;
    if n == 0 {
        return Ok(None);
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(None);
    }
    let method = parts[0].to_string();
    let target = parts[1].to_string();

    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let mut body = Vec::new();
    if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line).await?;
            let hex_size = size_line.trim().split(';').next().unwrap_or("0");
            let chunk_len = usize::from_str_radix(hex_size, 16).unwrap_or(0);
            if chunk_len == 0 {
                let mut trailer = String::new();
                let _ = reader.read_line(&mut trailer).await;
                break;
            }
            let mut chunk = vec![0u8; chunk_len];
            reader.read_exact(&mut chunk).await?;
            body.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf).await;
        }
    } else if let Some(len_str) = headers.get("content-length") {
        if let Ok(len) = len_str.parse::<usize>() {
            body.resize(len, 0);
            reader.read_exact(&mut body).await?;
        }
    }

    Ok(Some(HttpRequest {
        method,
        target,
        headers,
        body,
    }))
}

async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    state: Arc<Mutex<MockGcsState>>,
    addr: SocketAddr,
    is_tls: bool,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let Some(req) = read_request(&mut reader).await? else {
        return Ok(());
    };

    // Slow-streaming media download for deterministic SIGINT testing:
    // GET /storage/v1/b/slow-bkt/o/{obj}?alt=media streams 4 KiB every 150ms.
    let (req_path, req_query) = parse_query(&req.target);
    if req.method == "GET"
        && req_query.get("alt").map(String::as_str) == Some("media")
        && (req_path.starts_with("/storage/v1/b/slow-bkt/o/")
            || req_path.starts_with("/download/storage/v1/b/slow-bkt/o/"))
    {
        let total = 4 * 1024 * 100usize; // 400 KiB over ~15s
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n"
        );
        let mut inner = reader.into_inner();
        inner.write_all(head.as_bytes()).await?;
        inner.flush().await?;
        let chunk = vec![0x5Au8; 4096];
        for _ in 0..100 {
            if inner.write_all(&chunk).await.is_err() {
                break;
            }
            let _ = inner.flush().await;
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        return Ok(());
    }

    let resp = route_request(req, &state, addr, is_tls);

    let mut head = format!("HTTP/1.1 {} {}\r\n", resp.status, resp.reason);
    let mut has_content_length = false;
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        head.push_str(&format!("{}: {}\r\n", k, v));
    }
    if !has_content_length {
        head.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");

    let mut inner = reader.into_inner();
    inner.write_all(head.as_bytes()).await?;
    inner.write_all(&resp.body).await?;
    inner.flush().await?;
    Ok(())
}

fn check_fault_bucket(bucket: &str) -> Option<HttpResponse> {
    match bucket {
        "fault-403" => Some(HttpResponse::error(
            403,
            "Forbidden",
            "Caller does not have storage.objects.list access to the Google Cloud Storage bucket.",
            "forbidden",
        )),
        "fault-404" => Some(HttpResponse::error(
            404,
            "Not Found",
            "The specified bucket does not exist.",
            "notFound",
        )),
        "fault-409" => Some(HttpResponse::error(
            409,
            "Conflict",
            "Your previous request to create the named bucket succeeded and you already own it.",
            "conflict",
        )),
        "fault-412" => Some(HttpResponse::error(
            412,
            "Precondition Failed",
            "At least one of the pre-conditions you specified did not hold.",
            "conditionNotMet",
        )),
        "fault-500" => Some(HttpResponse::error(
            500,
            "Internal Server Error",
            "Backend Error",
            "backendError",
        )),
        "fault-503" => Some(HttpResponse::error(
            503,
            "Service Unavailable",
            "Service Unavailable",
            "backendError",
        )),
        _ => None,
    }
}

fn parse_query(target: &str) -> (String, BTreeMap<String, String>) {
    let full = format!("http://localhost{}", target);
    if let Ok(parsed) = url::Url::parse(&full) {
        let path = parsed.path().to_string();
        let params: BTreeMap<String, String> = parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        (path, params)
    } else {
        (target.to_string(), BTreeMap::new())
    }
}

fn pct_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("k={}", s).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| s.to_string())
}

/// True JSON Merge Patch (RFC 7396) helper: merges `patch` into `target`, deleting keys set to `null`.
fn merge_json_patch(target: &mut Value, patch: &Value) {
    if let (Some(t_map), Some(p_map)) = (target.as_object_mut(), patch.as_object()) {
        for (k, v) in p_map {
            if v.is_null() {
                t_map.remove(k);
            } else if v.is_object() {
                let entry = t_map.entry(k.clone()).or_insert_with(|| json!({}));
                if !entry.is_object() {
                    *entry = json!({});
                }
                merge_json_patch(entry, v);
            } else {
                t_map.insert(k.clone(), v.clone());
            }
        }
    } else {
        *target = patch.clone();
    }
}

fn route_request(
    req: HttpRequest,
    state: &Arc<Mutex<MockGcsState>>,
    addr: SocketAddr,
    is_tls: bool,
) -> HttpResponse {
    let (path, query) = parse_query(&req.target);
    {
        let mut st = state.lock().expect("lock poisoned");
        st.request_log
            .push(format!("{} {}", req.method, req.target));
    }

    if path == "/healthz" {
        return HttpResponse::json(200, "OK", json!({"status": "ok"}));
    }

    // Mock OAuth2 token endpoint for ADC authorized_user / SA credentials
    if (path == "/oauth2/token" || path == "/token") && req.method == "POST" {
        return HttpResponse::json(
            200,
            "OK",
            json!({
                "access_token": "mock-parity-token",
                "expires_in": 3600,
                "token_type": "Bearer"
            }),
        );
    }

    // Mock GCE metadata server endpoints
    if path.starts_with("/computeMetadata/v1") {
        let mut resp = if path.ends_with("/token") {
            HttpResponse::json(
                200,
                "OK",
                json!({
                    "access_token": "mock-parity-token",
                    "expires_in": 3600,
                    "token_type": "Bearer"
                }),
            )
        } else if path.ends_with("/email") {
            HttpResponse {
                status: 200,
                reason: "OK",
                headers: vec![("Content-Type".into(), "text/plain".into())],
                body: b"mock@mock-project-123.iam.gserviceaccount.com".to_vec(),
            }
        } else {
            HttpResponse {
                status: 200,
                reason: "OK",
                headers: vec![("Content-Type".into(), "text/plain".into())],
                body: b"default/\n".to_vec(),
            }
        };
        resp.headers
            .push(("Metadata-Flavor".into(), "Google".into()));
        return resp;
    }

    // Download endpoints: /download/storage/v1/b/{bucket}/o/{object}
    if let Some(rest) = path.strip_prefix("/download/storage/v1/b/") {
        return handle_bucket_json_routes(&req, rest, &query, state);
    }

    // Upload endpoints: /upload/storage/v1/b/{bucket}/o
    if let Some(rest) = path.strip_prefix("/upload/storage/v1/b/") {
        if let Some(bucket) = rest.strip_suffix("/o") {
            let bucket = pct_decode(bucket);
            if let Some(fault) = check_fault_bucket(&bucket) {
                return fault;
            }
            return handle_upload(&req, &bucket, &query, state, addr, is_tls);
        }
    }

    // Projects endpoints: serviceAccount & hmacKeys
    if let Some(rest) = path.strip_prefix("/storage/v1/projects/") {
        return handle_projects(&req, rest, &query, state);
    }

    // Channels stop: POST /storage/v1/channels/stop
    if path == "/storage/v1/channels/stop" && req.method == "POST" {
        let body_val: Value = serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
        let id = body_val.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let mut st = state.lock().expect("lock poisoned");
        st.watch_channels.remove(id);
        return HttpResponse::empty(204, "No Content");
    }

    // Buckets collection: /storage/v1/b
    if path == "/storage/v1/b" {
        return match req.method.as_str() {
            "GET" => {
                let st = state.lock().expect("lock poisoned");
                let items: Vec<Value> = st.buckets.values().map(|b| b.to_json()).collect();
                HttpResponse::json(
                    200,
                    "OK",
                    json!({"kind": "storage#buckets", "items": items}),
                )
            }
            "POST" => {
                let body_val: Value =
                    serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
                let name = body_val
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if let Some(fault) = check_fault_bucket(&name) {
                    return fault;
                }
                let location = body_val
                    .get("location")
                    .and_then(|v| v.as_str())
                    .unwrap_or("US");
                let sc = body_val
                    .get("storageClass")
                    .and_then(|v| v.as_str())
                    .unwrap_or("STANDARD");
                let mut st = state.lock().expect("lock poisoned");
                if !st.create_bucket(&name, location, sc) {
                    return HttpResponse::error(
                        409,
                        "Conflict",
                        &format!(
                            "You already own this bucket. Please select another name. ({name} already exists)"
                        ),
                        "conflict",
                    );
                }
                if let Some(b) = st.buckets.get_mut(&name) {
                    if let Some(map) = body_val.as_object() {
                        for (k, v) in map {
                            if k == "versioning" {
                                if let Some(en) = v.get("enabled").and_then(|x| x.as_bool()) {
                                    b.versioning_enabled = en;
                                }
                            } else if !matches!(k.as_str(), "name" | "location" | "storageClass") {
                                let mut val = v.clone();
                                if k == "retentionPolicy" {
                                    if let Some(rp) = val.as_object_mut() {
                                        if !rp.contains_key("effectiveTime") {
                                            rp.insert(
                                                "effectiveTime".into(),
                                                json!(fmt_gcs_ts(Utc::now())),
                                            );
                                        }
                                    }
                                } else if k == "autoclass" {
                                    if let Some(ac) = val.as_object_mut() {
                                        if !ac.contains_key("toggleTime") {
                                            ac.insert(
                                                "toggleTime".into(),
                                                json!(fmt_gcs_ts(Utc::now())),
                                            );
                                        }
                                    }
                                }
                                b.extra_fields.insert(k.clone(), val);
                            }
                        }
                    }
                }
                let b = st.buckets.get(&name).expect("just inserted").to_json();
                HttpResponse::json(200, "OK", b)
            }
            _ => HttpResponse::error(
                405,
                "Method Not Allowed",
                "Method not allowed",
                "methodNotAllowed",
            ),
        };
    }

    // Bucket & Object JSON API: /storage/v1/b/{bucket}...
    if let Some(rest) = path.strip_prefix("/storage/v1/b/") {
        return handle_bucket_json_routes(&req, rest, &query, state);
    }

    // Fallback: Mock XML/S3 routes when path does not start with /storage/v1/
    handle_xml_s3(&req, &path, &query, state)
}

fn handle_projects(
    req: &HttpRequest,
    rest: &str,
    query: &BTreeMap<String, String>,
    state: &Arc<Mutex<MockGcsState>>,
) -> HttpResponse {
    let segs: Vec<&str> = rest.split('/').collect();
    if segs.len() == 2 && segs[1] == "serviceAccount" && req.method == "GET" {
        return HttpResponse::json(
            200,
            "OK",
            json!({
                "kind": "storage#serviceAccount",
                "email_address": format!("service-{}@gs-project-accounts.iam.gserviceaccount.com", segs[0]),
            }),
        );
    }
    if segs.len() >= 2 && segs[1] == "hmacKeys" {
        let project = segs[0];
        let mut st = state.lock().expect("lock poisoned");
        if segs.len() == 2 {
            return match req.method.as_str() {
                "GET" => {
                    let items: Vec<Value> = st.hmac_keys.values().cloned().collect();
                    HttpResponse::json(
                        200,
                        "OK",
                        json!({"kind": "storage#hmacKeysMetadata", "items": items}),
                    )
                }
                "POST" => {
                    let sa = query
                        .get("serviceAccountEmail")
                        .cloned()
                        .unwrap_or_else(|| "sa@mock-project.iam.gserviceaccount.com".into());
                    let access_id = format!("GOOG1EMOCKKEY{}", st.next_gen());
                    let now = Utc::now().to_rfc3339();
                    let meta = json!({
                        "kind": "storage#hmacKeyMetadata",
                        "id": format!("{project}/{access_id}"),
                        "accessId": access_id,
                        "projectId": project,
                        "serviceAccountEmail": sa,
                        "state": "ACTIVE",
                        "timeCreated": now,
                        "updated": now,
                        "etag": "CAE="
                    });
                    st.hmac_keys.insert(access_id.clone(), meta.clone());
                    HttpResponse::json(
                        200,
                        "OK",
                        json!({
                            "kind": "storage#hmacKey",
                            "secret": "bW9jay1obWFjLXNlY3JldC1rZXktMzItYnl0ZXM=",
                            "metadata": meta
                        }),
                    )
                }
                _ => HttpResponse::error(
                    405,
                    "Method Not Allowed",
                    "Method not allowed",
                    "methodNotAllowed",
                ),
            };
        }
        if segs.len() == 3 {
            let access_id = pct_decode(segs[2]);
            return match req.method.as_str() {
                "GET" => match st.hmac_keys.get(&access_id) {
                    Some(m) => HttpResponse::json(200, "OK", m.clone()),
                    None => {
                        HttpResponse::error(404, "Not Found", "Access ID not found", "notFound")
                    }
                },
                "PUT" => {
                    let body_val: Value =
                        serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
                    let Some(existing) = st.hmac_keys.get_mut(&access_id) else {
                        return HttpResponse::error(
                            404,
                            "Not Found",
                            "Access ID not found",
                            "notFound",
                        );
                    };
                    if let Some(new_state) = body_val.get("state").and_then(|v| v.as_str()) {
                        existing["state"] = json!(new_state);
                    }
                    HttpResponse::json(200, "OK", existing.clone())
                }
                "DELETE" => {
                    if let Some(existing) = st.hmac_keys.get(&access_id) {
                        if existing.get("state").and_then(|v| v.as_str()) == Some("ACTIVE") {
                            return HttpResponse::error(
                                400,
                                "Bad Request",
                                "Cannot delete ACTIVE HMAC key. Set state to INACTIVE first.",
                                "invalid",
                            );
                        }
                        st.hmac_keys.remove(&access_id);
                        HttpResponse::empty(204, "No Content")
                    } else {
                        HttpResponse::error(404, "Not Found", "Access ID not found", "notFound")
                    }
                }
                _ => HttpResponse::error(
                    405,
                    "Method Not Allowed",
                    "Method not allowed",
                    "methodNotAllowed",
                ),
            };
        }
    }
    HttpResponse::error(404, "Not Found", "Unknown projects route", "notFound")
}

fn handle_bucket_json_routes(
    req: &HttpRequest,
    rest: &str,
    query: &BTreeMap<String, String>,
    state: &Arc<Mutex<MockGcsState>>,
) -> HttpResponse {
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.is_empty() {
        return HttpResponse::error(404, "Not Found", "Not Found", "notFound");
    }
    let bucket = pct_decode(segments[0]);
    if let Some(fault) = check_fault_bucket(&bucket) {
        return fault;
    }

    // /storage/v1/b/{bucket}
    if segments.len() == 1 {
        return match req.method.as_str() {
            "GET" => {
                let st = state.lock().expect("lock poisoned");
                match st.buckets.get(&bucket) {
                    Some(b) => {
                        let wants_acl = query
                            .get("fields")
                            .is_some_and(|f| f.contains("acl") || f.contains("defaultObjectAcl"))
                            || query.get("projection").map(String::as_str) == Some("full");
                        if b.ubla_enabled() && wants_acl {
                            return HttpResponse::error(
                                400,
                                "Bad Request",
                                "Cannot get legacy ACL for a bucket with Uniform bucket-level access enabled.",
                                "invalid",
                            );
                        }
                        HttpResponse::json(200, "OK", b.to_json())
                    }
                    None => HttpResponse::error(
                        404,
                        "Not Found",
                        &format!("The specified bucket does not exist: {bucket}"),
                        "notFound",
                    ),
                }
            }
            "PATCH" | "PUT" => {
                let body_val: Value =
                    serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
                let mut st = state.lock().expect("lock poisoned");
                let Some(b) = st.buckets.get_mut(&bucket) else {
                    return HttpResponse::error(
                        404,
                        "Not Found",
                        "The specified bucket does not exist.",
                        "notFound",
                    );
                };
                if let Some(if_meta) = query
                    .get("ifMetagenerationMatch")
                    .and_then(|v| v.parse::<u64>().ok())
                {
                    if b.metageneration != if_meta {
                        return HttpResponse::error(
                            412,
                            "Precondition Failed",
                            "At least one of the pre-conditions you specified did not hold.",
                            "conditionNotMet",
                        );
                    }
                }
                // Enforce locked retention policy
                if b.retention_locked() && body_val.get("retentionPolicy").is_some() {
                    let rp = &body_val["retentionPolicy"];
                    if rp.is_null() {
                        return HttpResponse::error(
                            403,
                            "Forbidden",
                            "Cannot remove a locked retention policy.",
                            "forbidden",
                        );
                    }
                    let current_period = b
                        .extra_fields
                        .get("retentionPolicy")
                        .and_then(|v| v.get("retentionPeriod"))
                        .and_then(|v| {
                            v.as_u64()
                                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                        })
                        .unwrap_or(0);
                    let new_period = rp.get("retentionPeriod").and_then(|v| {
                        v.as_u64()
                            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                    });
                    if let Some(np) = new_period {
                        if np < current_period {
                            return HttpResponse::error(
                                403,
                                "Forbidden",
                                "Cannot reduce retention duration of a locked Retention Policy for bucket.",
                                "forbidden",
                            );
                        }
                    }
                }
                if let Some(canned) = query.get("predefinedAcl") {
                    b.acl = predefined_acl_entries(canned, &bucket, None, false);
                }
                if let Some(canned) = query.get("predefinedDefaultObjectAcl") {
                    b.default_object_acl = predefined_acl_entries(canned, &bucket, None, true);
                }
                if let Some(map) = body_val.as_object() {
                    for (k, v) in map {
                        if k == "versioning" {
                            if v.is_null() {
                                b.versioning_enabled = false;
                            } else if let Some(en) = v.get("enabled").and_then(|x| x.as_bool()) {
                                b.versioning_enabled = en;
                            }
                        } else if k == "storageClass" {
                            if let Some(sc) = v.as_str() {
                                b.storage_class = sc.to_ascii_uppercase();
                            }
                        } else if k == "acl" {
                            if let Some(arr) = v.as_array() {
                                b.acl = arr.clone();
                            } else if v.is_null() {
                                b.acl.clear();
                            }
                        } else if k == "defaultObjectAcl" {
                            if let Some(arr) = v.as_array() {
                                b.default_object_acl = arr.clone();
                            } else if v.is_null() {
                                b.default_object_acl.clear();
                            }
                        } else if v.is_null() {
                            // True JSON PATCH null-tombstone deletion!
                            b.extra_fields.remove(k);
                        } else if k == "labels" && req.method == "PATCH" {
                            let entry = b
                                .extra_fields
                                .entry("labels".to_string())
                                .or_insert_with(|| json!({}));
                            merge_json_patch(entry, v);
                            if entry.as_object().is_some_and(|m| m.is_empty()) {
                                b.extra_fields.remove("labels");
                            }
                        } else if req.method == "PATCH" && v.is_object() {
                            let entry =
                                b.extra_fields.entry(k.clone()).or_insert_with(|| json!({}));
                            merge_json_patch(entry, v);
                            if k == "retentionPolicy" && entry.get("effectiveTime").is_none() {
                                entry["effectiveTime"] = json!(fmt_gcs_ts(Utc::now()));
                            }
                            if k == "autoclass" && entry.get("toggleTime").is_none() {
                                entry["toggleTime"] = json!(fmt_gcs_ts(Utc::now()));
                            }
                        } else {
                            b.extra_fields.insert(k.clone(), v.clone());
                        }
                    }
                }
                b.metageneration += 1;
                HttpResponse::json(200, "OK", b.to_json())
            }
            "DELETE" => {
                let mut st = state.lock().expect("lock poisoned");
                match st.buckets.get(&bucket) {
                    None => HttpResponse::error(
                        404,
                        "Not Found",
                        "The specified bucket does not exist.",
                        "notFound",
                    ),
                    Some(b) if !b.objects.is_empty() => HttpResponse::error(
                        409,
                        "Conflict",
                        "The bucket you tried to delete is not empty.",
                        "conflict",
                    ),
                    Some(_) => {
                        st.buckets.remove(&bucket);
                        HttpResponse::empty(204, "No Content")
                    }
                }
            }
            _ => HttpResponse::error(
                405,
                "Method Not Allowed",
                "Method not allowed",
                "methodNotAllowed",
            ),
        };
    }

    // POST /storage/v1/b/{bucket}/lockRetentionPolicy
    if segments.len() == 2 && segments[1] == "lockRetentionPolicy" && req.method == "POST" {
        let mut st = state.lock().expect("lock poisoned");
        let Some(b) = st.buckets.get_mut(&bucket) else {
            return HttpResponse::error(404, "Not Found", "No such bucket", "notFound");
        };
        if let Some(if_meta) = query
            .get("ifMetagenerationMatch")
            .and_then(|v| v.parse::<u64>().ok())
        {
            if b.metageneration != if_meta {
                return HttpResponse::error(
                    412,
                    "Precondition Failed",
                    "Metageneration mismatch on lockRetentionPolicy.",
                    "conditionNotMet",
                );
            }
        }
        let rp = b
            .extra_fields
            .entry("retentionPolicy".into())
            .or_insert_with(|| json!({}));
        rp["isLocked"] = json!(true);
        rp["effectiveTime"] = json!(fmt_gcs_ts(Utc::now()));
        b.metageneration += 1;
        return HttpResponse::json(200, "OK", b.to_json());
    }

    // /storage/v1/b/{bucket}/acl and /defaultObjectAcl
    if segments.len() >= 2 && (segments[1] == "acl" || segments[1] == "defaultObjectAcl") {
        let is_default = segments[1] == "defaultObjectAcl";
        let mut st = state.lock().expect("lock poisoned");
        let Some(b) = st.buckets.get_mut(&bucket) else {
            return HttpResponse::error(404, "Not Found", "No such bucket", "notFound");
        };
        if b.ubla_enabled() {
            return HttpResponse::error(
                400,
                "Bad Request",
                "Cannot get or update legacy ACLs for a bucket with Uniform bucket-level access enabled.",
                "invalid",
            );
        }
        let acl_vec = if is_default {
            &mut b.default_object_acl
        } else {
            &mut b.acl
        };
        return match req.method.as_str() {
            "GET" => HttpResponse::json(
                200,
                "OK",
                json!({
                    "kind": if is_default { "storage#objectAccessControls" } else { "storage#bucketAccessControls" },
                    "items": acl_vec
                }),
            ),
            "POST" | "PUT" | "PATCH" => {
                let val: Value = serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
                let entity = val
                    .get("entity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                acl_vec.retain(|e| e.get("entity").and_then(|v| v.as_str()) != Some(&entity));
                acl_vec.push(val.clone());
                HttpResponse::json(200, "OK", val)
            }
            "DELETE" if segments.len() == 3 => {
                let entity = pct_decode(segments[2]);
                acl_vec.retain(|e| e.get("entity").and_then(|v| v.as_str()) != Some(&entity));
                HttpResponse::empty(204, "No Content")
            }
            _ => HttpResponse::error(
                405,
                "Method Not Allowed",
                "Method not allowed",
                "methodNotAllowed",
            ),
        };
    }

    // /storage/v1/b/{bucket}/iam
    if segments.len() == 2 && segments[1] == "iam" {
        let mut st = state.lock().expect("lock poisoned");
        let Some(b) = st.buckets.get_mut(&bucket) else {
            return HttpResponse::error(404, "Not Found", "No such bucket", "notFound");
        };
        return match req.method.as_str() {
            "GET" => {
                let mut pol = b.iam_policy.clone();
                if let Some(fields_str) = query.get("fields") {
                    let wanted: BTreeSet<&str> = fields_str.split(',').map(str::trim).collect();
                    if let Some(map) = pol.as_object_mut() {
                        map.retain(|k, _| wanted.contains(k.as_str()));
                    }
                }
                HttpResponse::json(200, "OK", pol)
            }
            "PUT" => {
                let mut body_val: Value =
                    serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
                let current_etag = b
                    .iam_policy
                    .get("etag")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if let Some(req_etag) = body_val.get("etag").and_then(|v| v.as_str()) {
                    if !req_etag.is_empty() && !current_etag.is_empty() && req_etag != current_etag
                    {
                        return HttpResponse::error(
                            412,
                            "Precondition Failed",
                            "At least one of the pre-conditions you specified did not hold.",
                            "conditionNotMet",
                        );
                    }
                }
                b.metageneration += 1;
                body_val["etag"] = json!(format!("CAE={}", b.metageneration));
                if body_val.get("bindings").is_none() {
                    body_val["bindings"] = json!([]);
                }
                b.iam_policy = body_val;
                HttpResponse::json(200, "OK", b.iam_policy.clone())
            }
            _ => HttpResponse::error(
                405,
                "Method Not Allowed",
                "Method not allowed",
                "methodNotAllowed",
            ),
        };
    }

    // /storage/v1/b/{bucket}/notificationConfigs[/{id}]
    if segments.len() >= 2 && segments[1] == "notificationConfigs" {
        let mut st = state.lock().expect("lock poisoned");
        let Some(b) = st.buckets.get_mut(&bucket) else {
            return HttpResponse::error(404, "Not Found", "No such bucket", "notFound");
        };
        if segments.len() == 2 {
            return match req.method.as_str() {
                "GET" => HttpResponse::json(
                    200,
                    "OK",
                    json!({ "kind": "storage#notifications", "items": b.notifications }),
                ),
                "POST" => {
                    let mut body_val: Value =
                        serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
                    let id = format!("{}", b.notifications.len() + 1);
                    body_val["id"] = json!(id);
                    body_val["kind"] = json!("storage#notification");
                    b.notifications.push(body_val.clone());
                    HttpResponse::json(200, "OK", body_val)
                }
                _ => HttpResponse::error(
                    405,
                    "Method Not Allowed",
                    "Method not allowed",
                    "methodNotAllowed",
                ),
            };
        }
        if segments.len() == 3 && req.method == "DELETE" {
            let id = pct_decode(segments[2]);
            let before = b.notifications.len();
            b.notifications
                .retain(|n| n.get("id").and_then(|v| v.as_str()) != Some(&id));
            if b.notifications.len() == before {
                return HttpResponse::error(404, "Not Found", "Notification not found", "notFound");
            }
            return HttpResponse::empty(204, "No Content");
        }
    }

    // POST /storage/v1/b/{bucket}/o/watch
    if segments.len() == 3 && segments[1] == "o" && segments[2] == "watch" && req.method == "POST" {
        let mut body_val: Value = serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
        let id = body_val
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("mock-channel-1")
            .to_string();
        body_val["kind"] = json!("api#channel");
        body_val["resourceId"] = json!(format!("res-{id}"));
        let mut st = state.lock().expect("lock poisoned");
        st.watch_channels.insert(id, body_val.clone());
        return HttpResponse::json(200, "OK", body_val);
    }

    // POST /storage/v1/b/{bucket}/o/{object}/compose
    if segments.len() == 4 && segments[1] == "o" && segments[3] == "compose" && req.method == "POST"
    {
        let dst_obj = pct_decode(segments[2]);
        let body_val: Value = serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
        let mut st = state.lock().expect("lock poisoned");
        let mut combined = Vec::new();
        if let Some(sources) = body_val.get("sourceObjects").and_then(|v| v.as_array()) {
            for src in sources {
                let sname = src.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let sgen = src
                    .get("generation")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok());
                let Some(found) = st.buckets.get(&bucket).and_then(|b| {
                    b.objects.iter().find(|o| {
                        o.name == sname
                            && match sgen {
                                Some(g) => o.generation == g,
                                None => !o.deleted,
                            }
                    })
                }) else {
                    return HttpResponse::error(
                        404,
                        "Not Found",
                        "No such source object",
                        "notFound",
                    );
                };
                combined.extend_from_slice(&found.data);
            }
        }
        return match st.put_object(&bucket, &dst_obj, combined, "application/octet-stream") {
            Some(obj) => HttpResponse::json(200, "OK", obj.to_json()),
            None => HttpResponse::error(404, "Not Found", "No such bucket", "notFound"),
        };
    }

    // GET /storage/v1/b/{bucket}/o (with maxResults + pageToken pagination!)
    if segments.len() == 2 && segments[1] == "o" && req.method == "GET" {
        let st = state.lock().expect("lock poisoned");
        let Some(b) = st.buckets.get(&bucket) else {
            return HttpResponse::error(
                404,
                "Not Found",
                "The specified bucket does not exist.",
                "notFound",
            );
        };
        let prefix = query.get("prefix").map(String::as_str).unwrap_or("");
        let delimiter = query.get("delimiter").map(String::as_str);
        let versions = query.get("versions").is_some_and(|v| v == "true");
        let max_results = query
            .get("maxResults")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1000)
            .max(1);
        let offset = query
            .get("pageToken")
            .and_then(|t| t.strip_prefix("page-"))
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(0);

        let mut all_items = Vec::new();
        let mut prefixes = BTreeSet::new();
        for obj in &b.objects {
            if !versions && obj.deleted {
                continue;
            }
            if !obj.name.starts_with(prefix) {
                continue;
            }
            if let Some(delim) = delimiter {
                let remainder = &obj.name[prefix.len()..];
                if let Some(idx) = remainder.find(delim) {
                    let p = format!("{}{}{}", prefix, &remainder[..idx], delim);
                    prefixes.insert(p);
                    continue;
                }
            }
            let req_sha = req
                .headers
                .get("x-goog-encryption-key-sha256")
                .map(String::as_str);
            all_items.push(obj.to_json_with_key(req_sha));
        }
        let end = (offset + max_results).min(all_items.len());
        let page_items = if offset < all_items.len() {
            all_items[offset..end].to_vec()
        } else {
            Vec::new()
        };
        let mut resp = json!({ "kind": "storage#objects" });
        if !page_items.is_empty() {
            resp["items"] = json!(page_items);
        }
        if offset == 0 && !prefixes.is_empty() {
            resp["prefixes"] = json!(prefixes.into_iter().collect::<Vec<_>>());
        }
        if end < all_items.len() {
            resp["nextPageToken"] = json!(format!("page-{end}"));
        }
        return HttpResponse::json(200, "OK", resp);
    }

    // /storage/v1/b/{bucket}/o/{object}/iam
    if segments.len() == 4 && segments[1] == "o" && segments[3] == "iam" {
        let obj_name = pct_decode(segments[2]);
        let mut st = state.lock().expect("lock poisoned");
        let Some(b) = st.buckets.get_mut(&bucket) else {
            return HttpResponse::error(404, "Not Found", "No such bucket", "notFound");
        };
        let req_gen = query.get("generation").and_then(|g| g.parse::<u64>().ok());
        let Some(obj) = b.objects.iter_mut().find(|o| {
            o.name == obj_name
                && match req_gen {
                    Some(g) => o.generation == g,
                    None => !o.deleted,
                }
        }) else {
            return HttpResponse::error(404, "Not Found", "No such object", "notFound");
        };
        return match req.method.as_str() {
            "GET" => HttpResponse::json(200, "OK", obj.iam_policy.clone()),
            "PUT" => {
                let mut body_val: Value =
                    serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
                let current_etag = obj
                    .iam_policy
                    .get("etag")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if let Some(req_etag) = body_val.get("etag").and_then(|v| v.as_str()) {
                    if !req_etag.is_empty() && !current_etag.is_empty() && req_etag != current_etag
                    {
                        return HttpResponse::error(
                            412,
                            "Precondition Failed",
                            "At least one of the pre-conditions you specified did not hold.",
                            "conditionNotMet",
                        );
                    }
                }
                obj.metageneration += 1;
                body_val["etag"] = json!(format!("CAE={}", obj.metageneration));
                if body_val.get("bindings").is_none() {
                    body_val["bindings"] = json!([]);
                }
                obj.iam_policy = body_val;
                HttpResponse::json(200, "OK", obj.iam_policy.clone())
            }
            _ => HttpResponse::error(
                405,
                "Method Not Allowed",
                "Method not allowed",
                "methodNotAllowed",
            ),
        };
    }

    // /storage/v1/b/{bucket}/o/{object}/acl
    if segments.len() >= 4 && segments[1] == "o" && segments[3] == "acl" {
        let obj_name = pct_decode(segments[2]);
        let mut st = state.lock().expect("lock poisoned");
        let Some(b) = st.buckets.get_mut(&bucket) else {
            return HttpResponse::error(404, "Not Found", "No such bucket", "notFound");
        };
        if b.ubla_enabled() {
            return HttpResponse::error(
                400,
                "Bad Request",
                "Cannot update access control for an object when Uniform bucket-level access is enabled.",
                "invalid",
            );
        }
        let req_gen = query.get("generation").and_then(|g| g.parse::<u64>().ok());
        let Some(obj) = b.objects.iter_mut().find(|o| {
            o.name == obj_name
                && match req_gen {
                    Some(g) => o.generation == g,
                    None => !o.deleted,
                }
        }) else {
            return HttpResponse::error(404, "Not Found", "No such object", "notFound");
        };
        return match req.method.as_str() {
            "GET" => HttpResponse::json(
                200,
                "OK",
                json!({"kind": "storage#objectAccessControls", "items": obj.acl}),
            ),
            "POST" | "PUT" | "PATCH" => {
                let val: Value = serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
                let entity = val
                    .get("entity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                obj.acl
                    .retain(|e| e.get("entity").and_then(|v| v.as_str()) != Some(&entity));
                obj.acl.push(val.clone());
                HttpResponse::json(200, "OK", val)
            }
            _ => HttpResponse::error(
                405,
                "Method Not Allowed",
                "Method not allowed",
                "methodNotAllowed",
            ),
        };
    }

    // /storage/v1/b/{bucket}/o/{object}
    if segments.len() == 3 && segments[1] == "o" {
        let object_name = pct_decode(segments[2]);
        return handle_object(req, &bucket, &object_name, query, state);
    }

    // /storage/v1/b/{src_b}/o/{src_o}/(copyTo|rewriteTo)/b/{dst_b}/o/{dst_o}
    if segments.len() == 8
        && segments[1] == "o"
        && (segments[3] == "copyTo" || segments[3] == "rewriteTo")
        && segments[4] == "b"
        && segments[6] == "o"
        && req.method == "POST"
    {
        let src_obj = pct_decode(segments[2]);
        let dst_bucket = pct_decode(segments[5]);
        let dst_obj = pct_decode(segments[7]);
        if let Some(fault) = check_fault_bucket(&dst_bucket) {
            return fault;
        }
        let body_val: Value = serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
        let override_sc = body_val
            .get("storageClass")
            .and_then(|v| v.as_str())
            .map(String::from);
        let override_ct = body_val
            .get("contentType")
            .and_then(|v| v.as_str())
            .map(String::from);
        let override_meta = body_val
            .get("metadata")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<BTreeMap<String, String>>()
            });

        let src_gen = query
            .get("sourceGeneration")
            .and_then(|g| g.parse::<u64>().ok());
        let mut st = state.lock().expect("lock poisoned");
        let found = st
            .buckets
            .get(&bucket)
            .and_then(|b| {
                b.objects.iter().find(|o| {
                    o.name == src_obj
                        && match src_gen {
                            Some(g) => o.generation == g,
                            None => !o.deleted,
                        }
                })
            })
            .cloned();
        let Some(src) = found else {
            return HttpResponse::error(404, "Not Found", "No such object", "notFound");
        };
        if let Some((_, ref expected_sha)) = src.customer_encryption {
            let provided = req
                .headers
                .get("x-goog-copy-source-encryption-key-sha256")
                .or_else(|| req.headers.get("x-goog-encryption-key-sha256"));
            if provided.map(String::as_str) != Some(expected_sha.as_str()) {
                return HttpResponse::error(
                    400,
                    "Bad Request",
                    "The target object is encrypted by a customer-supplied encryption key.",
                    "customerEncryptionKeyIsIncorrect",
                );
            }
        }
        let dst_csek = req
            .headers
            .get("x-goog-encryption-algorithm")
            .zip(req.headers.get("x-goog-encryption-key-sha256"))
            .map(|(alg, sha)| (alg.clone(), sha.clone()));

        // Multi-step rewriteToken simulation when maxBytesRewrittenPerCall is set
        if segments[3] == "rewriteTo" && query.contains_key("maxBytesRewrittenPerCall") {
            let max_step = query
                .get("maxBytesRewrittenPerCall")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(src.data.len() / 2);
            if let Some(token) = query.get("rewriteToken") {
                if st.rewrite_sessions.remove(token).is_none() {
                    return HttpResponse::error(
                        404,
                        "Not Found",
                        "Invalid rewriteToken",
                        "notFound",
                    );
                }
            } else if max_step < src.data.len() {
                let tok = format!("rw-tok-{}", st.next_gen());
                st.rewrite_sessions.insert(
                    tok.clone(),
                    RewriteSession {
                        src_bucket: bucket.clone(),
                        src_object: src_obj.clone(),
                        dst_bucket: dst_bucket.clone(),
                        dst_object: dst_obj.clone(),
                        override_storage_class: override_sc,
                        override_content_type: override_ct,
                        override_metadata: override_meta,
                    },
                );
                return HttpResponse::json(
                    200,
                    "OK",
                    json!({
                        "kind": "storage#rewriteResponse",
                        "totalBytesRewritten": max_step.to_string(),
                        "objectSize": src.data.len().to_string(),
                        "done": false,
                        "rewriteToken": tok,
                    }),
                );
            }
        }

        let ct = override_ct.unwrap_or(src.content_type);
        let meta = override_meta.unwrap_or(src.metadata);
        let sc = override_sc.or(Some(src.storage_class));
        let Some(mut created) = st.put_object_full(
            &dst_bucket,
            &dst_obj,
            src.data,
            &ct,
            src.content_encoding,
            meta,
            sc,
        ) else {
            return HttpResponse::error(
                404,
                "Not Found",
                "Destination bucket not found",
                "notFound",
            );
        };
        if let Some(enc) = dst_csek {
            created.customer_encryption = Some(enc.clone());
            if let Some(b) = st.buckets.get_mut(&dst_bucket) {
                if let Some(stored) = b
                    .objects
                    .iter_mut()
                    .find(|o| o.generation == created.generation)
                {
                    stored.customer_encryption = Some(enc);
                }
            }
        }
        let req_sha = req
            .headers
            .get("x-goog-encryption-key-sha256")
            .map(String::as_str);
        if segments[3] == "rewriteTo" {
            return HttpResponse::json(
                200,
                "OK",
                json!({
                    "kind": "storage#rewriteResponse",
                    "totalBytesRewritten": created.data.len().to_string(),
                    "objectSize": created.data.len().to_string(),
                    "done": true,
                    "resource": created.to_json_with_key(req_sha),
                }),
            );
        }
        return HttpResponse::json(200, "OK", created.to_json_with_key(req_sha));
    }

    HttpResponse::error(
        404,
        "Not Found",
        &format!(
            "Unhandled mock GCS route: {} /storage/v1/b/{}",
            req.method, rest
        ),
        "notFound",
    )
}

fn handle_upload(
    req: &HttpRequest,
    bucket: &str,
    query: &BTreeMap<String, String>,
    state: &Arc<Mutex<MockGcsState>>,
    addr: SocketAddr,
    is_tls: bool,
) -> HttpResponse {
    let upload_type = query
        .get("uploadType")
        .map(String::as_str)
        .unwrap_or("media");
    let content_type = req
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| "application/octet-stream".into());

    if upload_type == "resumable" && req.method == "POST" {
        let body_val: Value = serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
        let name = query.get("name").cloned().unwrap_or_else(|| {
            body_val
                .get("name")
                .and_then(|n| n.as_str())
                .map(String::from)
                .unwrap_or_default()
        });
        let ct = body_val
            .get("contentType")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or(content_type);
        let ce = body_val
            .get("contentEncoding")
            .and_then(|v| v.as_str())
            .map(String::from);
        let meta = body_val
            .get("metadata")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<BTreeMap<String, String>>()
            })
            .unwrap_or_default();

        let mut st = state.lock().expect("lock poisoned");
        if !st.buckets.contains_key(bucket) {
            return HttpResponse::error(404, "Not Found", "Not Found", "notFound");
        }
        let csek = req
            .headers
            .get("x-goog-encryption-algorithm")
            .zip(req.headers.get("x-goog-encryption-key-sha256"))
            .map(|(alg, sha)| (alg.clone(), sha.clone()));
        let upload_id = format!("sess-{}", st.next_gen());
        st.resumable_sessions.insert(
            upload_id.clone(),
            ResumableSession {
                bucket: bucket.to_string(),
                name,
                content_type: ct,
                content_encoding: ce,
                metadata: meta,
                accumulated: Vec::new(),
                dropped_once: false,
                customer_encryption: csek,
            },
        );
        let scheme = if is_tls { "https" } else { "http" };
        let location = format!(
            "{}://{}/upload/storage/v1/b/{}/o?uploadType=resumable&upload_id={}",
            scheme, addr, bucket, upload_id
        );
        let mut resp = HttpResponse::empty(200, "OK");
        resp.headers.push(("Location".into(), location));
        return resp;
    }

    if req.method == "PUT" {
        if let Some(upload_id) = query.get("upload_id") {
            let mut st = state.lock().expect("lock poisoned");
            if let Some(cr) = req.headers.get("content-range") {
                st.resumable_put_ranges.push(cr.clone());
            }
            let Some(sess) = st.resumable_sessions.get_mut(upload_id) else {
                return HttpResponse::error(
                    404,
                    "Not Found",
                    "Upload session not found",
                    "notFound",
                );
            };
            // Fault-injection bucket `fault-resume`:
            // Commits chunk 1 cleanly, then injects a 503 abort on chunk 2 (once) so the
            // first process fails mid-upload with chunk 1 committed, and the second process
            // must query `Content-Range: bytes */<total>` -> `308` and resume from chunk 2!
            if bucket == "fault-resume"
                && !sess.dropped_once
                && !sess.accumulated.is_empty()
                && !req.body.is_empty()
            {
                sess.dropped_once = true;
                return HttpResponse::error(
                    503,
                    "Service Unavailable",
                    "Simulated mid-upload crash after chunk 1",
                    "backendError",
                );
            }
            // Optional disconnect fault injection on first chunk
            if bucket == "fault-resumable-drop" && !sess.dropped_once && !req.body.is_empty() {
                sess.dropped_once = true;
                return HttpResponse::error(
                    503,
                    "Service Unavailable",
                    "Simulated transient disconnect during resumable upload",
                    "backendError",
                );
            }
            if let Some(cr) = req.headers.get("content-range") {
                // Status probe: `Content-Range: bytes */*` OR `Content-Range: bytes */<total>`
                let trimmed_cr = cr.trim();
                if trimmed_cr == "bytes */*"
                    || (trimmed_cr.starts_with("bytes */") && req.body.is_empty())
                {
                    let mut resp = HttpResponse::empty(308, "Resume Incomplete");
                    if !sess.accumulated.is_empty() {
                        resp.headers.push((
                            "Range".into(),
                            format!("bytes=0-{}", sess.accumulated.len() - 1),
                        ));
                    }
                    return resp;
                }
                // Chunked: bytes <start>-<end>/<total|*>
                if let Some((range_part, total_part)) = cr
                    .trim()
                    .strip_prefix("bytes ")
                    .and_then(|s| s.split_once('/'))
                {
                    if let Some((start_s, end_s)) = range_part.split_once('-') {
                        let start: usize = start_s.parse().unwrap_or(0);
                        let end: usize = end_s.parse().unwrap_or(0);
                        if start == sess.accumulated.len() {
                            sess.accumulated.extend_from_slice(&req.body);
                        } else if start < sess.accumulated.len() {
                            sess.accumulated.truncate(start);
                            sess.accumulated.extend_from_slice(&req.body);
                        }
                        let is_final = total_part
                            .parse::<usize>()
                            .is_ok_and(|total| end + 1 >= total);
                        if !is_final {
                            let mut resp = HttpResponse::empty(308, "Resume Incomplete");
                            if !sess.accumulated.is_empty() {
                                resp.headers.push((
                                    "Range".into(),
                                    format!("bytes=0-{}", sess.accumulated.len() - 1),
                                ));
                            }
                            return resp;
                        }
                    }
                }
            } else {
                sess.accumulated.extend_from_slice(&req.body);
            }

            let finished = st
                .resumable_sessions
                .remove(upload_id)
                .expect("checked above");
            if let Some(mut obj) = st.put_object_full(
                &finished.bucket,
                &finished.name,
                finished.accumulated,
                &finished.content_type,
                finished.content_encoding,
                finished.metadata,
                None,
            ) {
                if let Some(enc) = finished.customer_encryption {
                    obj.customer_encryption = Some(enc.clone());
                    if let Some(b) = st.buckets.get_mut(&finished.bucket) {
                        if let Some(stored) = b
                            .objects
                            .iter_mut()
                            .find(|o| o.generation == obj.generation)
                        {
                            stored.customer_encryption = Some(enc);
                        }
                    }
                }
                let req_sha = req
                    .headers
                    .get("x-goog-encryption-key-sha256")
                    .map(String::as_str);
                return HttpResponse::json(200, "OK", obj.to_json_with_key(req_sha));
            }
            return HttpResponse::error(404, "Not Found", "Bucket not found", "notFound");
        }
    }

    // Simple media or multipart upload
    let (name, payload, ct, ce, meta) = if upload_type == "multipart" {
        parse_multipart_upload(&content_type, &req.body, query.get("name").cloned())
    } else {
        (
            query.get("name").cloned().unwrap_or_default(),
            req.body.clone(),
            content_type,
            None,
            BTreeMap::new(),
        )
    };

    let mut st = state.lock().expect("lock poisoned");
    if let Some(if_gen) = query
        .get("ifGenerationMatch")
        .and_then(|v| v.parse::<u64>().ok())
    {
        let current_gen = st
            .buckets
            .get(bucket)
            .and_then(|b| b.objects.iter().find(|o| o.name == name && !o.deleted))
            .map(|o| o.generation)
            .unwrap_or(0);
        if current_gen != if_gen {
            return HttpResponse::error(
                412,
                "Precondition Failed",
                "At least one of the pre-conditions you specified did not hold.",
                "conditionNotMet",
            );
        }
    }

    let csek = req
        .headers
        .get("x-goog-encryption-algorithm")
        .zip(req.headers.get("x-goog-encryption-key-sha256"))
        .map(|(alg, sha)| (alg.clone(), sha.clone()));

    match st.put_object_full(bucket, &name, payload, &ct, ce, meta, None) {
        Some(mut obj) => {
            if let Some(enc) = csek {
                obj.customer_encryption = Some(enc.clone());
                if let Some(b) = st.buckets.get_mut(bucket) {
                    if let Some(stored) = b
                        .objects
                        .iter_mut()
                        .find(|o| o.generation == obj.generation)
                    {
                        stored.customer_encryption = Some(enc);
                    }
                }
            }
            let req_sha = req
                .headers
                .get("x-goog-encryption-key-sha256")
                .map(String::as_str);
            HttpResponse::json(200, "OK", obj.to_json_with_key(req_sha))
        }
        None => HttpResponse::error(404, "Not Found", "Bucket not found", "notFound"),
    }
}

#[allow(clippy::type_complexity)]
fn parse_multipart_upload(
    content_type: &str,
    body: &[u8],
    fallback_name: Option<String>,
) -> (
    String,
    Vec<u8>,
    String,
    Option<String>,
    BTreeMap<String, String>,
) {
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .and_then(|s| s.split(';').next())
        .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string());
    let Some(boundary) = boundary else {
        return (
            fallback_name.unwrap_or_default(),
            body.to_vec(),
            "application/octet-stream".into(),
            None,
            BTreeMap::new(),
        );
    };
    let delim = format!("--{}", boundary).into_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    while let Some(pos) = find_subsequence(&body[start..], &delim) {
        let abs = start + pos;
        if start > 0 {
            parts.push(&body[start..abs]);
        }
        start = abs + delim.len();
    }
    let mut name = fallback_name.unwrap_or_default();
    let mut ct = "application/octet-stream".to_string();
    let mut ce: Option<String> = None;
    let mut meta = BTreeMap::new();
    let mut data = Vec::new();
    for (idx, part) in parts.iter().enumerate() {
        let (h_end, sep_len) = if let Some(p) = find_subsequence(part, b"\r\n\r\n") {
            (p, 4)
        } else if let Some(p) = find_subsequence(part, b"\n\n") {
            (p, 2)
        } else {
            continue;
        };
        let part_body = &part[h_end + sep_len..];
        let trimmed = part_body
            .strip_suffix(b"\r\n")
            .or_else(|| part_body.strip_suffix(b"\n"))
            .unwrap_or(part_body);
        if idx == 0 {
            if let Ok(v) = serde_json::from_slice::<Value>(trimmed) {
                if let Some(n) = v.get("name").and_then(|x| x.as_str()) {
                    name = n.to_string();
                }
                if let Some(c) = v.get("contentType").and_then(|x| x.as_str()) {
                    ct = c.to_string();
                }
                if let Some(e) = v.get("contentEncoding").and_then(|x| x.as_str()) {
                    ce = Some(e.to_string());
                }
                if let Some(m) = v.get("metadata").and_then(|x| x.as_object()) {
                    for (k, mv) in m {
                        if let Some(s) = mv.as_str() {
                            meta.insert(k.clone(), s.to_string());
                        }
                    }
                }
            }
        } else {
            data = trimmed.to_vec();
        }
    }
    (name, data, ct, ce, meta)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn handle_object(
    req: &HttpRequest,
    bucket: &str,
    object_name: &str,
    query: &BTreeMap<String, String>,
    state: &Arc<Mutex<MockGcsState>>,
) -> HttpResponse {
    let requested_gen = query.get("generation").and_then(|v| v.parse::<u64>().ok());

    match req.method.as_str() {
        "GET" => {
            let st = state.lock().expect("lock poisoned");
            let Some(b) = st.buckets.get(bucket) else {
                return HttpResponse::error(404, "Not Found", "No such bucket", "notFound");
            };
            let obj = b.objects.iter().find(|o| {
                o.name == object_name
                    && match requested_gen {
                        Some(g) => o.generation == g,
                        None => !o.deleted,
                    }
            });
            let Some(obj) = obj else {
                return HttpResponse::error(
                    404,
                    "Not Found",
                    &format!("No such object: {bucket}/{object_name}"),
                    "notFound",
                );
            };

            if query.get("alt").map(String::as_str) == Some("media") {
                if let Some((_, ref expected_sha)) = obj.customer_encryption {
                    let provided = req.headers.get("x-goog-encryption-key-sha256");
                    if provided.map(String::as_str) != Some(expected_sha.as_str()) {
                        return HttpResponse::error(
                            400,
                            "Bad Request",
                            "The target object is encrypted by a customer-supplied encryption key.",
                            "customerEncryptionKeyIsIncorrect",
                        );
                    }
                }
                // Emulate real GCS transparent gzip decompression when Accept-Encoding: gzip is absent!
                let is_gzip = obj
                    .content_encoding
                    .as_deref()
                    .is_some_and(|e| e.eq_ignore_ascii_case("gzip"));
                let accepts_gzip = req
                    .headers
                    .get("accept-encoding")
                    .is_some_and(|v| v.to_ascii_lowercase().contains("gzip"));
                let (wire_data, send_gzip_header) = if is_gzip && !accepts_gzip {
                    let mut dec = GzDecoder::new(obj.data.as_slice());
                    let mut plain = Vec::new();
                    if dec.read_to_end(&mut plain).is_ok() {
                        (plain, false)
                    } else {
                        (obj.data.clone(), true)
                    }
                } else {
                    (obj.data.clone(), is_gzip)
                };

                if let Some(range_hdr) = req.headers.get("range") {
                    if let Some((start, end)) = parse_byte_range(range_hdr, wire_data.len()) {
                        if start >= wire_data.len() {
                            return HttpResponse::error(
                                416,
                                "Requested Range Not Satisfiable",
                                "Range not satisfiable",
                                "requestedRangeNotSatisfiable",
                            );
                        }
                        let slice = wire_data[start..=end.min(wire_data.len() - 1)].to_vec();
                        return HttpResponse {
                            status: 206,
                            reason: "Partial Content",
                            headers: vec![
                                ("Content-Type".into(), obj.content_type.clone()),
                                (
                                    "Content-Range".into(),
                                    format!("bytes {}-{}/{}", start, end, wire_data.len()),
                                ),
                            ],
                            body: slice,
                        };
                    }
                }
                let mut hdrs = vec![
                    ("Content-Type".into(), obj.content_type.clone()),
                    ("Date".into(), "Sat, 21 Nov 2026 00:00:00 GMT".into()),
                    ("Expires".into(), "Sat, 21 Nov 2026 00:00:00 GMT".into()),
                    ("Cache-Control".into(), "private, max-age=0".into()),
                    ("ETag".into(), format!("\"{}\"", obj.md5_hex())),
                    ("x-goog-generation".into(), obj.generation.to_string()),
                    (
                        "x-goog-hash".into(),
                        format!("crc32c={}, md5={}", obj.crc32c_b64(), obj.md5_b64()),
                    ),
                ];
                if send_gzip_header {
                    hdrs.push(("Content-Encoding".into(), "gzip".into()));
                }
                return HttpResponse {
                    status: 200,
                    reason: "OK",
                    headers: hdrs,
                    body: wire_data,
                };
            }

            let req_sha = req
                .headers
                .get("x-goog-encryption-key-sha256")
                .map(String::as_str);
            HttpResponse::json(200, "OK", obj.to_json_with_key(req_sha))
        }
        "PATCH" | "PUT" => {
            let body_val: Value = serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
            let mut st = state.lock().expect("lock poisoned");
            let Some(b) = st.buckets.get_mut(bucket) else {
                return HttpResponse::error(404, "Not Found", "No such bucket", "notFound");
            };
            let Some(obj) = b.objects.iter_mut().find(|o| {
                o.name == object_name
                    && match requested_gen {
                        Some(g) => o.generation == g,
                        None => !o.deleted,
                    }
            }) else {
                return HttpResponse::error(
                    404,
                    "Not Found",
                    &format!("No such object: {bucket}/{object_name}"),
                    "notFound",
                );
            };
            if let Some(if_gen) = query
                .get("ifGenerationMatch")
                .and_then(|v| v.parse::<u64>().ok())
            {
                if obj.generation != if_gen {
                    return HttpResponse::error(
                        412,
                        "Precondition Failed",
                        "Generation precondition failed.",
                        "conditionNotMet",
                    );
                }
            }
            if let Some(if_meta) = query
                .get("ifMetagenerationMatch")
                .and_then(|v| v.parse::<u64>().ok())
            {
                if obj.metageneration != if_meta {
                    return HttpResponse::error(
                        412,
                        "Precondition Failed",
                        "Metageneration precondition failed.",
                        "conditionNotMet",
                    );
                }
            }
            if let Some(map) = body_val.as_object() {
                if let Some(v) = map.get("contentType") {
                    if let Some(s) = v.as_str() {
                        obj.content_type = s.to_string();
                    }
                }
                if let Some(v) = map.get("cacheControl") {
                    obj.cache_control = v.as_str().map(String::from);
                }
                if let Some(v) = map.get("contentDisposition") {
                    obj.content_disposition = v.as_str().map(String::from);
                }
                if let Some(v) = map.get("contentEncoding") {
                    obj.content_encoding = v.as_str().map(String::from);
                }
                if let Some(v) = map.get("contentLanguage") {
                    obj.content_language = v.as_str().map(String::from);
                }
                if let Some(v) = map.get("customTime") {
                    obj.custom_time = v.as_str().map(String::from);
                }
                if let Some(v) = map.get("temporaryHold").and_then(|x| x.as_bool()) {
                    obj.temporary_hold = Some(v);
                }
                if let Some(v) = map.get("eventBasedHold").and_then(|x| x.as_bool()) {
                    obj.event_based_hold = Some(v);
                }
                if let Some(acl_val) = map.get("acl") {
                    if let Some(arr) = acl_val.as_array() {
                        obj.acl = arr.clone();
                    } else if acl_val.is_null() {
                        obj.acl.clear();
                    }
                }
                if let Some(meta_val) = map.get("metadata") {
                    if meta_val.is_null() {
                        obj.metadata.clear();
                    } else if let Some(meta) = meta_val.as_object() {
                        // True JSON PATCH merge-with-null tombstone deletion!
                        for (k, v) in meta {
                            if v.is_null() {
                                obj.metadata.remove(k);
                            } else if let Some(s) = v.as_str() {
                                obj.metadata.insert(k.clone(), s.to_string());
                            }
                        }
                    }
                }
            }
            if let Some(canned) = query.get("predefinedAcl") {
                obj.acl = predefined_acl_entries(canned, bucket, Some(object_name), false);
            }
            obj.metageneration += 1;
            obj.updated = Utc::now();
            let req_sha = req
                .headers
                .get("x-goog-encryption-key-sha256")
                .map(String::as_str);
            HttpResponse::json(200, "OK", obj.to_json_with_key(req_sha))
        }
        "DELETE" => {
            let mut st = state.lock().expect("lock poisoned");
            let Some(b) = st.buckets.get_mut(bucket) else {
                return HttpResponse::error(404, "Not Found", "No such bucket", "notFound");
            };
            let pos = b.objects.iter().position(|o| {
                o.name == object_name
                    && match requested_gen {
                        Some(g) => o.generation == g,
                        None => !o.deleted,
                    }
            });
            let Some(idx) = pos else {
                return HttpResponse::error(
                    404,
                    "Not Found",
                    &format!("No such object: {bucket}/{object_name}"),
                    "notFound",
                );
            };
            if b.objects[idx].temporary_hold == Some(true)
                || b.objects[idx].event_based_hold == Some(true)
            {
                return HttpResponse::error(
                    403,
                    "Forbidden",
                    "Object is under an active hold and cannot be deleted.",
                    "forbidden",
                );
            }
            if let Some(if_gen) = query
                .get("ifGenerationMatch")
                .and_then(|v| v.parse::<u64>().ok())
            {
                if b.objects[idx].generation != if_gen {
                    return HttpResponse::error(
                        412,
                        "Precondition Failed",
                        "At least one of the pre-conditions you specified did not hold.",
                        "conditionNotMet",
                    );
                }
            }
            if b.versioning_enabled && requested_gen.is_none() {
                b.objects[idx].deleted = true;
                b.objects[idx].updated = Utc::now();
            } else {
                b.objects.remove(idx);
            }
            HttpResponse::empty(204, "No Content")
        }
        _ => HttpResponse::error(
            405,
            "Method Not Allowed",
            "Method not allowed",
            "methodNotAllowed",
        ),
    }
}

/// Basic Mock XML / S3 endpoint handler for `prefer_api = xml` and `s3://` parity tests.
fn handle_xml_s3(
    req: &HttpRequest,
    path: &str,
    query: &BTreeMap<String, String>,
    state: &Arc<Mutex<MockGcsState>>,
) -> HttpResponse {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() && req.method == "GET" {
        let st = state.lock().expect("lock poisoned");
        let mut buckets_xml = String::new();
        for b in st.buckets.values() {
            buckets_xml.push_str(&format!(
                "<Bucket><Name>{}</Name><CreationDate>{}</CreationDate></Bucket>",
                b.name,
                b.time_created.to_rfc3339()
            ));
        }
        return HttpResponse::xml(
            200,
            "OK",
            format!(
                "<?xml version='1.0' encoding='UTF-8'?><ListAllMyBucketsResult><Buckets>{buckets_xml}</Buckets></ListAllMyBucketsResult>"
            ),
        );
    }

    let mut parts = trimmed.splitn(2, '/');
    let bucket = pct_decode(parts.next().unwrap_or(""));
    let obj_opt = parts.next().filter(|s| !s.is_empty()).map(pct_decode);

    match (req.method.as_str(), obj_opt) {
        ("PUT", None) => {
            let mut st = state.lock().expect("lock poisoned");
            if query.contains_key("versioning") {
                if let Some(b) = st.buckets.get_mut(&bucket) {
                    let body_str = String::from_utf8_lossy(&req.body);
                    b.versioning_enabled = body_str.contains("Enabled");
                    b.metageneration += 1;
                    return HttpResponse::empty(200, "OK");
                }
                return HttpResponse::xml(
                    404,
                    "Not Found",
                    "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>".into(),
                );
            }
            let body_str = String::from_utf8_lossy(&req.body);
            let location = extract_xml_tag(&body_str, "LocationConstraint")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "US".into());
            let storage_class = extract_xml_tag(&body_str, "StorageClass")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "STANDARD".into());
            if !st.create_bucket(&bucket, &location, &storage_class) {
                return HttpResponse::xml(
                    409,
                    "Conflict",
                    "<Error><Code>BucketAlreadyOwnedByYou</Code><Message>Your previous request to create the named bucket succeeded and you already own it.</Message></Error>".into(),
                );
            }
            HttpResponse::empty(200, "OK")
        }
        ("DELETE", None) => {
            let mut st = state.lock().expect("lock poisoned");
            let Some(b) = st.buckets.get(&bucket) else {
                return HttpResponse::xml(
                    404,
                    "Not Found",
                    "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>".into(),
                );
            };
            if !b.objects.is_empty() {
                return HttpResponse::xml(
                    409,
                    "Conflict",
                    "<Error><Code>BucketNotEmpty</Code><Message>The bucket you tried to delete is not empty.</Message></Error>".into(),
                );
            }
            st.buckets.remove(&bucket);
            HttpResponse::empty(204, "No Content")
        }
        ("GET", None) => {
            let st = state.lock().expect("lock poisoned");
            let Some(b) = st.buckets.get(&bucket) else {
                return HttpResponse::xml(
                    404,
                    "Not Found",
                    "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>".into(),
                );
            };
            if query.contains_key("location") {
                return HttpResponse::xml(
                    200,
                    "OK",
                    format!(
                        "<?xml version='1.0' encoding='UTF-8'?><LocationConstraint>{}</LocationConstraint>",
                        b.location
                    ),
                );
            }
            if query.contains_key("versioning") {
                let status = if b.versioning_enabled {
                    "<Status>Enabled</Status>"
                } else {
                    ""
                };
                return HttpResponse::xml(
                    200,
                    "OK",
                    format!(
                        "<?xml version='1.0' encoding='UTF-8'?><VersioningConfiguration>{status}</VersioningConfiguration>"
                    ),
                );
            }
            let prefix = query.get("prefix").map(String::as_str).unwrap_or("");
            let versions = query.contains_key("versions");
            let mut contents_xml = String::new();
            for o in &b.objects {
                if (versions || !o.deleted) && o.name.starts_with(prefix) {
                    if versions {
                        let is_latest = if o.deleted { "false" } else { "true" };
                        contents_xml.push_str(&format!(
                            "<Version><Key>{}</Key><Generation>{}</Generation><MetaGeneration>{}</MetaGeneration><IsLatest>{}</IsLatest><Size>{}</Size><LastModified>{}</LastModified><ETag>\"{}\"</ETag></Version>",
                            o.name,
                            o.generation,
                            o.metageneration,
                            is_latest,
                            o.data.len(),
                            fmt_gcs_ts(o.updated),
                            o.md5_hex()
                        ));
                    } else {
                        contents_xml.push_str(&format!(
                            "<Contents><Key>{}</Key><Generation>{}</Generation><MetaGeneration>{}</MetaGeneration><Size>{}</Size><LastModified>{}</LastModified><ETag>\"{}\"</ETag></Contents>",
                            o.name,
                            o.generation,
                            o.metageneration,
                            o.data.len(),
                            fmt_gcs_ts(o.updated),
                            o.md5_hex()
                        ));
                    }
                }
            }
            let xml_body = if versions {
                format!(
                    "<?xml version='1.0' encoding='UTF-8'?><ListVersionsResult><Name>{bucket}</Name><Prefix>{prefix}</Prefix><IsTruncated>false</IsTruncated>{contents_xml}</ListVersionsResult>"
                )
            } else {
                format!(
                    "<?xml version='1.0' encoding='UTF-8'?><ListBucketResult><Name>{bucket}</Name><Prefix>{prefix}</Prefix><IsTruncated>false</IsTruncated>{contents_xml}</ListBucketResult>"
                )
            };
            HttpResponse::xml(200, "OK", xml_body)
        }
        ("GET" | "HEAD", Some(obj_name)) => {
            let st = state.lock().expect("lock poisoned");
            let req_gen = query.get("generation").and_then(|g| g.parse::<u64>().ok());
            let Some(o) = st.buckets.get(&bucket).and_then(|b| {
                b.objects.iter().find(|o| {
                    o.name == obj_name
                        && match req_gen {
                            Some(g) => o.generation == g,
                            None => !o.deleted,
                        }
                })
            }) else {
                return HttpResponse::xml(
                    404,
                    "Not Found",
                    "<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>".into(),
                );
            };
            HttpResponse {
                status: 200,
                reason: "OK",
                headers: vec![
                    ("Content-Type".into(), o.content_type.clone()),
                    ("Content-Length".into(), o.data.len().to_string()),
                    ("ETag".into(), format!("\"{}\"", o.md5_hex())),
                    ("x-goog-generation".into(), o.generation.to_string()),
                    ("x-goog-metageneration".into(), o.metageneration.to_string()),
                    (
                        "x-goog-hash".into(),
                        format!("crc32c={}, md5={}", o.crc32c_b64(), o.md5_b64()),
                    ),
                ],
                body: if req.method == "HEAD" {
                    Vec::new()
                } else {
                    o.data.clone()
                },
            }
        }
        ("PUT", Some(obj_name)) => {
            let mut st = state.lock().expect("lock poisoned");
            let ct = req
                .headers
                .get("content-type")
                .cloned()
                .unwrap_or_else(|| "application/octet-stream".into());
            let ce = req.headers.get("content-encoding").cloned();
            let mut meta = BTreeMap::new();
            for (k, v) in &req.headers {
                if let Some(mk) = k.strip_prefix("x-goog-meta-") {
                    meta.insert(mk.to_string(), v.clone());
                }
            }
            let csek = req
                .headers
                .get("x-goog-encryption-algorithm")
                .zip(req.headers.get("x-goog-encryption-key-sha256"))
                .map(|(alg, sha)| (alg.clone(), sha.clone()));
            match st.put_object_full(&bucket, &obj_name, req.body.clone(), &ct, ce, meta, None) {
                Some(mut obj) => {
                    if let Some(enc) = csek {
                        obj.customer_encryption = Some(enc.clone());
                        if let Some(b) = st.buckets.get_mut(&bucket) {
                            if let Some(stored) = b
                                .objects
                                .iter_mut()
                                .find(|o| o.generation == obj.generation)
                            {
                                stored.customer_encryption = Some(enc);
                            }
                        }
                    }
                    HttpResponse {
                        status: 200,
                        reason: "OK",
                        headers: vec![
                            ("ETag".into(), format!("\"{}\"", obj.md5_hex())),
                            ("x-goog-generation".into(), obj.generation.to_string()),
                            (
                                "x-goog-metageneration".into(),
                                obj.metageneration.to_string(),
                            ),
                            (
                                "x-goog-hash".into(),
                                format!("crc32c={}, md5={}", obj.crc32c_b64(), obj.md5_b64()),
                            ),
                        ],
                        body: Vec::new(),
                    }
                }
                None => HttpResponse::xml(
                    404,
                    "Not Found",
                    "<Error><Code>NoSuchBucket</Code><Message>No such bucket</Message></Error>"
                        .into(),
                ),
            }
        }
        ("DELETE", Some(obj_name)) => {
            let mut st = state.lock().expect("lock poisoned");
            let req_gen = query.get("generation").and_then(|g| g.parse::<u64>().ok());
            if let Some(b) = st.buckets.get_mut(&bucket) {
                if let Some(g) = req_gen {
                    b.objects
                        .retain(|o| !(o.name == obj_name && o.generation == g));
                } else {
                    b.objects.retain(|o| o.name != obj_name);
                }
                return HttpResponse::empty(204, "No Content");
            }
            HttpResponse::xml(
                404,
                "Not Found",
                "<Error><Code>NoSuchBucket</Code><Message>No such bucket</Message></Error>".into(),
            )
        }
        _ => HttpResponse::error(404, "Not Found", "Unhandled route", "notFound"),
    }
}

fn predefined_acl_entries(
    canned: &str,
    bucket: &str,
    object: Option<&str>,
    is_defacl: bool,
) -> Vec<Value> {
    let kind = if object.is_some() || is_defacl {
        "storage#objectAccessControl"
    } else {
        "storage#bucketAccessControl"
    };
    let mk = |entity: &str, role: &str| {
        let mut entry = json!({
            "kind": kind,
            "bucket": bucket,
            "entity": entity,
            "role": role,
        });
        if let Some(obj) = object {
            entry["object"] = json!(obj);
        }
        entry
    };
    let mut entries = if is_defacl && canned.eq_ignore_ascii_case("private") {
        Vec::new()
    } else {
        vec![mk("project-owners-123", "OWNER")]
    };
    match canned {
        "publicRead" | "public-read" => {
            entries.push(mk("allUsers", "READER"));
        }
        "publicReadWrite" | "public-read-write" => {
            entries.push(mk("allUsers", "WRITER"));
        }
        "authenticatedRead" | "authenticated-read" => {
            entries.push(mk("allAuthenticatedUsers", "READER"));
        }
        "projectPrivate" | "project-private" => {
            entries.push(mk("project-editors-123", "OWNER"));
            entries.push(mk("project-viewers-123", "READER"));
        }
        "bucketOwnerRead" | "bucket-owner-read" => {
            entries.push(mk("project-owners-123", "READER"));
        }
        "bucketOwnerFullControl" | "bucket-owner-full-control" => {}
        _ => {}
    }
    entries
}

fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

fn parse_byte_range(header: &str, total_len: usize) -> Option<(usize, usize)> {
    let spec = header.strip_prefix("bytes=")?;
    let (s, e) = spec.split_once('-')?;
    if s.is_empty() {
        let suffix: usize = e.parse().ok()?;
        if suffix == 0 || total_len == 0 {
            return Some((total_len, total_len));
        }
        let start = total_len.saturating_sub(suffix);
        return Some((start, total_len - 1));
    }
    let start: usize = s.parse().ok()?;
    let end: usize = if e.is_empty() {
        total_len.saturating_sub(1)
    } else {
        e.parse().ok()?
    };
    Some((start, end))
}
