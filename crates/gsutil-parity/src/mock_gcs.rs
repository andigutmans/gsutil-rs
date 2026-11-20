//! In-process deterministic Mock GCS JSON v1 HTTP server for hermetic testing.
//!
//! Supports bucket/object CRUD, listing with `prefix`/`delimiter`/`versions`,
//! media downloads with HTTP `Range`, simple/multipart/resumable uploads,
//! preconditions (`ifGenerationMatch` -> 412), and deterministic fault buckets
//! (`fault-403`, `fault-404`, `fault-409`, `fault-412`, `fault-500`, `fault-503`).

use base64::Engine;
use chrono::{DateTime, Utc};
use md5::{Digest, Md5};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Stored mock object version.
#[derive(Debug, Clone)]
pub struct MockObject {
    pub bucket: String,
    pub name: String,
    pub generation: u64,
    pub metageneration: u64,
    pub content_type: String,
    pub data: Vec<u8>,
    pub time_created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: bool,
    pub storage_class: String,
    pub metadata: BTreeMap<String, String>,
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

    pub fn to_json(&self) -> Value {
        let mut obj = json!({
            "kind": "storage#object",
            "id": format!("{}/{}/{}", self.bucket, self.name, self.generation),
            "name": self.name,
            "bucket": self.bucket,
            "generation": self.generation.to_string(),
            "metageneration": self.metageneration.to_string(),
            "contentType": self.content_type,
            "timeCreated": self.time_created.to_rfc3339(),
            "updated": self.updated.to_rfc3339(),
            "timeStorageClassUpdated": self.time_created.to_rfc3339(),
            "storageClass": self.storage_class,
            "size": self.data.len().to_string(),
            "md5Hash": self.md5_b64(),
            "crc32c": self.crc32c_b64(),
            "etag": format!("etag-{}-{}", self.generation, self.metageneration),
        });
        if !self.metadata.is_empty() {
            obj["metadata"] = json!(self.metadata);
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
    pub time_created: DateTime<Utc>,
    pub objects: Vec<MockObject>,
    pub extra_fields: BTreeMap<String, Value>,
    pub iam_policy: Value,
    pub notifications: Vec<Value>,
}

impl MockBucket {
    pub fn to_json(&self) -> Value {
        let mut obj = json!({
            "kind": "storage#bucket",
            "id": self.name,
            "name": self.name,
            "location": self.location,
            "locationType": "multi-region",
            "storageClass": self.storage_class,
            "timeCreated": self.time_created.to_rfc3339(),
            "updated": self.time_created.to_rfc3339(),
            "metageneration": "1",
            "versioning": { "enabled": self.versioning_enabled },
            "etag": "CAE=",
        });
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

#[derive(Debug, Default)]
pub struct MockGcsState {
    pub buckets: BTreeMap<String, MockBucket>,
    pub next_generation: u64,
    pub resumable_sessions: BTreeMap<String, (String, String, String)>,
    pub request_log: Vec<String>,
}

impl MockGcsState {
    pub fn new() -> Self {
        Self {
            buckets: BTreeMap::new(),
            next_generation: 1_700_000_000_000_000,
            resumable_sessions: BTreeMap::new(),
            request_log: Vec::new(),
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
        self.buckets.insert(
            name.to_string(),
            MockBucket {
                name: name.to_string(),
                location: location.to_string(),
                storage_class: storage_class.to_string(),
                versioning_enabled: false,
                time_created: Utc::now(),
                objects: Vec::new(),
                extra_fields: BTreeMap::new(),
                iam_policy: json!({
                    "kind": "storage#policy",
                    "resourceId": format!("projects/_/buckets/{name}"),
                    "version": 1,
                    "etag": "CAE=",
                    "bindings": []
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
        let gen = self.next_gen();
        let b = self.buckets.get_mut(bucket)?;
        let now = Utc::now();
        // Mark any existing live object with same name as deleted if versioning is on, else remove it.
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
        let obj = MockObject {
            bucket: bucket.to_string(),
            name: name.to_string(),
            generation: gen,
            metageneration: 1,
            content_type: content_type.to_string(),
            data,
            time_created: now,
            updated: now,
            deleted: false,
            storage_class: b.storage_class.clone(),
            metadata: BTreeMap::new(),
        };
        b.objects.push(obj.clone());
        Some(obj)
    }
}

/// Running handle for the in-process Mock GCS server.
pub struct MockGcsServer {
    pub addr: SocketAddr,
    pub state: Arc<Mutex<MockGcsState>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl MockGcsServer {
    /// Start listening on `127.0.0.1:0` (OS-assigned ephemeral port).
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
                                    let _ = handle_connection(stream, st, addr).await;
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
            state,
            shutdown_tx: Some(shutdown_tx),
        })
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
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

    /// Write a `.boto` configuration file targeting this mock server without TLS.
    pub fn write_boto_config(&self, path: &Path) -> std::io::Result<()> {
        let contents = format!(
            "[Boto]\n\
             num_retries = 1\n\
             [Credentials]\n\
             use_client_certificate = False\n\
             gs_host = http://{ip}\n\
             gs_json_host = http://{ip}\n\
             gs_port = {port}\n\
             gs_json_port = {port}\n\
             [GSUtil]\n\
             prefer_api = json\n\
             default_project_id = mock-project-123\n\
             state_dir = {state_dir}\n",
            ip = self.addr.ip(),
            port = self.addr.port(),
            state_dir = path.parent().unwrap_or_else(|| Path::new("/tmp")).display(),
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

async fn read_request(
    reader: &mut BufReader<&mut TcpStream>,
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

async fn handle_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<MockGcsState>>,
    addr: SocketAddr,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(&mut stream);
    let Some(req) = read_request(&mut reader).await? else {
        return Ok(());
    };
    let resp = route_request(req, &state, addr);

    let mut head = format!("HTTP/1.1 {} {}\r\n", resp.status, resp.reason);
    for (k, v) in &resp.headers {
        head.push_str(&format!("{}: {}\r\n", k, v));
    }
    head.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    head.push_str("Connection: close\r\n\r\n");

    let stream_ref = reader.into_inner();
    stream_ref.write_all(head.as_bytes()).await?;
    stream_ref.write_all(&resp.body).await?;
    stream_ref.flush().await?;
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

fn route_request(
    req: HttpRequest,
    state: &Arc<Mutex<MockGcsState>>,
    addr: SocketAddr,
) -> HttpResponse {
    let (path, query) = parse_query(&req.target);
    {
        let mut st = state.lock().expect("lock poisoned");
        st.request_log
            .push(format!("{} {}", req.method, req.target));
    }

    // Health check endpoint
    if path == "/healthz" {
        return HttpResponse::json(200, "OK", json!({"status": "ok"}));
    }

    // Mock OAuth2 token endpoint for ADC authorized_user credentials
    if path == "/oauth2/token" && req.method == "POST" {
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

    // Mock GCE metadata server endpoints so both Python and Rust gsutil get an instant token
    // without touching real gcloud or the network.
    if path == "/" || path.starts_with("/computeMetadata/v1") {
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

    // Upload endpoints: /upload/storage/v1/b/{bucket}/o
    if let Some(rest) = path.strip_prefix("/upload/storage/v1/b/") {
        if let Some(bucket) = rest.strip_suffix("/o") {
            let bucket = pct_decode(bucket);
            if let Some(fault) = check_fault_bucket(&bucket) {
                return fault;
            }
            return handle_upload(&req, &bucket, &query, state, addr);
        }
    }

    // Standard JSON API endpoints: /storage/v1/b...
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
                        &format!("You already own this bucket. Please select another name. ({name} already exists)"),
                        "conflict",
                    );
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

    if let Some(rest) = path.strip_prefix("/storage/v1/b/") {
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
                        Some(b) => HttpResponse::json(200, "OK", b.to_json()),
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
                    if let Some(map) = body_val.as_object() {
                        for (k, v) in map {
                            if k == "versioning" {
                                if let Some(en) = v.get("enabled").and_then(|x| x.as_bool()) {
                                    b.versioning_enabled = en;
                                }
                            } else if k == "storageClass" {
                                if let Some(sc) = v.as_str() {
                                    b.storage_class = sc.to_string();
                                }
                            } else {
                                b.extra_fields.insert(k.clone(), v.clone());
                            }
                        }
                    }
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
                        Some(b) if b.objects.iter().any(|o| !o.deleted) => HttpResponse::error(
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

        // /storage/v1/b/{bucket}/iam
        if segments.len() == 2 && segments[1] == "iam" {
            let mut st = state.lock().expect("lock poisoned");
            let Some(b) = st.buckets.get_mut(&bucket) else {
                return HttpResponse::error(404, "Not Found", "No such bucket", "notFound");
            };
            return match req.method.as_str() {
                "GET" => HttpResponse::json(200, "OK", b.iam_policy.clone()),
                "PUT" => {
                    let body_val: Value =
                        serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
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

        // /storage/v1/b/{bucket}/notificationConfigs
        if segments.len() == 2 && segments[1] == "notificationConfigs" {
            let mut st = state.lock().expect("lock poisoned");
            let Some(b) = st.buckets.get_mut(&bucket) else {
                return HttpResponse::error(404, "Not Found", "No such bucket", "notFound");
            };
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

        // /storage/v1/b/{bucket}/o/{object}/compose
        if segments.len() == 4
            && segments[1] == "o"
            && segments[3] == "compose"
            && req.method == "POST"
        {
            let dst_obj = pct_decode(segments[2]);
            let body_val: Value = serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
            let mut st = state.lock().expect("lock poisoned");
            let mut combined = Vec::new();
            if let Some(sources) = body_val.get("sourceObjects").and_then(|v| v.as_array()) {
                for src in sources {
                    let sname = src.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let Some(found) = st
                        .buckets
                        .get(&bucket)
                        .and_then(|b| b.objects.iter().find(|o| o.name == sname && !o.deleted))
                    else {
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

        // /storage/v1/b/{bucket}/o
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

            let mut items = Vec::new();
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
                items.push(obj.to_json());
            }
            let mut resp = json!({ "kind": "storage#objects" });
            if !items.is_empty() {
                resp["items"] = json!(items);
            }
            if !prefixes.is_empty() {
                resp["prefixes"] = json!(prefixes.into_iter().collect::<Vec<_>>());
            }
            return HttpResponse::json(200, "OK", resp);
        }

        // /storage/v1/b/{bucket}/o/{object}
        if segments.len() == 3 && segments[1] == "o" {
            let object_name = pct_decode(segments[2]);
            return handle_object(&req, &bucket, &object_name, &query, state);
        }

        // /storage/v1/b/{src_b}/o/{src_o}/copyTo/b/{dst_b}/o/{dst_o} or rewriteTo
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
            let mut st = state.lock().expect("lock poisoned");
            let found = st
                .buckets
                .get(&bucket)
                .and_then(|b| b.objects.iter().find(|o| o.name == src_obj && !o.deleted))
                .cloned();
            let Some(src) = found else {
                return HttpResponse::error(404, "Not Found", "No such object", "notFound");
            };
            let Some(created) = st.put_object(&dst_bucket, &dst_obj, src.data, &src.content_type)
            else {
                return HttpResponse::error(
                    404,
                    "Not Found",
                    "Destination bucket not found",
                    "notFound",
                );
            };
            if segments[3] == "rewriteTo" {
                return HttpResponse::json(
                    200,
                    "OK",
                    json!({
                        "kind": "storage#rewriteResponse",
                        "totalBytesRewritten": created.data.len().to_string(),
                        "objectSize": created.data.len().to_string(),
                        "done": true,
                        "resource": created.to_json(),
                    }),
                );
            }
            return HttpResponse::json(200, "OK", created.to_json());
        }
    }

    HttpResponse::error(
        404,
        "Not Found",
        &format!("Unhandled mock GCS route: {} {}", req.method, path),
        "notFound",
    )
}

fn handle_upload(
    req: &HttpRequest,
    bucket: &str,
    query: &BTreeMap<String, String>,
    state: &Arc<Mutex<MockGcsState>>,
    addr: SocketAddr,
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
        let name = query.get("name").cloned().unwrap_or_else(|| {
            serde_json::from_slice::<Value>(&req.body)
                .ok()
                .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(String::from))
                .unwrap_or_default()
        });
        let mut st = state.lock().expect("lock poisoned");
        if !st.buckets.contains_key(bucket) {
            return HttpResponse::error(404, "Not Found", "Not Found", "notFound");
        }
        let upload_id = format!("sess-{}", st.next_gen());
        st.resumable_sessions
            .insert(upload_id.clone(), (bucket.to_string(), name, content_type));
        let location = format!(
            "http://{}/upload/storage/v1/b/{}/o?uploadType=resumable&upload_id={}",
            addr, bucket, upload_id
        );
        let mut resp = HttpResponse::empty(200, "OK");
        resp.headers.push(("Location".into(), location));
        return resp;
    }

    if req.method == "PUT" {
        if let Some(upload_id) = query.get("upload_id") {
            let mut st = state.lock().expect("lock poisoned");
            if let Some((bkt, name, ct)) = st.resumable_sessions.remove(upload_id) {
                if let Some(obj) = st.put_object(&bkt, &name, req.body.clone(), &ct) {
                    return HttpResponse::json(200, "OK", obj.to_json());
                }
            }
            return HttpResponse::error(404, "Not Found", "Upload session not found", "notFound");
        }
    }

    // Simple media or multipart upload
    let (name, payload, ct) = if upload_type == "multipart" {
        parse_multipart_upload(&content_type, &req.body, query.get("name").cloned())
    } else {
        (
            query.get("name").cloned().unwrap_or_default(),
            req.body.clone(),
            content_type,
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

    match st.put_object(bucket, &name, payload, &ct) {
        Some(obj) => HttpResponse::json(200, "OK", obj.to_json()),
        None => HttpResponse::error(404, "Not Found", "Bucket not found", "notFound"),
    }
}

fn parse_multipart_upload(
    content_type: &str,
    body: &[u8],
    fallback_name: Option<String>,
) -> (String, Vec<u8>, String) {
    let boundary = content_type
        .split("boundary=")
        .nth(1)
        .map(|s| s.trim_matches('"').to_string());
    let Some(boundary) = boundary else {
        return (
            fallback_name.unwrap_or_default(),
            body.to_vec(),
            "application/octet-stream".into(),
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
    let mut data = Vec::new();
    for (idx, part) in parts.iter().enumerate() {
        let sep = b"\r\n\r\n";
        if let Some(h_end) = find_subsequence(part, sep) {
            let part_body = &part[h_end + 4..];
            let trimmed = part_body.strip_suffix(b"\r\n").unwrap_or(part_body);
            if idx == 0 {
                if let Ok(v) = serde_json::from_slice::<Value>(trimmed) {
                    if let Some(n) = v.get("name").and_then(|x| x.as_str()) {
                        name = n.to_string();
                    }
                    if let Some(c) = v.get("contentType").and_then(|x| x.as_str()) {
                        ct = c.to_string();
                    }
                }
            } else {
                data = trimmed.to_vec();
            }
        }
    }
    (name, data, ct)
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
                if let Some(range_hdr) = req.headers.get("range") {
                    if let Some((start, end)) = parse_byte_range(range_hdr, obj.data.len()) {
                        if start >= obj.data.len() {
                            return HttpResponse::error(
                                416,
                                "Requested Range Not Satisfiable",
                                "Range not satisfiable",
                                "requestedRangeNotSatisfiable",
                            );
                        }
                        let slice = obj.data[start..=end.min(obj.data.len() - 1)].to_vec();
                        return HttpResponse {
                            status: 206,
                            reason: "Partial Content",
                            headers: vec![
                                ("Content-Type".into(), obj.content_type.clone()),
                                (
                                    "Content-Range".into(),
                                    format!("bytes {}-{}/{}", start, end, obj.data.len()),
                                ),
                            ],
                            body: slice,
                        };
                    }
                }
                return HttpResponse {
                    status: 200,
                    reason: "OK",
                    headers: vec![
                        ("Content-Type".into(), obj.content_type.clone()),
                        ("x-goog-generation".into(), obj.generation.to_string()),
                    ],
                    body: obj.data.clone(),
                };
            }

            HttpResponse::json(200, "OK", obj.to_json())
        }
        "PATCH" | "PUT" => {
            let body_val: Value = serde_json::from_slice(&req.body).unwrap_or_else(|_| json!({}));
            let mut st = state.lock().expect("lock poisoned");
            let Some(b) = st.buckets.get_mut(bucket) else {
                return HttpResponse::error(404, "Not Found", "No such bucket", "notFound");
            };
            let Some(obj) = b
                .objects
                .iter_mut()
                .find(|o| o.name == object_name && !o.deleted)
            else {
                return HttpResponse::error(
                    404,
                    "Not Found",
                    &format!("No such object: {bucket}/{object_name}"),
                    "notFound",
                );
            };
            if let Some(ct) = body_val.get("contentType").and_then(|v| v.as_str()) {
                obj.content_type = ct.to_string();
            }
            if let Some(meta) = body_val.get("metadata").and_then(|v| v.as_object()) {
                for (k, v) in meta {
                    if let Some(s) = v.as_str() {
                        obj.metadata.insert(k.clone(), s.to_string());
                    } else if v.is_null() {
                        obj.metadata.remove(k);
                    }
                }
            }
            obj.metageneration += 1;
            obj.updated = Utc::now();
            HttpResponse::json(200, "OK", obj.to_json())
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
