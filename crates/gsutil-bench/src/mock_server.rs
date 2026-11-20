//! Lightweight in-process async HTTP/1.1 Mock GCS JSON v1 server for
//! deterministic `-m` parallel fanout benchmarking.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[derive(Default)]
struct Store {
    objects: BTreeMap<(String, String), Vec<u8>>,
}

pub struct BenchMockGcs {
    pub addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl BenchMockGcs {
    pub async fn start(
        seed_bucket: &str,
        seed_objects: Vec<(String, Vec<u8>)>,
    ) -> std::io::Result<Self> {
        let store = Arc::new(Mutex::new(Store::default()));
        {
            let mut st = store.lock().unwrap();
            for (k, v) in seed_objects {
                st.objects.insert((seed_bucket.to_string(), k), v);
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (tx, mut rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accept_res = listener.accept() => {
                        if let Ok((stream, _)) = accept_res {
                            let st = Arc::clone(&store);
                            tokio::spawn(async move {
                                let _ = handle_conn(stream, st).await;
                            });
                        }
                    }
                }
            }
        });

        Ok(Self {
            addr,
            shutdown_tx: Some(tx),
        })
    }

    pub fn host(&self) -> String {
        self.addr.ip().to_string()
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl Drop for BenchMockGcs {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn handle_conn(mut stream: TcpStream, store: Arc<Mutex<Store>>) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];

    let header_end = loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let target = parts.next().unwrap_or("/");

    let mut content_len: usize = 0;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            }
        }
    }

    while buf.len() < header_end + content_len {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = &buf[header_end..(header_end + content_len).min(buf.len())];

    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    if method == "POST" && path == "/oauth2/token" {
        let tok = r#"{"access_token":"bench-mock-token","expires_in":3600,"token_type":"Bearer"}"#;
        write_resp(&mut stream, "200 OK", "application/json", tok.as_bytes()).await?;
        return Ok(());
    }

    // Route GCS JSON API v1 endpoints.
    if method == "GET" && path.starts_with("/storage/v1/b/") {
        let rest = &path["/storage/v1/b/".len()..];
        if let Some((bucket, after)) = rest.split_once("/o/") {
            let obj_name = percent_decode(after);
            let data_opt = store
                .lock()
                .unwrap()
                .objects
                .get(&(bucket.to_string(), obj_name.clone()))
                .cloned();
            match data_opt {
                Some(data) if query.contains("alt=media") => {
                    write_resp(&mut stream, "200 OK", "application/octet-stream", &data).await?;
                }
                Some(data) => {
                    let crc = gsutil_core::hash::crc32c_base64(&data);
                    let md5 = gsutil_core::hash::md5_base64(&data);
                    let json = serde_json::json!({
                        "kind": "storage#object",
                        "bucket": bucket,
                        "name": obj_name,
                        "generation": "1",
                        "metageneration": "1",
                        "size": data.len().to_string(),
                        "crc32c": crc,
                        "md5Hash": md5,
                    })
                    .to_string();
                    write_resp(&mut stream, "200 OK", "application/json", json.as_bytes()).await?;
                }
                None => {
                    let err = r#"{"error":{"code":404,"message":"Not Found"}}"#;
                    write_resp(
                        &mut stream,
                        "404 Not Found",
                        "application/json",
                        err.as_bytes(),
                    )
                    .await?;
                }
            }
            return Ok(());
        } else if let Some(bucket) = rest.strip_suffix("/o") {
            let items: Vec<serde_json::Value> = {
                let st = store.lock().unwrap();
                st.objects
                    .iter()
                    .filter(|((b, _), _)| b == bucket)
                    .map(|((_, name), data)| {
                        serde_json::json!({
                            "kind": "storage#object",
                            "bucket": bucket,
                            "name": name,
                            "generation": "1",
                            "metageneration": "1",
                            "size": data.len().to_string(),
                            "crc32c": gsutil_core::hash::crc32c_base64(data),
                            "md5Hash": gsutil_core::hash::md5_base64(data),
                        })
                    })
                    .collect()
            };
            let json = serde_json::json!({ "kind": "storage#objects", "items": items }).to_string();
            write_resp(&mut stream, "200 OK", "application/json", json.as_bytes()).await?;
            return Ok(());
        } else if !rest.contains('/') {
            let json = serde_json::json!({
                "kind": "storage#bucket",
                "id": rest,
                "name": rest,
                "location": "US",
                "storageClass": "STANDARD"
            })
            .to_string();
            write_resp(&mut stream, "200 OK", "application/json", json.as_bytes()).await?;
            return Ok(());
        }
    } else if method == "POST" && path.starts_with("/upload/storage/v1/b/") {
        let rest = &path["/upload/storage/v1/b/".len()..];
        let bucket = rest.strip_suffix("/o").unwrap_or(rest);
        let obj_name = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("name="))
            .map(percent_decode)
            .unwrap_or_else(|| "uploaded".to_string());
        let data = body.to_vec();
        let crc = gsutil_core::hash::crc32c_base64(&data);
        let md5 = gsutil_core::hash::md5_base64(&data);
        let size = data.len();
        store
            .lock()
            .unwrap()
            .objects
            .insert((bucket.to_string(), obj_name.clone()), data);
        let json = serde_json::json!({
            "kind": "storage#object",
            "bucket": bucket,
            "name": obj_name,
            "generation": "1",
            "metageneration": "1",
            "size": size.to_string(),
            "crc32c": crc,
            "md5Hash": md5,
        })
        .to_string();
        write_resp(&mut stream, "200 OK", "application/json", json.as_bytes()).await?;
        return Ok(());
    }

    write_resp(
        &mut stream,
        "404 Not Found",
        "application/json",
        br#"{"error":{"code":404,"message":"Not Found"}}"#,
    )
    .await
}

async fn write_resp(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bench_mock_gcs_starts_and_serves() {
        let srv = BenchMockGcs::start("bkt", vec![("a.txt".to_string(), b"hello".to_vec())])
            .await
            .unwrap();
        let mut stream = TcpStream::connect(srv.addr).await.unwrap();
        stream
            .write_all(b"GET /storage/v1/b/bkt/o HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).await.unwrap();
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("a.txt"));
    }
}
