//! Enterprise Certificate Proxy (ECP) HTTP proxy support for mTLS / Context-Aware Access.
//!
//! On workstations where Context-Aware Access mTLS/ECP is configured via `/etc/gcloud/certificate_config.json`
//! and `ecp_http_proxy`, GCS requests are routed over plain localhost HTTP to `ecp_http_proxy`
//! with header `x-goog-ecpproxy-target-host: storage.mtls.googleapis.com`.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gsutil_auth::adc::certificate_config_path;
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result};
use gsutil_core::signals::{register_cleanup, CleanupGuard};
use serde::Deserialize;
use tracing::debug;

use crate::client::MTLS_GCS_HOST;

/// Environment variable pointing to an already-running `ecp_http_proxy` localhost port.
pub const ECP_PROXY_PORT_ENV: &str = "GSUTIL_ECP_PROXY_PORT";

/// HTTP header instructing `ecp_http_proxy` which upstream mTLS host to connect to.
pub const ECP_TARGET_HOST_HEADER: &str = "x-goog-ecpproxy-target-host";

#[derive(Deserialize)]
struct CertificateConfig {
    libs: Option<CertificateConfigLibs>,
}

#[derive(Deserialize)]
struct CertificateConfigLibs {
    ecp_http_proxy: Option<String>,
}

/// Handle to a shared or auto-spawned `ecp_http_proxy` localhost process.
///
/// When auto-spawned, the child process is terminated cleanly both on [`Drop`]
/// and via `gsutil_core::signals` on `SIGINT`/`SIGTERM`.
pub struct EcpProxy {
    port: u16,
    child: Option<Arc<Mutex<Option<Child>>>>,
    _cleanup_guard: Option<CleanupGuard>,
}

impl std::fmt::Debug for EcpProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcpProxy")
            .field("port", &self.port)
            .field("managed_child", &self.child.is_some())
            .finish()
    }
}

impl Drop for EcpProxy {
    fn drop(&mut self) {
        if let Some(ref child_arc) = self.child {
            kill_child_handle(child_arc);
        }
    }
}

fn kill_child_handle(child_arc: &Mutex<Option<Child>>) {
    if let Ok(mut guard) = child_arc.lock() {
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl EcpProxy {
    /// Detect an existing `GSUTIL_ECP_PROXY_PORT` or auto-spawn `ecp_http_proxy` from
    /// `certificate_config.json` when no custom `gs_json_host` is configured.
    pub fn detect_or_spawn(boto_config: &BotoConfig) -> Result<Option<Arc<Self>>> {
        // Never hijack custom endpoints (e.g. mock servers or custom gs_json_host).
        if boto_config
            .get("Credentials", "gs_json_host")
            .is_some_and(|s| !s.trim().is_empty())
        {
            return Ok(None);
        }

        // Respect explicit opt-out in .boto.
        if boto_config.has_option("Credentials", "use_client_certificate")
            && !boto_config.get_bool("Credentials", "use_client_certificate", true)
        {
            return Ok(None);
        }

        // 1. Reuse an already-running proxy if GSUTIL_ECP_PROXY_PORT is set.
        if let Ok(port_str) = env::var(ECP_PROXY_PORT_ENV) {
            let trimmed = port_str.trim();
            if !trimmed.is_empty() {
                let port: u16 = trimmed.parse().map_err(|_| {
                    GsutilError::command(format!(
                        "Invalid {ECP_PROXY_PORT_ENV} value \"{trimmed}\": expected TCP port number"
                    ))
                })?;
                if port > 0 {
                    debug!("Using existing ECP proxy on 127.0.0.1:{port}");
                    return Ok(Some(Arc::new(Self {
                        port,
                        child: None,
                        _cleanup_guard: None,
                    })));
                }
            }
        }

        // 2. Auto-spawn ecp_http_proxy if certificate_config.json points to an executable binary.
        let Some(cfg_path) = certificate_config_path() else {
            return Ok(None);
        };
        let Some(proxy_bin) = extract_ecp_http_proxy_bin(&cfg_path) else {
            return Ok(None);
        };
        if !proxy_bin.is_file() {
            return Ok(None);
        }

        Self::spawn(&proxy_bin, &cfg_path).map(|p| Some(Arc::new(p)))
    }

    /// Spawn `ecp_http_proxy` on an ephemeral localhost port and wait for `/readyz` HTTP 200.
    pub fn spawn(proxy_bin: &Path, cert_config_path: &Path) -> Result<Self> {
        let port = pick_ephemeral_port()?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let nonce = format!("gsutil-rs-{}-{nanos}", std::process::id());

        debug!(
            "Spawning ECP proxy {} on 127.0.0.1:{port} with config {}",
            proxy_bin.display(),
            cert_config_path.display()
        );

        let mut child = Command::new(proxy_bin)
            .arg(format!(
                "-enterprise_certificate_file_path={}",
                cert_config_path.display()
            ))
            .arg(format!("-nonce_token={nonce}"))
            .arg(format!("-port={port}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                GsutilError::command(format!(
                    "Failed to spawn ecp_http_proxy ({}): {e}",
                    proxy_bin.display()
                ))
            })?;

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(GsutilError::command(format!(
                    "ecp_http_proxy exited prematurely with status {status}"
                )));
            }
            if check_readyz(port, &nonce) {
                debug!("ECP proxy ready on 127.0.0.1:{port}");
                let child_arc = Arc::new(Mutex::new(Some(child)));
                let cleanup_arc = Arc::clone(&child_arc);
                let guard = register_cleanup(move || {
                    kill_child_handle(&cleanup_arc);
                });
                return Ok(Self {
                    port,
                    child: Some(child_arc),
                    _cleanup_guard: Some(guard),
                });
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        let _ = child.kill();
        let _ = child.wait();
        Err(GsutilError::command(format!(
            "Timed out waiting for ecp_http_proxy /readyz on 127.0.0.1:{port}"
        )))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Rewrite a `https://<service>.googleapis.com/...` URL to route through this local ECP proxy,
    /// returning `(rewritten_url, Some("<service>.mtls.googleapis.com"))` when rewritten.
    pub fn rewrite_google_api_url(&self, url: &str) -> (String, Option<String>) {
        for (plain, mtls) in [
            (
                "https://storage.mtls.googleapis.com",
                "storage.mtls.googleapis.com",
            ),
            (
                "https://storage.googleapis.com",
                "storage.mtls.googleapis.com",
            ),
            (
                "https://cloudkms.mtls.googleapis.com",
                "cloudkms.mtls.googleapis.com",
            ),
            (
                "https://cloudkms.googleapis.com",
                "cloudkms.mtls.googleapis.com",
            ),
            (
                "https://pubsub.mtls.googleapis.com",
                "pubsub.mtls.googleapis.com",
            ),
            (
                "https://pubsub.googleapis.com",
                "pubsub.mtls.googleapis.com",
            ),
            (
                "https://iamcredentials.mtls.googleapis.com",
                "iamcredentials.mtls.googleapis.com",
            ),
            (
                "https://iamcredentials.googleapis.com",
                "iamcredentials.mtls.googleapis.com",
            ),
        ] {
            if let Some(rest) = url.strip_prefix(plain) {
                return (format!("{}{}", self.origin(), rest), Some(mtls.to_string()));
            }
        }
        (url.to_string(), None)
    }

    /// Rewrite a `https://storage*.googleapis.com/...` URL to route through this local ECP proxy.
    pub fn rewrite_gcs_url(&self, url: &str) -> String {
        self.rewrite_google_api_url(url).0
    }

    pub fn target_host(&self) -> &'static str {
        MTLS_GCS_HOST
    }
}

fn extract_ecp_http_proxy_bin(cfg_path: &Path) -> Option<PathBuf> {
    let raw = fs::read_to_string(cfg_path).ok()?;
    let parsed: CertificateConfig = serde_json::from_str(&raw).ok()?;
    let bin = parsed.libs?.ecp_http_proxy?;
    if bin.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(bin))
    }
}

fn pick_ephemeral_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| GsutilError::command(format!("Failed to bind ephemeral port for ECP: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| GsutilError::command(format!("Failed to read ephemeral port: {e}")))?
        .port();
    Ok(port)
}

fn check_readyz(port: u16, expected_nonce: &str) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
    let req =
        format!("GET /readyz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 1024];
    let Ok(n) = stream.read(&mut buf) else {
        return false;
    };
    let resp = String::from_utf8_lossy(&buf[..n]);
    resp.starts_with("HTTP/1.1 200") && (expected_nonce.is_empty() || resp.contains(expected_nonce))
}
