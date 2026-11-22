//! `signurl` command handler supporting V2 and V4 GCS Signed URLs.
//!
//! Matches `gslib/commands/signurl.py` and `gslib/utils/signurl_helper.py`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use pkcs8::DecodePrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use gsutil_core::api::SignUrlOptions;
use gsutil_core::error::{GsutilError, Result};

use crate::{expand_cloud_urls, parse_duration_secs, AdminContext};

const V4_SIGNING_ALGO: &str = "GOOG4-RSA-SHA256";
const V4_UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
const DEFAULT_HOST: &str = "storage.googleapis.com";
const MAX_V4_DURATION_SECS: u64 = 7 * 86_400; // 7 days

#[derive(Deserialize)]
struct ServiceAccountKeyFile {
    client_email: String,
    private_key: String,
}

impl std::fmt::Debug for ServiceAccountKeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccountKeyFile")
            .field("client_email", &self.client_email)
            .field("private_key", &"<REDACTED>")
            .finish()
    }
}

/// RFC 3986 percent-encode a query parameter value (`%20` for spaces, matching GCS V4 signing).
fn quote_rfc3986(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

/// Percent-encode an object path while preserving `/` separators (`%20` for spaces).
fn encode_gcs_path(path: &str) -> String {
    path.split('/')
        .map(quote_rfc3986)
        .collect::<Vec<_>>()
        .join("/")
}

/// Build the V4 string-to-sign and canonical query string (matching `signurl_helper.CreatePayload`).
#[allow(clippy::too_many_arguments)]
pub fn build_v4_payload(
    client_email: &str,
    method: &str,
    duration_secs: u64,
    path: &str,
    generation: Option<&str>,
    region: &str,
    signed_headers: &BTreeMap<String, String>,
    billing_project: Option<&str>,
    now: DateTime<Utc>,
) -> (String, String) {
    let canonical_day = now.format("%Y%m%d").to_string();
    let canonical_time = now.format("%Y%m%dT%H%M%SZ").to_string();
    let canonical_scope = format!("{canonical_day}/{region}/storage/goog4_request");

    let sorted_header_keys: Vec<String> = signed_headers
        .keys()
        .map(|k| k.to_ascii_lowercase())
        .collect();
    let canonical_signed_headers = sorted_header_keys.join(";");

    let mut query_params: BTreeMap<&str, String> = BTreeMap::new();
    query_params.insert("x-goog-algorithm", V4_SIGNING_ALGO.to_string());
    query_params.insert(
        "x-goog-credential",
        format!("{client_email}/{canonical_scope}"),
    );
    query_params.insert("x-goog-date", canonical_time.clone());
    query_params.insert("x-goog-expires", duration_secs.to_string());
    query_params.insert("x-goog-signedheaders", canonical_signed_headers.clone());

    if let Some(proj) = billing_project {
        query_params.insert("userProject", proj.to_string());
    }
    if let Some(gen) = generation {
        query_params.insert("generation", gen.to_string());
    }

    let canonical_query_string = query_params
        .iter()
        .map(|(k, v)| format!("{k}={}", quote_rfc3986(v)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_headers = signed_headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k.to_ascii_lowercase(), v.trim()))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    let canonical_resource = format!("/{path}");
    let canonical_request = format!(
        "{method}\n{canonical_resource}\n{canonical_query_string}\n{canonical_headers}\n{canonical_signed_headers}\n{V4_UNSIGNED_PAYLOAD}"
    );

    let hashed_request = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign =
        format!("{V4_SIGNING_ALGO}\n{canonical_time}\n{canonical_scope}\n{hashed_request}");
    (string_to_sign, canonical_query_string)
}

/// Sign a V4 URL locally using an RSA private key.
#[allow(clippy::too_many_arguments)]
pub fn sign_url_v4(
    private_key: &RsaPrivateKey,
    client_email: &str,
    method: &str,
    duration_secs: u64,
    host: &str,
    path: &str,
    generation: Option<&str>,
    region: &str,
    signed_headers: &BTreeMap<String, String>,
    billing_project: Option<&str>,
    now: DateTime<Utc>,
) -> Result<String> {
    if duration_secs > MAX_V4_DURATION_SECS {
        return Err(GsutilError::command(
            "Max allowed duration for V4 signed URLs is 7 days (604800 seconds).",
        ));
    }
    let encoded_path = encode_gcs_path(path);
    let (string_to_sign, canonical_query_string) = build_v4_payload(
        client_email,
        method,
        duration_secs,
        &encoded_path,
        generation,
        region,
        signed_headers,
        billing_project,
        now,
    );

    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let sig = signing_key.sign(string_to_sign.as_bytes());
    let sig_hex = hex::encode(sig.to_bytes());

    Ok(format!(
        "https://{host}/{encoded_path}?x-goog-signature={sig_hex}&{canonical_query_string}"
    ))
}

/// Sign a V2 URL locally using an RSA private key (RSA-SHA256).
#[allow(clippy::too_many_arguments)]
pub fn sign_url_v2(
    private_key: &RsaPrivateKey,
    client_email: &str,
    method: &str,
    duration_secs: u64,
    host: &str,
    path: &str,
    content_type: Option<&str>,
    generation: Option<&str>,
    now: DateTime<Utc>,
) -> String {
    let expiration = (now + Duration::seconds(duration_secs as i64)).timestamp();
    let encoded_path = encode_gcs_path(path);
    let canonical_resource = match generation {
        Some(gen) => format!("/{encoded_path}?generation={gen}"),
        None => format!("/{encoded_path}"),
    };
    let ct = content_type.unwrap_or("");
    let string_to_sign = format!("{method}\n\n{ct}\n{expiration}\n{canonical_resource}");

    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let sig = signing_key.sign(string_to_sign.as_bytes());
    let sig_b64 = BASE64.encode(sig.to_bytes());

    let mut url = format!(
        "https://{host}/{encoded_path}?GoogleAccessId={}&Expires={expiration}&Signature={}",
        quote_rfc3986(client_email),
        quote_rfc3986(&sig_b64)
    );
    if let Some(gen) = generation {
        url.push_str(&format!("&generation={}", quote_rfc3986(gen)));
    }
    url
}

pub async fn run_signurl(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    let mut method = "GET".to_string();
    let mut duration_secs: u64 = 3600; // default 1h
    let mut content_type: Option<String> = None;
    let mut region: Option<String> = None;
    let mut billing_project: Option<String> = None;
    let mut use_iam_sign = false;
    let mut version: u8 = 4;
    let mut p12_password = "notasecret".to_string();
    let mut positional = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-m" => {
                i += 1;
                method = args
                    .get(i)
                    .ok_or_else(|| GsutilError::command("Option -m requires an HTTP method."))?
                    .to_ascii_uppercase();
            }
            "-d" => {
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or_else(|| GsutilError::command("Option -d requires a duration."))?;
                duration_secs = parse_duration_secs(raw)?;
            }
            "-c" => {
                i += 1;
                content_type = Some(
                    args.get(i)
                        .ok_or_else(|| GsutilError::command("Option -c requires a content-type."))?
                        .clone(),
                );
            }
            "-r" => {
                i += 1;
                region = Some(
                    args.get(i)
                        .ok_or_else(|| GsutilError::command("Option -r requires a region."))?
                        .clone(),
                );
            }
            "-b" => {
                i += 1;
                billing_project = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            GsutilError::command("Option -b requires a billing project.")
                        })?
                        .clone(),
                );
            }
            "-u" | "--use-service-account" => use_iam_sign = true,
            "-v" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| GsutilError::command("Option -v requires 2 or 4."))?;
                version = match v.as_str() {
                    "2" | "v2" | "V2" => 2,
                    "4" | "v4" | "V4" => 4,
                    _ => {
                        return Err(GsutilError::command(format!(
                            "Invalid signing version \"{v}\"; expected 2 or 4."
                        )));
                    }
                };
            }
            "-p" => {
                i += 1;
                p12_password = args
                    .get(i)
                    .ok_or_else(|| GsutilError::command("Option -p requires a password."))?
                    .clone();
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }

    if use_iam_sign && billing_project.is_some() {
        return Err(GsutilError::command(
            "Specifying both the -b and --use-service-account options is not allowed.",
        ));
    }

    if !matches!(
        method.as_str(),
        "GET" | "PUT" | "POST" | "DELETE" | "HEAD" | "RESUMABLE"
    ) {
        return Err(GsutilError::command(
            "HTTP method must be one of [GET, HEAD, PUT, DELETE, POST, RESUMABLE].",
        ));
    }

    if use_iam_sign && duration_secs > 12 * 3600 {
        return Err(GsutilError::command(
            "Max valid duration allowed is 12:00:00.",
        ));
    }
    if version == 4 && duration_secs > MAX_V4_DURATION_SECS {
        return Err(GsutilError::command(
            "Max valid duration allowed is 7 days.",
        ));
    }

    let is_resumable = method == "RESUMABLE";
    let http_method = if is_resumable {
        "POST".to_string()
    } else {
        method.clone()
    };

    let (key_file_opt, url_args) = if use_iam_sign {
        if positional.is_empty() {
            return Err(GsutilError::command(
                "The command requires one or more URL arguments.",
            ));
        }
        (None, positional.as_slice())
    } else {
        if positional.len() < 2 {
            return Err(GsutilError::command(
                "The command requires a key file argument and one or more URL arguments.",
            ));
        }
        (Some(positional[0].as_str()), &positional[1..])
    };

    // Validate all URLs are gs:// before reading key files or signing.
    for raw in url_args {
        if !raw.starts_with("gs://") {
            return Err(GsutilError::command(format!(
                "Can only create signed urls from gs:// urls, got: {raw}"
            )));
        }
    }

    let loaded_key = if let Some(key_path) = key_file_opt {
        let raw_bytes = std::fs::read(key_path).map_err(|e| {
            GsutilError::command(format!(
                "Could not read private key file \"{key_path}\": {e}"
            ))
        })?;
        let looks_like_json = std::str::from_utf8(&raw_bytes)
            .ok()
            .is_some_and(|s| s.trim_start().starts_with('{'));
        if !looks_like_json || key_path.to_ascii_lowercase().ends_with(".p12") {
            let (email, rsa_key) = load_p12_key(key_path, &p12_password)?;
            Some((email, rsa_key))
        } else {
            let raw = String::from_utf8(raw_bytes).map_err(|e| {
                GsutilError::command(format!(
                    "Could not read private key file \"{key_path}\": {e}"
                ))
            })?;
            let sa_key: ServiceAccountKeyFile = serde_json::from_str(&raw).map_err(|e| {
                GsutilError::command(format!(
                    "Could not parse service account JSON key \"{key_path}\": {e}"
                ))
            })?;
            let rsa_key = RsaPrivateKey::from_pkcs8_pem(&sa_key.private_key).map_err(|e| {
                GsutilError::command(format!("Invalid RSA private key in \"{key_path}\": {e}"))
            })?;
            Some((sa_key.client_email, rsa_key))
        }
    } else {
        None
    };

    let urls = expand_cloud_urls(ctx, url_args, false, false).await?;
    if is_resumable && urls.iter().any(|u| u.is_bucket()) {
        return Err(GsutilError::command(
            "Resumable signed URLs require an object name.",
        ));
    }
    let now = Utc::now();
    let expiration_str = (now + Duration::seconds(duration_secs as i64))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    writeln!(ctx.out, "URL\tHTTP Method\tExpiration\tSigned URL")?;

    for u in urls {
        let bname = u.bucket_name.as_deref().unwrap_or("");
        let path = match u.object_name.as_deref() {
            Some(o) => format!("{bname}/{o}"),
            None => bname.to_string(),
        };

        let mut signed_headers = BTreeMap::new();
        signed_headers.insert("host".to_string(), DEFAULT_HOST.to_string());
        if let Some(ref ct) = content_type {
            signed_headers.insert("content-type".to_string(), ct.clone());
        }
        if is_resumable {
            signed_headers.insert("x-goog-resumable".to_string(), "start".to_string());
        }

        let effective_region = match region.as_deref() {
            Some(r) => r.to_ascii_lowercase(),
            None => {
                if u.is_bucket() {
                    match ctx
                        .api
                        .get_bucket(bname, Some(&["location".to_string()]))
                        .await
                    {
                        Ok(meta) => meta
                            .location
                            .map(|l| l.to_ascii_lowercase())
                            .unwrap_or_else(|| "auto".to_string()),
                        Err(_) => {
                            return Err(GsutilError::command(
                                "Generating signed URLs for creating buckets requires a region be specified via the -r option.",
                            ));
                        }
                    }
                } else {
                    ctx.api
                        .get_bucket(bname, Some(&["location".to_string()]))
                        .await
                        .ok()
                        .and_then(|meta| meta.location)
                        .map(|l| l.to_ascii_lowercase())
                        .unwrap_or_else(|| "auto".to_string())
                }
            }
        };

        let signed_url = if let Some((ref client_email, ref rsa_key)) = loaded_key {
            if version == 2 {
                sign_url_v2(
                    rsa_key,
                    client_email,
                    &http_method,
                    duration_secs,
                    DEFAULT_HOST,
                    &path,
                    content_type.as_deref(),
                    u.generation.as_deref(),
                    now,
                )
            } else {
                sign_url_v4(
                    rsa_key,
                    client_email,
                    &http_method,
                    duration_secs,
                    DEFAULT_HOST,
                    &path,
                    u.generation.as_deref(),
                    &effective_region,
                    &signed_headers,
                    billing_project.as_deref(),
                    now,
                )?
            }
        } else {
            ctx.api
                .sign_url(&SignUrlOptions {
                    method: http_method.clone(),
                    duration_secs,
                    path: path.clone(),
                    generation: u.generation.clone(),
                    region: Some(effective_region),
                    signed_headers,
                })
                .await?
        };

        writeln!(
            ctx.out,
            "{}\t{http_method}\t{expiration_str}\t{signed_url}",
            u.url_string()
        )?;
    }

    Ok(())
}

/// Extract an RSA private key and service account email (CN) from a legacy `.p12` PKCS12 bundle.
fn load_p12_key(key_path: &str, password: &str) -> Result<(String, RsaPrivateKey)> {
    let pass_arg = format!("pass:{password}");
    let run_openssl = |extra_args: &[&str]| -> std::io::Result<std::process::Output> {
        let mut cmd = std::process::Command::new("openssl");
        cmd.arg("pkcs12")
            .arg("-in")
            .arg(key_path)
            .arg("-nodes")
            .arg("-passin")
            .arg(&pass_arg);
        for a in extra_args {
            cmd.arg(a);
        }
        cmd.output()
    };

    let output = match run_openssl(&["-legacy"]) {
        Ok(out) if out.status.success() => out,
        _ => run_openssl(&[]).map_err(|e| {
            GsutilError::command(format!(
                "Could not invoke openssl to read PKCS12 key \"{key_path}\": {e}"
            ))
        })?,
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GsutilError::command(format!(
            "Could not parse PKCS12 key \"{key_path}\": {}",
            stderr.trim()
        )));
    }
    let pem_all = String::from_utf8_lossy(&output.stdout);
    let key_start = pem_all
        .find("-----BEGIN PRIVATE KEY-----")
        .or_else(|| pem_all.find("-----BEGIN RSA PRIVATE KEY-----"))
        .ok_or_else(|| {
            GsutilError::command(format!(
                "No private key found inside PKCS12 file \"{key_path}\"."
            ))
        })?;
    let key_pem = &pem_all[key_start..];
    let rsa_key = RsaPrivateKey::from_pkcs8_pem(key_pem).map_err(|e| {
        GsutilError::command(format!(
            "Invalid RSA private key extracted from \"{key_path}\": {e}"
        ))
    })?;

    // Extract CN= from subject line if present, otherwise fallback to filename stem.
    let email = pem_all
        .lines()
        .find(|l| l.trim_start().starts_with("subject="))
        .and_then(|l| {
            l.split("CN=").nth(1).map(|rest| {
                rest.split(['/', ','])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string()
            })
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "service-account@developer.gserviceaccount.com".to_string());

    Ok((email, rsa_key))
}
