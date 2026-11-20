//! Service Account credentials for JSON keyfiles and legacy PKCS12 (`.p12`) keyfiles.
//!
//! Matches `gslib/gcs_json_credentials.py` (`_GetOauth2ServiceAccountCredentials`,
//! `P12Credentials`, `PKCS12Signer`).

use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Command;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use gsutil_core::error::{GsutilError, Result, ServiceError};
use pkcs8::DecodePrivateKey;
use reqwest::Client;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::RwLock;

use crate::{AccessToken, CredentialType, TokenProvider, DEFAULT_SCOPES, DEFAULT_TOKEN_URI};

/// Default password for legacy `.p12` service account keyfiles.
pub const GOOGLE_OAUTH2_DEFAULT_FILE_PASSWORD: &str = "notasecret";

/// Parsed Google Service Account JSON keyfile.
#[derive(Clone, Deserialize)]
pub struct ServiceAccountKey {
    #[serde(rename = "type")]
    pub key_type: Option<String>,
    pub project_id: Option<String>,
    pub private_key_id: String,
    pub private_key: String,
    pub client_email: String,
    pub client_id: String,
    pub token_uri: Option<String>,
}

impl fmt::Debug for ServiceAccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountKey")
            .field("client_email", &self.client_email)
            .field("client_id", &self.client_id)
            .field("private_key_id", &self.private_key_id)
            .field("private_key", &"[REDACTED]")
            .field("token_uri", &self.token_uri)
            .finish()
    }
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'static str,
    typ: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct JwtTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
}

/// Service account credentials backed by an RSA private key (from JSON or P12 keyfile).
pub struct ServiceAccountCredentials {
    client_email: String,
    private_key_id: Option<String>,
    signing_key: SigningKey<Sha256>,
    token_uri: String,
    scopes: String,
    http: Client,
    cached: RwLock<Option<AccessToken>>,
}

impl fmt::Debug for ServiceAccountCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountCredentials")
            .field("client_email", &self.client_email)
            .field("private_key_id", &self.private_key_id)
            .field("token_uri", &self.token_uri)
            .finish()
    }
}

impl ServiceAccountCredentials {
    /// Load service account credentials from a JSON keyfile on disk.
    pub fn from_json_file(
        path: &Path,
        token_uri_override: Option<&str>,
        http: Client,
    ) -> Result<Self> {
        let raw = fs::read_to_string(path).map_err(|e| {
            GsutilError::command(format!(
                "Could not read service account keyfile \"{}\": {e}",
                path.display()
            ))
        })?;
        Self::from_json_str(&raw, &path.display().to_string(), token_uri_override, http)
    }

    /// Parse service account credentials from a JSON string, validating required fields
    /// matching `gslib/gcs_json_credentials.py`.
    pub fn from_json_str(
        raw: &str,
        source_name: &str,
        token_uri_override: Option<&str>,
        http: Client,
    ) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(raw).map_err(|_| {
            GsutilError::command(format!(
                "Could not parse JSON keyfile \"{source_name}\" as valid JSON"
            ))
        })?;

        for required in ["client_id", "client_email", "private_key_id", "private_key"] {
            if value.get(required).and_then(|v| v.as_str()).is_none() {
                return Err(GsutilError::command(format!(
                    "The JSON private key file at {source_name} did not contain the required entry: {required}"
                )));
            }
        }

        let key: ServiceAccountKey = serde_json::from_value(value).map_err(|e| {
            GsutilError::command(format!(
                "Could not parse JSON keyfile \"{source_name}\": {e}"
            ))
        })?;

        let rsa_key = parse_rsa_private_key_pem(&key.private_key)?;
        let token_uri = token_uri_override
            .or(key.token_uri.as_deref())
            .unwrap_or(DEFAULT_TOKEN_URI)
            .to_string();

        Ok(Self {
            client_email: key.client_email,
            private_key_id: Some(key.private_key_id),
            signing_key: SigningKey::<Sha256>::new(rsa_key),
            token_uri,
            scopes: DEFAULT_SCOPES.join(" "),
            http,
            cached: RwLock::new(None),
        })
    }

    /// Construct directly from an RSA private key and metadata (used by P12 loader & tests).
    pub fn from_rsa_key(
        client_email: impl Into<String>,
        private_key_id: Option<String>,
        rsa_key: RsaPrivateKey,
        token_uri: impl Into<String>,
        http: Client,
    ) -> Self {
        Self {
            client_email: client_email.into(),
            private_key_id,
            signing_key: SigningKey::<Sha256>::new(rsa_key),
            token_uri: token_uri.into(),
            scopes: DEFAULT_SCOPES.join(" "),
            http,
            cached: RwLock::new(None),
        }
    }

    /// Build a signed RS256 JWT assertion for Google's OAuth2 token endpoint.
    pub fn build_jwt_assertion(&self) -> Result<String> {
        let now = Utc::now().timestamp();
        let header = JwtHeader {
            alg: "RS256",
            typ: "JWT",
            kid: self.private_key_id.as_deref(),
        };
        let claims = JwtClaims {
            iss: &self.client_email,
            scope: &self.scopes,
            aud: &self.token_uri,
            iat: now,
            exp: now + 3600,
        };

        let header_json = serde_json::to_vec(&header)
            .map_err(|e| GsutilError::command(format!("Failed to serialize JWT header: {e}")))?;
        let claims_json = serde_json::to_vec(&claims)
            .map_err(|e| GsutilError::command(format!("Failed to serialize JWT claims: {e}")))?;

        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&header_json),
            URL_SAFE_NO_PAD.encode(&claims_json)
        );
        let signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        Ok(format!("{signing_input}.{sig_b64}"))
    }

    async fn exchange_jwt(&self) -> Result<AccessToken> {
        let assertion = self.build_jwt_assertion()?;
        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ];

        let resp = self
            .http
            .post(&self.token_uri)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                GsutilError::Service(ServiceError::authentication(
                    format!("Failed to obtain service account access token: {e}"),
                    None,
                    None,
                ))
            })?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(GsutilError::Service(ServiceError::authentication(
                format!(
                    "Service account token exchange failed (HTTP {})",
                    status.as_u16()
                ),
                Some(status.as_u16()),
                Some(body),
            )));
        }

        let parsed: JwtTokenResponse = serde_json::from_str(&body).map_err(|e| {
            GsutilError::Service(ServiceError::authentication(
                format!("Invalid token response from {}: {e}", self.token_uri),
                Some(status.as_u16()),
                None,
            ))
        })?;

        let expires_in = parsed.expires_in.unwrap_or(3600);
        Ok(AccessToken::from_expires_in(
            parsed.access_token,
            expires_in,
        ))
    }
}

#[async_trait]
impl TokenProvider for ServiceAccountCredentials {
    async fn token(&self) -> Result<Option<AccessToken>> {
        {
            let guard = self.cached.read().await;
            if let Some(ref tok) = *guard {
                if !tok.is_expired() {
                    return Ok(Some(tok.clone()));
                }
            }
        }

        let mut guard = self.cached.write().await;
        if let Some(ref tok) = *guard {
            if !tok.is_expired() {
                return Ok(Some(tok.clone()));
            }
        }

        let fresh = self.exchange_jwt().await?;
        *guard = Some(fresh.clone());
        Ok(Some(fresh))
    }

    fn credential_type(&self) -> CredentialType {
        CredentialType::OAuth2ServiceAccount
    }

    fn service_account_email(&self) -> Option<&str> {
        Some(&self.client_email)
    }

    async fn sign_blob(&self, payload: &[u8]) -> Result<(String, Vec<u8>)> {
        let sig = self.signing_key.sign(payload);
        let key_id = self.private_key_id.clone().unwrap_or_default();
        Ok((key_id, sig.to_bytes().to_vec()))
    }
}

/// Legacy PKCS12 (`.p12`) service account credentials wrapper.
///
/// Extracts the RSA private key from a `.p12` file using `openssl pkcs12` (supporting legacy
/// RC2/3DES ciphers when available) and delegates JWT signing & token exchange to
/// [`ServiceAccountCredentials`].
#[derive(Debug)]
pub struct P12ServiceAccountCredentials {
    inner: ServiceAccountCredentials,
}

impl P12ServiceAccountCredentials {
    pub fn from_p12_file(
        path: &Path,
        service_account_email: &str,
        password: Option<&str>,
        token_uri: Option<&str>,
        http: Client,
    ) -> Result<Self> {
        if service_account_email.trim().is_empty() {
            return Err(GsutilError::command(
                "Missing fields: service_account_email.",
            ));
        }

        let pass = password.unwrap_or(GOOGLE_OAUTH2_DEFAULT_FILE_PASSWORD);
        let pass_arg = format!("pass:{pass}");

        // Try with -legacy first (OpenSSL 3.x), falling back to standard flags (OpenSSL 1.1).
        let output = Command::new("openssl")
            .args([
                "pkcs12",
                "-in",
                &path.display().to_string(),
                "-nocerts",
                "-nodes",
                "-legacy",
                "-passin",
                &pass_arg,
            ])
            .output()
            .or_else(|_| {
                Command::new("openssl")
                    .args([
                        "pkcs12",
                        "-in",
                        &path.display().to_string(),
                        "-nocerts",
                        "-nodes",
                        "-passin",
                        &pass_arg,
                    ])
                    .output()
            })
            .map_err(|_| {
                GsutilError::command(
                    "Unable to load the keyfile, Invalid password or PKCS12 data. \
                     Please consider using the .json keyfile.",
                )
            })?;

        let pem_bytes = if output.status.success() {
            output.stdout
        } else {
            // Retry without -legacy in case OpenSSL 1.1 rejected the flag.
            let retry = Command::new("openssl")
                .args([
                    "pkcs12",
                    "-in",
                    &path.display().to_string(),
                    "-nocerts",
                    "-nodes",
                    "-passin",
                    &pass_arg,
                ])
                .output()
                .map_err(|_| {
                    GsutilError::command(
                        "Unable to load the keyfile, Invalid password or PKCS12 data.",
                    )
                })?;
            if !retry.status.success() {
                return Err(GsutilError::command(
                    "Unable to load the keyfile, Invalid password or PKCS12 data.",
                ));
            }
            retry.stdout
        };

        let pem_str = String::from_utf8(pem_bytes).map_err(|_| {
            GsutilError::command("Unable to load the keyfile, Invalid password or PKCS12 data.")
        })?;

        let rsa_key = parse_rsa_private_key_pem(&pem_str)?;
        let inner = ServiceAccountCredentials::from_rsa_key(
            service_account_email,
            None,
            rsa_key,
            token_uri.unwrap_or(DEFAULT_TOKEN_URI),
            http,
        );
        Ok(Self { inner })
    }
}

#[async_trait]
impl TokenProvider for P12ServiceAccountCredentials {
    async fn token(&self) -> Result<Option<AccessToken>> {
        self.inner.token().await
    }

    fn credential_type(&self) -> CredentialType {
        CredentialType::OAuth2ServiceAccount
    }

    fn service_account_email(&self) -> Option<&str> {
        self.inner.service_account_email()
    }

    async fn sign_blob(&self, payload: &[u8]) -> Result<(String, Vec<u8>)> {
        self.inner.sign_blob(payload).await
    }
}

/// Parse an RSA private key from PKCS#8 (`BEGIN PRIVATE KEY`) or PKCS#1 (`BEGIN RSA PRIVATE KEY`) PEM.
pub(crate) fn parse_rsa_private_key_pem(pem: &str) -> Result<RsaPrivateKey> {
    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(pem) {
        return Ok(key);
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(pem) {
        return Ok(key);
    }
    // Extract PEM block if surrounded by Bag Attributes (from openssl pkcs12 output).
    for header in [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
    ] {
        if let Some(start) = pem.find(header) {
            let slice = &pem[start..];
            if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(slice) {
                return Ok(key);
            }
            if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(slice) {
                return Ok(key);
            }
        }
    }
    Err(GsutilError::command(
        "Unable to parse RSA private key from keyfile.",
    ))
}
