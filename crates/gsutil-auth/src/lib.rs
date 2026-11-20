//! Authentication and credential resolution for `gsutil-rs`.
//!
//! Mirrors the credential resolution chain in Python gsutil (`gslib/gcs_json_credentials.py`,
//! `gslib/impersonation_credentials.py`, `gslib/no_op_credentials.py`) plus native
//! Application Default Credentials (ADC) and `gcloud` integration.

pub mod adc;
pub mod gce;
pub mod hmac;
pub mod impersonation;
pub mod noop;
pub mod oauth2;
pub mod resolver;
pub mod service_account;

use std::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use gsutil_core::error::{GsutilError, Result};

pub use adc::{AdcCredentials, GcloudCredentials};
pub use gce::GceMetadataCredentials;
pub use hmac::HmacCredentials;
pub use impersonation::ImpersonationCredentials;
pub use noop::NoOpCredentials;
pub use oauth2::OAuth2UserCredentials;
pub use resolver::{resolve_credentials, resolve_credentials_with_options, AuthOptions};
pub use service_account::{P12ServiceAccountCredentials, ServiceAccountCredentials};

/// Default Google OAuth2 token endpoint.
pub const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// Default OAuth2 scopes matching `gslib/gcs_json_credentials.py`.
pub const DEFAULT_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/cloud-platform.read-only",
    "https://www.googleapis.com/auth/devstorage.full_control",
    "https://www.googleapis.com/auth/devstorage.read_only",
    "https://www.googleapis.com/auth/devstorage.read_write",
];

/// Cloud Platform scope used for service account impersonation.
pub const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// Token refresh skew buffer (refresh tokens within 60s of expiry).
pub const TOKEN_EXPIRY_BUFFER_SECS: i64 = 60;

/// Credential type matching `gslib/cred_types.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialType {
    OAuth2UserAccount,
    OAuth2ServiceAccount,
    ExternalAccount,
    ExternalAccountAuthorizedUser,
    Gce,
    Gcloud,
    ApplicationDefault,
    Hmac,
    Impersonation,
    Anonymous,
}

impl CredentialType {
    /// Human-readable display name matching Python `CredTypes`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OAuth2UserAccount => "OAuth 2.0 User Account",
            Self::OAuth2ServiceAccount => "OAuth 2.0 Service Account",
            Self::ExternalAccount => "External Account",
            Self::ExternalAccountAuthorizedUser => "External Account Authorized User",
            Self::Gce => "GCE",
            Self::Gcloud => "gcloud",
            Self::ApplicationDefault => "Application Default Credentials",
            Self::Hmac => "HMAC",
            Self::Impersonation => "Impersonated Service Account",
            Self::Anonymous => "Anonymous",
        }
    }
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An OAuth2 bearer access token with optional expiration timestamp.
///
/// `Debug` intentionally redacts the token value so credentials are never leaked in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessToken {
    pub token: String,
    pub expires_at: Option<DateTime<Utc>>,
}

impl AccessToken {
    pub fn new(token: impl Into<String>, expires_at: Option<DateTime<Utc>>) -> Self {
        Self {
            token: token.into(),
            expires_at,
        }
    }

    /// Construct from an `expires_in` duration in seconds.
    pub fn from_expires_in(token: impl Into<String>, expires_in_secs: i64) -> Self {
        let expires_at = Utc::now() + Duration::seconds(expires_in_secs);
        Self {
            token: token.into(),
            expires_at: Some(expires_at),
        }
    }

    /// Returns `true` if the token is expired or within the refresh buffer window.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => Utc::now() + Duration::seconds(TOKEN_EXPIRY_BUFFER_SECS) >= exp,
            None => false,
        }
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Core async trait implemented by all credential providers.
#[async_trait]
pub trait TokenProvider: Send + Sync {
    /// Return a valid OAuth2 access token, or `Ok(None)` for anonymous/HMAC-only credentials.
    async fn token(&self) -> Result<Option<AccessToken>>;

    /// The credential type for diagnostics and error messages.
    fn credential_type(&self) -> CredentialType;

    /// Returns the service account email if these credentials represent a service account
    /// (direct JSON/P12 SA key or impersonated SA).
    fn service_account_email(&self) -> Option<&str> {
        None
    }

    /// Sign an arbitrary byte payload using the service account's private key or
    /// IAMCredentials `signBlob` API. Returns `(key_id, raw_signature_bytes)`.
    async fn sign_blob(&self, _payload: &[u8]) -> Result<(String, Vec<u8>)> {
        Err(GsutilError::command(
            "Authentication using a service account is required for signing the content.",
        ))
    }

    /// Returns HMAC credentials if this provider holds HMAC keys.
    fn hmac_credentials(&self) -> Option<&HmacCredentials> {
        None
    }

    /// Returns `true` if this provider represents anonymous/unauthenticated access.
    fn is_anonymous(&self) -> bool {
        false
    }

    /// Optional quota project ID (from ADC `quota_project_id`).
    fn quota_project_id(&self) -> Option<&str> {
        None
    }
}
