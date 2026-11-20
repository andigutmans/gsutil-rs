//! HMAC key credentials for GCS interoperability (`gs_access_key_id`/`gs_secret_access_key`)
//! and AWS S3 (`aws_access_key_id`/`aws_secret_access_key`).

use std::fmt;

use async_trait::async_trait;
use gsutil_core::error::Result;

use crate::{AccessToken, CredentialType, TokenProvider};

/// Provider scope for HMAC credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacProvider {
    Gcs,
    Aws,
}

/// HMAC access key / secret key pair with redacted `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct HmacCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub provider: HmacProvider,
}

impl HmacCredentials {
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        provider: HmacProvider,
    ) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            provider,
        }
    }
}

impl fmt::Debug for HmacCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field("provider", &self.provider)
            .finish()
    }
}

#[async_trait]
impl TokenProvider for HmacCredentials {
    async fn token(&self) -> Result<Option<AccessToken>> {
        // HMAC credentials authenticate via request signing, not OAuth2 bearer tokens.
        Ok(None)
    }

    fn credential_type(&self) -> CredentialType {
        CredentialType::Hmac
    }

    fn hmac_credentials(&self) -> Option<&HmacCredentials> {
        Some(self)
    }
}
