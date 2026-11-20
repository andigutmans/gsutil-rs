//! Anonymous / No-op credentials matching `gslib/no_op_credentials.py`.

use async_trait::async_trait;
use gsutil_core::error::Result;

use crate::{AccessToken, CredentialType, TokenProvider};

/// No-op credential provider for public/anonymous bucket access.
#[derive(Debug, Clone, Default)]
pub struct NoOpCredentials;

#[async_trait]
impl TokenProvider for NoOpCredentials {
    async fn token(&self) -> Result<Option<AccessToken>> {
        Ok(None)
    }

    fn credential_type(&self) -> CredentialType {
        CredentialType::Anonymous
    }

    fn is_anonymous(&self) -> bool {
        true
    }
}
