//! Google Cloud Storage JSON API v1 client, XML/S3 interoperability client,
//! CloudApiDelegator, and auxiliary Google Cloud API clients (Cloud KMS,
//! Cloud Pub/Sub, IAM Credentials).
//!
//! Mirrors `gslib/gcs_json_api.py`, `gslib/boto_translation.py`,
//! `gslib/cloud_api_delegator.py`, `gslib/kms_api.py`, `gslib/pubsub_api.py`,
//! `gslib/iamcredentials_api.py`, and `gslib/utils/retry_util.py`.

pub mod client;
pub mod delegator;
pub mod ecp;
pub mod error_translation;
pub mod iamcredentials;
pub mod kms;
pub mod pubsub;
pub mod retry;
pub mod xml;

pub use client::{GcsJsonClient, GcsJsonClientConfig, DEFAULT_GCS_HOST, MTLS_GCS_HOST};
pub use delegator::{ApiSelector, CloudApiDelegator};
pub use ecp::{EcpProxy, ECP_PROXY_PORT_ENV, ECP_TARGET_HOST_HEADER};
pub use error_translation::{translate_http_error, translate_resumable_upload_error, ErrorContext};
pub use iamcredentials::IamCredentialsClient;
pub use kms::KmsClient;
pub use pubsub::PubsubClient;
pub use retry::RetryPolicy;
pub use xml::{translate_xml_error, XmlApiClient, XmlClientConfig};
