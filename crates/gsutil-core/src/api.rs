//! Async `CloudApi` trait and GCS JSON API v1 data models.
//!
//! Mirrors `gslib/cloud_api.py` and GCS JSON API v1 (`storage_v1_messages.py`)
//! in Python gsutil v5.38.

use std::collections::BTreeMap;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::url::StorageUrl;

// ---------------------------------------------------------------------------
// Preconditions & Encryption
// ---------------------------------------------------------------------------

/// Preconditions for conditional GCS requests (`ifGenerationMatch`, `ifMetagenerationMatch`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preconditions {
    pub gen_match: Option<i64>,
    pub meta_gen_match: Option<i64>,
}

impl Preconditions {
    pub fn new(gen_match: Option<i64>, meta_gen_match: Option<i64>) -> Self {
        Self {
            gen_match,
            meta_gen_match,
        }
    }
}

/// Customer-supplied (CSEK) or Customer-managed (CMEK) encryption key info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionKey {
    /// AES-256 Customer-Supplied Encryption Key (base64 key + base64 SHA256).
    Csek {
        key_b64: String,
        key_sha256_b64: String,
    },
    /// Cloud KMS key resource name (`projects/.../locations/.../keyRings/.../cryptoKeys/...`).
    Cmek { kms_key_name: String },
}

/// Download strategy enum matching `CloudApi.DownloadStrategy`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DownloadStrategy {
    #[default]
    OneShot,
    Resumable,
}

// ---------------------------------------------------------------------------
// GCS JSON API v1 Resource Models
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Bucket {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metageneration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_event_based_hold: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acl: Option<Vec<BucketAccessControl>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_object_acl: Option<Vec<ObjectAccessControl>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<ResourceOwner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing: Option<BucketBilling>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cors: Option<Vec<BucketCors>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<BucketEncryption>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iam_configuration: Option<BucketIamConfiguration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<BucketLifecycle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<BucketLogging>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy: Option<BucketRetentionPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versioning: Option<BucketVersioning>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<BucketWebsite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autoclass: Option<BucketAutoclass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_placement_config: Option<BucketCustomPlacementConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soft_delete_policy: Option<BucketSoftDeletePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hierarchical_namespace: Option<BucketHierarchicalNamespace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub satisfies_pzs: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceOwner {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketBilling {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester_pays: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketCors {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_header: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketEncryption {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_kms_key_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketIamConfiguration {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uniform_bucket_level_access: Option<UniformBucketLevelAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket_policy_only: Option<UniformBucketLevelAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_access_prevention: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UniformBucketLevelAccess {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_time: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BucketLifecycle {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<Vec<LifecycleRule>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<LifecycleAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<LifecycleCondition>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleAction {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub action_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleCondition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_time_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_since_custom_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_since_noncurrent_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_live: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches_prefix: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches_storage_class: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches_suffix: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noncurrent_time_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_newer_versions: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketLogging {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_object_prefix: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketRetentionPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_locked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_period: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketVersioning {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketWebsite {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_page_suffix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_found_page: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketAutoclass {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toggle_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_storage_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_storage_class_update_time: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketCustomPlacementConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_locations: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketSoftDeletePolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_duration_seconds: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_time: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketHierarchicalNamespace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Object {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metageneration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crc32c: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_deleted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_storage_class_updated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_disposition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_based_hold: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporary_hold: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_expiration_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_key_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_encryption: Option<ObjectCustomerEncryption>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acl: Option<Vec<ObjectAccessControl>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<ResourceOwner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention: Option<ObjectRetention>,
}

impl Object {
    /// Parse the GCS string-encoded `size` field into `u64`.
    pub fn size_bytes(&self) -> u64 {
        self.size
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectCustomerEncryption {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectRetention {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retain_until_time: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BucketAccessControl {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_team: Option<ProjectTeam>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectAccessControl {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_team: Option<ProjectTeam>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectTeam {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IamPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
    #[serde(default)]
    pub bindings: Vec<IamBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IamBinding {
    pub role: String,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<IamCondition>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IamCondition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expression: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Notification {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_attributes: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_name_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_link: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub channel_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_address: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HmacKeyMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_account_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HmacKeyCreateResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub secret: String,
    pub metadata: HmacKeyMetadata,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComposeSourceObject {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_preconditions: Option<ComposeObjectPreconditions>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ComposeObjectPreconditions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_generation_match: Option<String>,
}

// ---------------------------------------------------------------------------
// Listing & Request Option Types
// ---------------------------------------------------------------------------

/// Container for `list_objects` results (matches `CloudApi.CsObjectOrPrefix`).
#[derive(Debug, Clone, PartialEq)]
pub enum CsObjectOrPrefix {
    Object(Box<Object>),
    Prefix(String),
}

/// Bucket listing reference (matches `gslib/bucket_listing_ref.py`).
#[derive(Debug, Clone, PartialEq)]
pub enum BucketListingRef {
    Bucket {
        url: StorageUrl,
        metadata: Option<Box<Bucket>>,
    },
    Object {
        url: StorageUrl,
        metadata: Option<Box<Object>>,
    },
    Prefix {
        url: StorageUrl,
        prefix: String,
    },
}

impl BucketListingRef {
    pub fn url(&self) -> &StorageUrl {
        match self {
            Self::Bucket { url, .. } | Self::Object { url, .. } | Self::Prefix { url, .. } => url,
        }
    }

    pub fn is_bucket(&self) -> bool {
        matches!(self, Self::Bucket { .. })
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object { .. })
    }

    pub fn is_prefix(&self) -> bool {
        matches!(self, Self::Prefix { .. })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ListObjectsOptions {
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub all_versions: bool,
    pub fields: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct DownloadOptions {
    pub generation: Option<String>,
    pub start_byte: Option<i64>,
    pub end_byte: Option<u64>,
    pub compressed_encoding: bool,
    pub strategy: DownloadStrategy,
    pub decryption_key: Option<EncryptionKey>,
}

#[derive(Debug, Clone, Default)]
pub struct UploadOptions {
    pub canned_acl: Option<String>,
    pub preconditions: Option<Preconditions>,
    pub encryption_key: Option<EncryptionKey>,
    pub fields: Option<Vec<String>>,
    pub gzip_encoded: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CopyOptions {
    pub src_generation: Option<String>,
    pub canned_acl: Option<String>,
    pub preconditions: Option<Preconditions>,
    pub max_bytes_per_call: Option<u64>,
    pub encryption_key: Option<EncryptionKey>,
    pub decryption_key: Option<EncryptionKey>,
    pub fields: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct CreateNotificationOptions {
    pub pubsub_topic: String,
    pub payload_format: String,
    pub event_types: Option<Vec<String>>,
    pub custom_attributes: Option<BTreeMap<String, String>>,
    pub object_name_prefix: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SignUrlOptions {
    pub method: String,
    pub duration_secs: u64,
    pub path: String,
    pub generation: Option<String>,
    pub region: Option<String>,
    pub signed_headers: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// Async CloudApi Trait
// ---------------------------------------------------------------------------

/// Async Cloud Storage API trait covering all methods in `gslib/cloud_api.py`.
#[async_trait]
pub trait CloudApi: Send + Sync {
    async fn get_service_account_id(&self) -> Result<String>;

    // ---- Buckets ----

    async fn get_bucket(&self, bucket_name: &str, fields: Option<&[String]>) -> Result<Bucket>;

    async fn list_buckets(
        &self,
        project_id: Option<&str>,
        fields: Option<&[String]>,
    ) -> Result<Vec<Bucket>>;

    async fn create_bucket(
        &self,
        bucket_name: &str,
        project_id: Option<&str>,
        metadata: Option<&Bucket>,
        fields: Option<&[String]>,
    ) -> Result<Bucket>;

    async fn patch_bucket(
        &self,
        bucket_name: &str,
        metadata: &Bucket,
        canned_acl: Option<&str>,
        canned_def_acl: Option<&str>,
        preconditions: Option<&Preconditions>,
        fields: Option<&[String]>,
    ) -> Result<Bucket>;

    async fn delete_bucket(
        &self,
        bucket_name: &str,
        preconditions: Option<&Preconditions>,
    ) -> Result<()>;

    async fn lock_retention_policy(&self, bucket_name: &str, metageneration: i64)
        -> Result<Bucket>;

    async fn get_bucket_iam_policy(
        &self,
        bucket_name: &str,
        fields: Option<&[String]>,
    ) -> Result<IamPolicy>;

    async fn set_bucket_iam_policy(
        &self,
        bucket_name: &str,
        policy: &IamPolicy,
    ) -> Result<IamPolicy>;

    // ---- Objects ----

    async fn list_objects(
        &self,
        bucket_name: &str,
        options: &ListObjectsOptions,
    ) -> Result<Vec<CsObjectOrPrefix>>;

    async fn get_object_metadata(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
        fields: Option<&[String]>,
    ) -> Result<Object>;

    #[allow(clippy::too_many_arguments)]
    async fn patch_object_metadata(
        &self,
        bucket_name: &str,
        object_name: &str,
        metadata: &Object,
        canned_acl: Option<&str>,
        generation: Option<&str>,
        preconditions: Option<&Preconditions>,
        fields: Option<&[String]>,
    ) -> Result<Object>;

    async fn get_object_iam_policy(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
        fields: Option<&[String]>,
    ) -> Result<IamPolicy>;

    async fn set_object_iam_policy(
        &self,
        bucket_name: &str,
        object_name: &str,
        policy: &IamPolicy,
        generation: Option<&str>,
    ) -> Result<IamPolicy>;

    async fn get_object_media(
        &self,
        bucket_name: &str,
        object_name: &str,
        options: &DownloadOptions,
    ) -> Result<Bytes>;

    async fn upload_object(
        &self,
        data: Bytes,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object>;

    async fn upload_object_resumable(
        &self,
        data: Bytes,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object>;

    async fn copy_object(
        &self,
        src_obj_metadata: &Object,
        dst_obj_metadata: &Object,
        options: &CopyOptions,
    ) -> Result<Object>;

    async fn compose_object(
        &self,
        src_objs: &[ComposeSourceObject],
        dst_obj_metadata: &Object,
        preconditions: Option<&Preconditions>,
        encryption_key: Option<&EncryptionKey>,
        fields: Option<&[String]>,
    ) -> Result<Object>;

    async fn delete_object(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
        preconditions: Option<&Preconditions>,
    ) -> Result<()>;

    // ---- Notifications & Channels ----

    async fn watch_bucket(
        &self,
        bucket_name: &str,
        address: &str,
        channel_id: &str,
        token: Option<&str>,
    ) -> Result<Channel>;

    async fn stop_channel(&self, channel_id: &str, resource_id: &str) -> Result<()>;

    async fn get_project_service_account(&self, project_id: &str) -> Result<ServiceAccount>;

    async fn create_notification_config(
        &self,
        bucket_name: &str,
        options: &CreateNotificationOptions,
    ) -> Result<Notification>;

    async fn delete_notification_config(
        &self,
        bucket_name: &str,
        notification_id: &str,
    ) -> Result<()>;

    async fn list_notification_configs(&self, bucket_name: &str) -> Result<Vec<Notification>>;

    // ---- HMAC Keys ----

    async fn create_hmac_key(
        &self,
        project_id: &str,
        service_account_email: &str,
    ) -> Result<HmacKeyCreateResponse>;

    async fn delete_hmac_key(&self, project_id: &str, access_id: &str) -> Result<()>;

    async fn get_hmac_key(&self, project_id: &str, access_id: &str) -> Result<HmacKeyMetadata>;

    async fn list_hmac_keys(
        &self,
        project_id: &str,
        service_account_email: Option<&str>,
        show_deleted_keys: bool,
    ) -> Result<Vec<HmacKeyMetadata>>;

    async fn update_hmac_key(
        &self,
        project_id: &str,
        access_id: &str,
        state: &str,
        etag: Option<&str>,
    ) -> Result<HmacKeyMetadata>;

    // ---- Signed URLs ----

    async fn sign_url(&self, options: &SignUrlOptions) -> Result<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_json_roundtrip() {
        let json = r#"{
            "kind": "storage#bucket",
            "id": "my-bucket",
            "name": "my-bucket",
            "location": "US",
            "storageClass": "STANDARD",
            "versioning": { "enabled": true },
            "iamConfiguration": {
                "uniformBucketLevelAccess": { "enabled": true },
                "publicAccessPrevention": "enforced"
            },
            "labels": { "env": "prod" }
        }"#;
        let bucket: Bucket = serde_json::from_str(json).unwrap();
        assert_eq!(bucket.name.as_deref(), Some("my-bucket"));
        assert_eq!(
            bucket.versioning.as_ref().and_then(|v| v.enabled),
            Some(true)
        );
        let re = serde_json::to_string(&bucket).unwrap();
        let bucket2: Bucket = serde_json::from_str(&re).unwrap();
        assert_eq!(bucket, bucket2);
    }

    #[test]
    fn test_object_json_roundtrip() {
        let json = r#"{
            "kind": "storage#object",
            "bucket": "my-bucket",
            "name": "dir/file.txt",
            "generation": "1700000000000000",
            "metageneration": "1",
            "size": "42",
            "crc32c": "mnG7TA==",
            "md5Hash": "XUFAKrxLKna5cZ2REBfFkg==",
            "metadata": { "custom-key": "custom-val" }
        }"#;
        let obj: Object = serde_json::from_str(json).unwrap();
        assert_eq!(obj.size_bytes(), 42);
        assert_eq!(obj.crc32c.as_deref(), Some("mnG7TA=="));
        let re = serde_json::to_string(&obj).unwrap();
        let obj2: Object = serde_json::from_str(&re).unwrap();
        assert_eq!(obj, obj2);
    }

    #[test]
    fn test_iam_policy_roundtrip() {
        let json = r#"{
            "version": 3,
            "etag": "BwX123=",
            "bindings": [{
                "role": "roles/storage.objectViewer",
                "members": ["allUsers"],
                "condition": {
                    "title": "exp",
                    "expression": "request.time < timestamp('2030-01-01T00:00:00Z')"
                }
            }]
        }"#;
        let policy: IamPolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.version, Some(3));
        assert_eq!(policy.bindings.len(), 1);
        assert!(policy.bindings[0].condition.is_some());
    }
}
