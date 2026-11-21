//! Async `CloudApi` trait and GCS JSON API v1 data models.
//!
//! Mirrors `gslib/cloud_api.py` and GCS JSON API v1 (`storage_v1_messages.py`)
//! in Python gsutil v5.38.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt};

use crate::error::Result;
use crate::url::StorageUrl;

/// Boxed async stream of byte chunks for constant-memory media downloads.
pub type ByteStream = Pin<Box<dyn futures::Stream<Item = std::io::Result<Bytes>> + Send>>;

/// Callback invoked periodically during transfers with `(bytes_transferred, total_bytes)`.
pub type ProgressCallback = Arc<dyn Fn(u64, Option<u64>) + Send + Sync>;

/// Callback invoked immediately when GCS returns a resumable upload session `Location` URI.
pub type SessionUriCallback = Arc<dyn Fn(&str) + Send + Sync>;

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
    /// Label keys to explicitly delete (`{"key": null}`) in JSON `PATCH` requests.
    #[serde(skip)]
    pub label_removals: Vec<String>,
    /// Top-level bucket JSON fields to explicitly set to `null` in JSON `PATCH` requests
    /// (e.g., `"logging"`, `"encryption"`, `"website"`, `"retentionPolicy"`).
    #[serde(skip)]
    pub clear_fields: Vec<String>,
}

impl Bucket {
    /// Serialize this `Bucket` as a GCS JSON `PATCH` payload, injecting explicit `null`
    /// tombstones for `label_removals` and `clear_fields`.
    pub fn to_patch_value(&self) -> serde_json::Value {
        let mut val = serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(map) = val.as_object_mut() {
            for field in &self.clear_fields {
                map.insert(field.clone(), serde_json::Value::Null);
            }
            if !self.label_removals.is_empty() {
                let labels_entry = map
                    .entry("labels".to_string())
                    .or_insert_with(|| serde_json::json!({}));
                if let Some(labels_map) = labels_entry.as_object_mut() {
                    for k in &self.label_removals {
                        labels_map.insert(k.clone(), serde_json::Value::Null);
                    }
                }
            }
        }
        val
    }
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
    /// Custom metadata keys to explicitly delete (`{"key": null}`) in JSON `PATCH` requests.
    #[serde(skip)]
    pub metadata_removals: Vec<String>,
    /// Top-level object JSON fields to explicitly set to `null` in JSON `PATCH` requests
    /// (e.g., `"cacheControl"`, `"contentDisposition"`, `"contentEncoding"`,
    /// `"contentLanguage"`, `"contentType"`, `"customTime"`).
    #[serde(skip)]
    pub clear_fields: Vec<String>,
}

impl Object {
    /// Parse the GCS string-encoded `size` field into `u64`.
    pub fn size_bytes(&self) -> u64 {
        self.size
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// Serialize this `Object` as a GCS JSON `PATCH` payload, injecting explicit `null`
    /// tombstones for `metadata_removals` and `clear_fields`.
    pub fn to_patch_value(&self) -> serde_json::Value {
        let mut val = serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(map) = val.as_object_mut() {
            for field in &self.clear_fields {
                map.insert(field.clone(), serde_json::Value::Null);
            }
            if !self.metadata_removals.is_empty() {
                let meta_entry = map
                    .entry("metadata".to_string())
                    .or_insert_with(|| serde_json::json!({}));
                if let Some(meta_map) = meta_entry.as_object_mut() {
                    for k in &self.metadata_removals {
                        meta_map.insert(k.clone(), serde_json::Value::Null);
                    }
                }
            }
        }
        val
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
pub struct ServiceAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// GCS JSON API v1 returns `email_address` (snake_case), not camelCase.
    #[serde(
        rename = "email_address",
        alias = "emailAddress",
        skip_serializing_if = "Option::is_none"
    )]
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

#[derive(Clone, Default)]
pub struct DownloadOptions {
    pub generation: Option<String>,
    pub start_byte: Option<i64>,
    pub end_byte: Option<u64>,
    pub compressed_encoding: bool,
    pub strategy: DownloadStrategy,
    pub decryption_key: Option<EncryptionKey>,
    pub progress_callback: Option<ProgressCallback>,
}

impl fmt::Debug for DownloadOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DownloadOptions")
            .field("generation", &self.generation)
            .field("start_byte", &self.start_byte)
            .field("end_byte", &self.end_byte)
            .field("compressed_encoding", &self.compressed_encoding)
            .field("strategy", &self.strategy)
            .field("decryption_key", &self.decryption_key.is_some())
            .field("progress_callback", &self.progress_callback.is_some())
            .finish()
    }
}

#[derive(Clone, Default)]
pub struct UploadOptions {
    pub canned_acl: Option<String>,
    pub preconditions: Option<Preconditions>,
    pub encryption_key: Option<EncryptionKey>,
    pub fields: Option<Vec<String>>,
    pub gzip_encoded: bool,
    /// Existing GCS resumable upload session URI to resume via `Content-Range: bytes */<total>`.
    pub resumable_session_uri: Option<String>,
    /// Invoked immediately when GCS returns a new resumable upload `Location` URI.
    pub session_uri_callback: Option<SessionUriCallback>,
    /// Invoked periodically with `(bytes_transferred, total_bytes)`.
    pub progress_callback: Option<ProgressCallback>,
    /// Total byte length of the upload (if known).
    pub total_size: Option<u64>,
    /// Resumable upload chunk size in bytes (must be a multiple of 256 KiB).
    pub chunk_size: Option<usize>,
}

impl fmt::Debug for UploadOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadOptions")
            .field("canned_acl", &self.canned_acl)
            .field("preconditions", &self.preconditions)
            .field("encryption_key", &self.encryption_key.is_some())
            .field("fields", &self.fields)
            .field("gzip_encoded", &self.gzip_encoded)
            .field("resumable_session_uri", &self.resumable_session_uri)
            .field("session_uri_callback", &self.session_uri_callback.is_some())
            .field("progress_callback", &self.progress_callback.is_some())
            .field("total_size", &self.total_size)
            .field("chunk_size", &self.chunk_size)
            .finish()
    }
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
    /// Resolve a provider-specific `CloudApi` delegate (`"gs"` or `"s3"`).
    /// Returns `Ok(None)` by default (meaning `self` handles the request).
    /// `CloudApiDelegator` overrides this to route `s3://` to `XmlApiClient("s3")`.
    fn resolve_provider(&self, _provider: &str) -> Result<Option<&dyn CloudApi>> {
        Ok(None)
    }

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

    /// Stream object media chunks without buffering the full object in memory.
    /// Real HTTP clients override this to stream directly from `reqwest::Response::bytes_stream()`.
    async fn get_object_media_stream(
        &self,
        bucket_name: &str,
        object_name: &str,
        options: &DownloadOptions,
    ) -> Result<ByteStream> {
        let data = self
            .get_object_media(bucket_name, object_name, options)
            .await?;
        let len = data.len() as u64;
        if let Some(ref cb) = options.progress_callback {
            cb(len, Some(len));
        }
        Ok(Box::pin(futures::stream::once(async move { Ok(data) })))
    }

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

    /// Upload a file slice `[start_offset..start_offset + length]` from disk using chunked
    /// resumable upload with constant memory and real GCS `308` resume offset recovery.
    /// Real HTTP clients override this to stream chunks directly from `file_path`.
    async fn upload_object_resumable_file(
        &self,
        file_path: &Path,
        start_offset: u64,
        length: u64,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        let mut file = tokio::fs::File::open(file_path).await?;
        if start_offset > 0 {
            file.seek(std::io::SeekFrom::Start(start_offset)).await?;
        }
        let mut buf = Vec::with_capacity(length.min(16 * 1024 * 1024) as usize);
        file.take(length).read_to_end(&mut buf).await?;
        self.upload_object_resumable(Bytes::from(buf), object_metadata, options)
            .await
    }

    /// Upload an object from a streaming `AsyncRead` (for stdin `-`, gzip streams, and
    /// cloud-to-cloud daisy-chain `-D`) using constant-memory chunked resumable upload.
    async fn upload_object_streaming(
        &self,
        mut reader: Box<dyn AsyncRead + Send + Unpin>,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await?;
        self.upload_object_resumable(Bytes::from(buf), object_metadata, options)
            .await
    }

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

impl dyn CloudApi + '_ {
    /// Return the `CloudApi` instance for `provider` (`"gs"` or `"s3"`),
    /// delegating through `resolve_provider` when implemented (e.g. `CloudApiDelegator`).
    pub fn for_provider(&self, provider: &str) -> Result<&dyn CloudApi> {
        match self.resolve_provider(provider)? {
            Some(api) => Ok(api),
            None => Ok(self),
        }
    }
}

/// Async Cloud KMS API trait for `gsutil kms authorize`.
#[async_trait]
pub trait KmsApi: Send + Sync {
    /// Grant `roles/cloudkms.cryptoKeyEncrypterDecrypter` to `service_account_email`
    /// on `kms_key_name`. Returns `true` if the policy was updated, `false` if already authorized.
    async fn authorize_service_account(
        &self,
        kms_key_name: &str,
        service_account_email: &str,
    ) -> Result<bool>;
}

/// Async Cloud Pub/Sub API trait for `gsutil notification create`.
#[async_trait]
pub trait PubsubApi: Send + Sync {
    /// Create `topic_name` if it does not already exist (idempotent).
    async fn create_topic(&self, topic_name: &str) -> Result<()>;

    /// Grant `roles/pubsub.publisher` to `service_account_email` on `topic_name`.
    async fn authorize_publisher(
        &self,
        topic_name: &str,
        service_account_email: &str,
    ) -> Result<()>;
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

    #[test]
    fn test_bucket_and_object_patch_null_tombstones() {
        let mut b = Bucket {
            labels: Some(BTreeMap::from([("env".to_string(), "prod".to_string())])),
            label_removals: vec!["old_label".to_string()],
            clear_fields: vec!["logging".to_string(), "encryption".to_string()],
            ..Default::default()
        };
        let b_val = b.to_patch_value();
        assert_eq!(b_val["labels"]["env"], "prod");
        assert!(b_val["labels"]["old_label"].is_null());
        assert!(b_val["logging"].is_null());
        assert!(b_val["encryption"].is_null());
        b.labels = None;
        let b_val2 = b.to_patch_value();
        assert!(b_val2["labels"]["old_label"].is_null());

        let o = Object {
            metadata: Some(BTreeMap::from([("k1".to_string(), "v1".to_string())])),
            metadata_removals: vec!["k2".to_string()],
            clear_fields: vec!["cacheControl".to_string()],
            ..Default::default()
        };
        let o_val = o.to_patch_value();
        assert_eq!(o_val["metadata"]["k1"], "v1");
        assert!(o_val["metadata"]["k2"].is_null());
        assert!(o_val["cacheControl"].is_null());

        // GCS JSON v1 returns snake_case `email_address` for projects.serviceAccount.get
        let sa: ServiceAccount = serde_json::from_str(
            r#"{"kind": "storage#serviceAccount", "email_address": "service-123@gs-project-accounts.iam.gserviceaccount.com"}"#,
        )
        .unwrap();
        assert_eq!(
            sa.email_address.as_deref(),
            Some("service-123@gs-project-accounts.iam.gserviceaccount.com")
        );
    }
}
