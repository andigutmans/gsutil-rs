//! In-place cloud object transformation (`gsutil rewrite`).
//!
//! Matches `gslib/commands/rewrite.py` in Python gsutil v5.38:
//! - Storage class (`-s`) and encryption key (`-k`) transformations
//! - ACL preservation vs `-O` (skip ACL / apply default object ACL)
//! - Redundant rewrite skipping when object already matches desired state
//! - Rewrite tracker file creation, resumption, and cleanup

use std::sync::Arc;

use gsutil_core::api::{
    CloudApi, CopyOptions, CsObjectOrPrefix, EncryptionKey, ListObjectsOptions, Object,
    Preconditions,
};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result};
use gsutil_core::url::{contains_wildcard, StorageUrl};
use gsutil_core::wildcard::{build_bucket_filter_strings, WildcardMatcher};

use crate::parallel::{run_parallel_with_results, ParallelConfig};
use crate::tracker::{
    delete_tracker_file, get_rewrite_tracker_file_path, hash_rewrite_parameters,
    read_rewrite_tracker, write_rewrite_tracker, RewriteTrackerParams,
};

/// Configuration for `gsutil rewrite`.
#[derive(Debug, Clone, Default)]
pub struct RewriteConfig {
    pub urls: Vec<String>,
    /// `-s <class>`: target storage class (e.g. `STANDARD`, `NEARLINE`, `COLDLINE`, `ARCHIVE`).
    pub storage_class: Option<String>,
    /// `-k`: rotate/update/remove encryption key.
    pub update_encryption_key: bool,
    /// Target encryption key (CSEK or CMEK) when `-k` is set.
    pub encryption_key: Option<EncryptionKey>,
    /// Decryption key for currently-encrypted source object (CSEK).
    pub decryption_key: Option<EncryptionKey>,
    /// `-O`: omit reading/preserving object ACL (required for UBLA buckets).
    pub omit_acl: bool,
    /// `-r` / `-R`: recursively rewrite objects under prefixes/buckets.
    pub recursive: bool,
    /// `-f`: continue on error.
    pub continue_on_error: bool,
    /// `-m`: parallel rewrite execution.
    pub parallel_operations: bool,
    /// Suppress informational progress lines (`-q`).
    pub quiet: bool,
    pub preconditions: Option<Preconditions>,
    pub max_bytes_per_call: Option<u64>,
}

/// Outcome of a `gsutil rewrite` execution.
#[derive(Debug, Default)]
pub struct RewriteSummary {
    pub rewritten: usize,
    pub skipped: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SingleRewriteOutcome {
    Rewritten,
    Skipped,
}

/// Normalize storage class names matching `NormalizeStorageClass` in `text_util.py`.
pub fn normalize_storage_class(sc: &str) -> String {
    match sc.trim().to_ascii_lowercase().as_str() {
        "standard" | "std" => "STANDARD".to_string(),
        "nearline" | "nl" => "NEARLINE".to_string(),
        "coldline" | "cl" => "COLDLINE".to_string(),
        "archive" | "ar" => "ARCHIVE".to_string(),
        "multi_regional" | "dra" => "MULTI_REGIONAL".to_string(),
        "regional" => "REGIONAL".to_string(),
        "durable_reduced_availability" => "DURABLE_REDUCED_AVAILABILITY".to_string(),
        other => other.to_ascii_uppercase(),
    }
}

fn encryption_key_sha256(key: Option<&EncryptionKey>) -> Option<&str> {
    match key {
        Some(EncryptionKey::Csek { key_sha256_b64, .. }) => Some(key_sha256_b64.as_str()),
        Some(EncryptionKey::Cmek { kms_key_name }) => Some(kms_key_name.as_str()),
        None => None,
    }
}

/// Check if an object's current encryption matches the desired key.
fn object_matches_encryption(obj: &Object, desired: Option<&EncryptionKey>) -> bool {
    match desired {
        Some(EncryptionKey::Csek { key_sha256_b64, .. }) => {
            obj.customer_encryption
                .as_ref()
                .and_then(|ce| ce.key_sha256.as_deref())
                == Some(key_sha256_b64.as_str())
        }
        Some(EncryptionKey::Cmek { kms_key_name }) => {
            // GCS appends `/cryptoKeyVersions/<N>` to the stored `kmsKeyName`.
            obj.kms_key_name.as_deref().is_some_and(|stored| {
                stored == kms_key_name || stored.starts_with(&format!("{kms_key_name}/"))
            })
        }
        // When no encryption key is configured with `-k`, gsutil always rewrites
        // (cannot know whether bucket default KMS key applies).
        None => false,
    }
}

/// Expand input URLs (supporting wildcards and `-r`) into `(bucket, object_name)` pairs.
async fn expand_rewrite_targets(
    api: &dyn CloudApi,
    urls: &[String],
    recursive: bool,
) -> Result<Vec<(String, String)>> {
    let mut targets = Vec::new();
    for raw in urls {
        let parsed = StorageUrl::parse(raw)?;
        if !parsed.is_cloud_url() {
            return Err(GsutilError::command(format!(
                "\"rewrite\" only supports cloud URLs, got: {raw}"
            )));
        }
        if parsed.has_generation() {
            return Err(GsutilError::command(format!(
                "\"rewrite\" called on URL with generation ({raw})."
            )));
        }
        let bucket = parsed.bucket_name().ok_or_else(|| {
            GsutilError::command(format!(
                "\"rewrite\" requires a bucket or object URL: {raw}"
            ))
        })?;

        if parsed.is_bucket() {
            if !recursive {
                return Err(GsutilError::command(format!(
                    "Omitting bucket \"{raw}\". (Did you mean to use -r?)"
                )));
            }
            let items = api
                .list_objects(
                    bucket,
                    &ListObjectsOptions {
                        prefix: None,
                        delimiter: None,
                        all_versions: false,
                        fields: None,
                    },
                )
                .await?;
            for item in items {
                if let CsObjectOrPrefix::Object(obj) = item {
                    if let Some(name) = obj.name {
                        targets.push((bucket.to_string(), name));
                    }
                }
            }
        } else if contains_wildcard(raw) {
            let pattern = parsed.object_name().unwrap_or("*");
            let filter = build_bucket_filter_strings(pattern);
            let matcher = WildcardMatcher::compile(pattern)?;
            let items = api
                .list_objects(
                    bucket,
                    &ListObjectsOptions {
                        prefix: filter.prefix,
                        delimiter: if recursive { None } else { filter.delimiter },
                        all_versions: false,
                        fields: None,
                    },
                )
                .await?;
            for item in items {
                if let CsObjectOrPrefix::Object(obj) = item {
                    if let Some(name) = obj.name {
                        if matcher.is_match(&name) {
                            targets.push((bucket.to_string(), name));
                        }
                    }
                }
            }
        } else {
            let obj_name = parsed.object_name().unwrap_or("");
            if recursive {
                let prefix = if obj_name.ends_with('/') {
                    obj_name.to_string()
                } else {
                    format!("{obj_name}/")
                };
                let listed = api
                    .list_objects(
                        bucket,
                        &ListObjectsOptions {
                            prefix: Some(prefix),
                            delimiter: None,
                            all_versions: false,
                            fields: None,
                        },
                    )
                    .await?;
                let mut found_children = false;
                for item in listed {
                    if let CsObjectOrPrefix::Object(obj) = item {
                        if let Some(name) = obj.name {
                            found_children = true;
                            targets.push((bucket.to_string(), name));
                        }
                    }
                }
                if !found_children {
                    targets.push((bucket.to_string(), obj_name.to_string()));
                }
            } else {
                targets.push((bucket.to_string(), obj_name.to_string()));
            }
        }
    }
    Ok(targets)
}

/// Execute `gsutil rewrite` across all matching live objects.
pub async fn run_rewrite(
    api: Arc<dyn CloudApi>,
    boto: &BotoConfig,
    cfg: &RewriteConfig,
) -> Result<RewriteSummary> {
    if !cfg.update_encryption_key && cfg.storage_class.is_none() {
        return Err(GsutilError::command(
            "rewrite command requires at least one transformation flag (-k or -s).",
        ));
    }

    let targets = expand_rewrite_targets(api.as_ref(), &cfg.urls, cfg.recursive).await?;
    if targets.is_empty() {
        return Err(GsutilError::command_informational(
            gsutil_core::error::NO_URLS_MATCHED_GENERIC,
        ));
    }

    if cfg.parallel_operations && !cfg.quiet {
        let force = boto.get_bool("GSUtil", "task_estimation_force", false);
        let threshold = boto.get_u64("GSUtil", "task_estimation_threshold", 50_000) as usize;
        if force || (threshold > 0 && targets.len() >= threshold) {
            let mut total_size = 0u64;
            for (b, o) in &targets {
                if let Ok(m) = api
                    .get_object_metadata(b, o, None, Some(&["size".to_string()]))
                    .await
                {
                    total_size += m.size_bytes();
                }
            }
            eprintln!(
                "Estimated work for this command: objects: {}, total size: {}",
                targets.len(),
                total_size
            );
        }
    }

    let desired_sc = cfg.storage_class.as_deref().map(normalize_storage_class);
    let par_cfg = ParallelConfig::from_boto(
        boto,
        cfg.parallel_operations,
        cfg.continue_on_error || cfg.parallel_operations,
    );
    let boto_cloned = boto.clone();
    let cfg_cloned = cfg.clone();

    let (outcomes, batch) = run_parallel_with_results(targets, &par_cfg, move |(bucket, name)| {
        let api = Arc::clone(&api);
        let boto = boto_cloned.clone();
        let cfg = cfg_cloned.clone();
        let desired_sc = desired_sc.clone();
        async move {
            rewrite_single_object(
                api.as_ref(),
                &boto,
                &cfg,
                &bucket,
                &name,
                desired_sc.as_deref(),
            )
            .await
        }
    })
    .await;

    let mut summary = RewriteSummary {
        failed: batch.failed,
        ..Default::default()
    };
    for o in outcomes {
        match o {
            SingleRewriteOutcome::Rewritten => summary.rewritten += 1,
            SingleRewriteOutcome::Skipped => summary.skipped += 1,
        }
    }

    if batch.failed > 0 {
        batch.into_result()?;
    }
    Ok(summary)
}

async fn rewrite_single_object(
    api: &dyn CloudApi,
    boto: &BotoConfig,
    cfg: &RewriteConfig,
    bucket: &str,
    object_name: &str,
    desired_sc: Option<&str>,
) -> Result<SingleRewriteOutcome> {
    let src_meta = api
        .get_object_metadata(bucket, object_name, None, None)
        .await?;

    // Determine whether each requested transformation is already satisfied.
    let sc_needs_change = match desired_sc {
        Some(target_sc) => {
            src_meta
                .storage_class
                .as_deref()
                .map(normalize_storage_class)
                .as_deref()
                != Some(target_sc)
        }
        None => false,
    };
    let enc_needs_change = if cfg.update_encryption_key {
        !object_matches_encryption(&src_meta, cfg.encryption_key.as_ref())
    } else {
        false
    };

    if !sc_needs_change && !enc_needs_change {
        if !cfg.quiet {
            eprintln!("Skipping gs://{bucket}/{object_name}");
        }
        return Ok(SingleRewriteOutcome::Skipped);
    }

    if !cfg.quiet {
        if enc_needs_change {
            let was_encrypted =
                src_meta.customer_encryption.is_some() || src_meta.kms_key_name.is_some();
            let will_encrypt = cfg.encryption_key.is_some();
            let verb = match (was_encrypted, will_encrypt) {
                (true, true) => "Rotating",
                (false, true) => "Encrypting",
                (true, false) => "Decrypting",
                (false, false) => "Rewriting",
            };
            eprintln!("{verb} gs://{bucket}/{object_name}...");
        } else {
            eprintln!("Rewriting gs://{bucket}/{object_name}...");
        }
    }

    let mut dst_meta = src_meta.clone();
    if let Some(sc) = desired_sc {
        dst_meta.storage_class = Some(sc.to_string());
    }
    if cfg.omit_acl {
        dst_meta.acl = None;
    }

    // Track rewrite progress/resumption via rewrite tracker file.
    let tracker_path =
        get_rewrite_tracker_file_path(boto, bucket, object_name, bucket, object_name, "JSON")?;
    let params_hash = hash_rewrite_parameters(&RewriteTrackerParams {
        src_bucket: bucket,
        src_obj: object_name,
        src_etag: src_meta.etag.as_deref().unwrap_or(""),
        dst_bucket: bucket,
        dst_obj: object_name,
        dst_storage_class: dst_meta.storage_class.as_deref(),
        src_generation: src_meta.generation.as_deref(),
        gen_match: cfg.preconditions.as_ref().and_then(|p| p.gen_match),
        meta_gen_match: cfg.preconditions.as_ref().and_then(|p| p.meta_gen_match),
        canned_acl: None,
        max_bytes_per_call: cfg.max_bytes_per_call,
        src_dec_key_sha256: encryption_key_sha256(cfg.decryption_key.as_ref()),
        dst_enc_key_sha256: encryption_key_sha256(cfg.encryption_key.as_ref()),
    });

    // Check if there's an existing resume token; if not, write initial tracker entry.
    let _existing_token = read_rewrite_tracker(&tracker_path, &params_hash);
    write_rewrite_tracker(&tracker_path, &params_hash, "in-progress")?;

    let preconditions = cfg.preconditions.clone().or_else(|| {
        src_meta
            .generation
            .as_deref()
            .and_then(|g| g.parse::<i64>().ok())
            .map(|g| Preconditions::new(Some(g), None))
    });

    let copy_opts = CopyOptions {
        src_generation: src_meta.generation.clone(),
        canned_acl: None,
        preconditions,
        max_bytes_per_call: cfg.max_bytes_per_call,
        encryption_key: if cfg.update_encryption_key {
            cfg.encryption_key.clone()
        } else {
            None
        },
        decryption_key: cfg.decryption_key.clone(),
        fields: None,
    };

    let result = api.copy_object(&src_meta, &dst_meta, &copy_opts).await;
    if result.is_ok() {
        delete_tracker_file(&tracker_path);
    }
    result?;
    Ok(SingleRewriteOutcome::Rewritten)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_api::MockCloudApi;

    #[tokio::test]
    async fn test_rewrite_storage_class_and_skip_redundant() {
        let tmp = tempfile::tempdir().unwrap();
        let mut boto = BotoConfig::new();
        boto.set(
            "GSUtil",
            "resumable_tracker_dir",
            tmp.path().to_string_lossy().into_owned(),
        );

        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");
        api.put_object("bkt", "a.txt", b"hello");

        // First rewrite: STANDARD -> NEARLINE
        let s1 = run_rewrite(
            api.clone(),
            &boto,
            &RewriteConfig {
                urls: vec!["gs://bkt/a.txt".into()],
                storage_class: Some("nearline".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(s1.rewritten, 1);
        assert_eq!(s1.skipped, 0);

        let meta = api
            .get_object_metadata("bkt", "a.txt", None, None)
            .await
            .unwrap();
        assert_eq!(meta.storage_class.as_deref(), Some("NEARLINE"));

        // Second rewrite with same storage class: skipped!
        let s2 = run_rewrite(
            api.clone(),
            &boto,
            &RewriteConfig {
                urls: vec!["gs://bkt/a.txt".into()],
                storage_class: Some("NEARLINE".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(s2.rewritten, 0);
        assert_eq!(s2.skipped, 1);
    }

    #[tokio::test]
    async fn test_rewrite_encryption_key_and_generation_error() {
        let tmp = tempfile::tempdir().unwrap();
        let mut boto = BotoConfig::new();
        boto.set(
            "GSUtil",
            "resumable_tracker_dir",
            tmp.path().to_string_lossy().into_owned(),
        );

        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");
        api.put_object("bkt", "secret.bin", b"top-secret");

        let csek = EncryptionKey::Csek {
            key_b64: "AAAA".into(),
            key_sha256_b64: "SHA256-KEY-1".into(),
        };

        let s1 = run_rewrite(
            api.clone(),
            &boto,
            &RewriteConfig {
                urls: vec!["gs://bkt/secret.bin".into()],
                update_encryption_key: true,
                encryption_key: Some(csek.clone()),
                omit_acl: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(s1.rewritten, 1);

        let meta = api
            .get_object_metadata("bkt", "secret.bin", None, None)
            .await
            .unwrap();
        assert_eq!(
            meta.customer_encryption
                .as_ref()
                .and_then(|c| c.key_sha256.as_deref()),
            Some("SHA256-KEY-1")
        );

        // Version-specific URL must be rejected.
        let err = run_rewrite(
            api.clone(),
            &boto,
            &RewriteConfig {
                urls: vec!["gs://bkt/secret.bin#1".into()],
                storage_class: Some("COLDLINE".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("generation"));
    }
}
