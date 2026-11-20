//! Move/rename engine (`gsutil mv`).
//!
//! Matches `gslib/commands/mv.py` in Python gsutil v5.38:
//! - Refuses to move a source bucket or provider URL directly
//! - Implies recursive (`-R`) and delete-source-after-copy (`-M`)
//! - Deletes each source ONLY when its copy succeeds (never on failure or `-n` skip)
//! - Supports `-p` preserve ACL, `-Z` gzip, `-n` no-clobber, `-m` parallel, etc.

use std::sync::Arc;

use gsutil_core::api::CloudApi;
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result};
use gsutil_core::url::StorageUrl;

use crate::copy::{run_copy, CopyConfig, CopySummary};

/// Configuration for `gsutil mv`.
///
/// Wraps `CopyConfig`; `run_mv` enforces `delete_source_after_copy = true` and `recursive = true`.
#[derive(Debug, Clone, Default)]
pub struct MvConfig {
    pub copy: CopyConfig,
}

impl MvConfig {
    pub fn new(src_urls: Vec<String>, dst_url: String) -> Self {
        Self {
            copy: CopyConfig {
                src_urls,
                dst_url,
                recursive: true,
                delete_source_after_copy: true,
                ..Default::default()
            },
        }
    }
}

/// Execute `gsutil mv`: validate source URLs, copy, and delete each source only on success.
pub async fn run_mv(
    api: Arc<dyn CloudApi>,
    boto: &BotoConfig,
    cfg: &MvConfig,
) -> Result<CopySummary> {
    for raw_src in &cfg.copy.src_urls {
        let url = StorageUrl::parse(raw_src)?;
        if url.is_cloud_url() && (url.is_bucket() || url.is_provider()) {
            return Err(GsutilError::command(format!(
                "You cannot move a source bucket using the mv command. If you meant to move\n\
                 all objects in the bucket, you can use a command like:\n\
                 \tgsutil mv {raw_src}/* {}",
                cfg.copy.dst_url
            )));
        }
    }

    let mut copy_cfg = cfg.copy.clone();
    copy_cfg.delete_source_after_copy = true;
    copy_cfg.recursive = true;

    run_copy(api, boto, &copy_cfg).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_api::MockCloudApi;

    #[tokio::test]
    async fn test_mv_cloud_to_cloud_and_no_clobber_preserves_source() {
        let tmp = tempfile::tempdir().unwrap();
        let mut boto = BotoConfig::new();
        boto.set(
            "GSUtil",
            "resumable_tracker_dir",
            tmp.path().to_string_lossy().into_owned(),
        );

        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");
        api.put_object("bkt", "src.txt", b"move-me");

        // Move src.txt -> dst.txt
        let mv_cfg = MvConfig::new(vec!["gs://bkt/src.txt".into()], "gs://bkt/dst.txt".into());
        let summary = run_mv(api.clone(), &boto, &mv_cfg).await.unwrap();
        assert_eq!(summary.succeeded, 1);
        assert!(api.get_stored("bkt", "src.txt").is_none());
        assert_eq!(
            api.get_stored("bkt", "dst.txt").unwrap().data.as_ref(),
            b"move-me"
        );

        // Move with -n when dst already exists: must NOT delete source!
        api.put_object("bkt", "src2.txt", b"keep-me");
        let mut mv_noclobber =
            MvConfig::new(vec!["gs://bkt/src2.txt".into()], "gs://bkt/dst.txt".into());
        mv_noclobber.copy.no_clobber = true;
        let summary2 = run_mv(api.clone(), &boto, &mv_noclobber).await.unwrap();
        assert_eq!(summary2.skipped, 1);
        assert!(api.get_stored("bkt", "src2.txt").is_some());
    }

    #[tokio::test]
    async fn test_mv_rejects_source_bucket() {
        let boto = BotoConfig::new();
        let api = Arc::new(MockCloudApi::new());
        let mv_cfg = MvConfig::new(vec!["gs://src-bucket".into()], "gs://dst-bucket".into());
        let err = run_mv(api, &boto, &mv_cfg).await.unwrap_err();
        assert!(err.to_string().contains("cannot move a source bucket"));
    }
}
