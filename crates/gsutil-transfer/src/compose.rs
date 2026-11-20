//! Object composition (`gsutil compose`).
//!
//! Matches `gslib/commands/compose.py` in Python gsutil v5.38:
//! - Up to `MAX_COMPOSE_ARITY` (32) source objects
//! - Same-bucket enforcement and `gs://` provider validation
//! - Wildcard expansion on source URLs
//! - Content-Type & Content-Encoding inherited from first source object
//! - Preconditions and CSEK/CMEK encryption support

use gsutil_core::api::{
    CloudApi, ComposeSourceObject, CsObjectOrPrefix, EncryptionKey, ListObjectsOptions, Object,
    Preconditions,
};
use gsutil_core::error::{GsutilError, Result};
use gsutil_core::url::{contains_wildcard, StorageUrl};
use gsutil_core::wildcard::{build_bucket_filter_strings, WildcardMatcher};

/// Maximum number of component objects allowed in a single GCS compose request.
pub const MAX_COMPOSE_ARITY: usize = 32;

/// Configuration for `gsutil compose`.
#[derive(Debug, Clone, Default)]
pub struct ComposeConfig {
    pub src_urls: Vec<String>,
    pub dst_url: String,
    pub preconditions: Option<Preconditions>,
    pub encryption_key: Option<EncryptionKey>,
}

fn check_gs_provider(url: &StorageUrl) -> Result<()> {
    if url.scheme() != "gs" {
        return Err(GsutilError::command(format!(
            "\"compose\" called on URL with unsupported provider ({url})."
        )));
    }
    Ok(())
}

/// Execute `gsutil compose`, concatenating source objects in the same bucket into `dst_url`.
pub async fn run_compose(api: &dyn CloudApi, cfg: &ComposeConfig) -> Result<Object> {
    let target_url = StorageUrl::parse(&cfg.dst_url)?;
    check_gs_provider(&target_url)?;
    if target_url.has_generation() {
        return Err(GsutilError::command(format!(
            "A version-specific URL ({target_url}) cannot be the destination for gsutil compose - abort."
        )));
    }
    let target_bucket = target_url.bucket_name().ok_or_else(|| {
        GsutilError::command(format!(
            "Destination URL ({target_url}) must specify a bucket and object name."
        ))
    })?;
    let target_obj = target_url.object_name().ok_or_else(|| {
        GsutilError::command(format!(
            "Destination URL ({target_url}) must specify an object name."
        ))
    })?;

    let mut components: Vec<ComposeSourceObject> = Vec::new();
    let mut first_src: Option<(String, String, Option<String>)> = None;

    for raw_src in &cfg.src_urls {
        let parsed = StorageUrl::parse(raw_src)?;
        check_gs_provider(&parsed)?;

        if contains_wildcard(raw_src) {
            let src_bucket = parsed.bucket_name().ok_or_else(|| {
                GsutilError::command(format!("Invalid compose source URL: {raw_src}"))
            })?;
            if src_bucket != target_bucket {
                return Err(GsutilError::command(
                    "GCS does not support inter-bucket composing.",
                ));
            }
            let obj_pattern = parsed.object_name().unwrap_or("*");
            let filter = build_bucket_filter_strings(obj_pattern);
            let matcher = WildcardMatcher::compile(obj_pattern)?;
            let listed = api
                .list_objects(
                    src_bucket,
                    &ListObjectsOptions {
                        prefix: filter.prefix,
                        delimiter: filter.delimiter,
                        all_versions: false,
                        fields: None,
                    },
                )
                .await?;

            for item in listed {
                if let CsObjectOrPrefix::Object(obj) = item {
                    let Some(name) = obj.name else { continue };
                    if !matcher.is_match(&name) {
                        continue;
                    }
                    if first_src.is_none() {
                        first_src =
                            Some((src_bucket.to_string(), name.clone(), obj.generation.clone()));
                    }
                    components.push(ComposeSourceObject {
                        name,
                        generation: None,
                        object_preconditions: None,
                    });
                    if components.len() > MAX_COMPOSE_ARITY {
                        return Err(GsutilError::command(format!(
                            "\"compose\" called with too many component objects. Limit is {MAX_COMPOSE_ARITY}."
                        )));
                    }
                }
            }
        } else {
            let src_bucket = parsed.bucket_name().ok_or_else(|| {
                GsutilError::command(format!("Invalid compose source URL: {raw_src}"))
            })?;
            if src_bucket != target_bucket {
                return Err(GsutilError::command(
                    "GCS does not support inter-bucket composing.",
                ));
            }
            let src_obj = parsed.object_name().ok_or_else(|| {
                GsutilError::command(format!("Compose source must be an object URL: {raw_src}"))
            })?;
            let generation = parsed.generation().map(ToString::to_string);
            if first_src.is_none() {
                first_src = Some((
                    src_bucket.to_string(),
                    src_obj.to_string(),
                    generation.clone(),
                ));
            }
            components.push(ComposeSourceObject {
                name: src_obj.to_string(),
                generation,
                object_preconditions: None,
            });
            if components.len() > MAX_COMPOSE_ARITY {
                return Err(GsutilError::command(format!(
                    "\"compose\" called with too many component objects. Limit is {MAX_COMPOSE_ARITY}."
                )));
            }
        }
    }

    if components.is_empty() {
        return Err(GsutilError::command(
            "\"compose\" requires at least 1 component object.",
        ));
    }

    let (first_bucket, first_name, first_gen) = first_src.unwrap();
    let first_meta = api
        .get_object_metadata(
            &first_bucket,
            &first_name,
            first_gen.as_deref(),
            Some(&["contentEncoding".to_string(), "contentType".to_string()]),
        )
        .await?;

    let dst_meta = Object {
        bucket: Some(target_bucket.to_string()),
        name: Some(target_obj.to_string()),
        content_type: first_meta.content_type,
        content_encoding: first_meta.content_encoding,
        ..Default::default()
    };

    api.compose_object(
        &components,
        &dst_meta,
        cfg.preconditions.as_ref(),
        cfg.encryption_key.as_ref(),
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_api::MockCloudApi;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_compose_basic_and_wildcards() {
        let api = MockCloudApi::new();
        api.create_bucket_sync("bkt");
        api.put_object_with_content_type("bkt", "part-1", b"hello ", Some("text/plain"));
        api.put_object_with_content_type(
            "bkt",
            "part-2",
            b"world!",
            Some("application/octet-stream"),
        );

        let res = run_compose(
            &api,
            &ComposeConfig {
                src_urls: vec!["gs://bkt/part-*".into()],
                dst_url: "gs://bkt/combined".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(res.name.as_deref(), Some("combined"));
        assert_eq!(res.content_type.as_deref(), Some("text/plain"));
        let data = api
            .get_object_media("bkt", "combined", &Default::default())
            .await
            .unwrap();
        assert_eq!(data, Bytes::from_static(b"hello world!"));
    }

    #[tokio::test]
    async fn test_compose_validation_errors() {
        let api = MockCloudApi::new();
        api.create_bucket_sync("b1");
        api.create_bucket_sync("b2");
        api.put_object("b1", "a", b"1");

        // Inter-bucket error
        let err = run_compose(
            &api,
            &ComposeConfig {
                src_urls: vec!["gs://b1/a".into()],
                dst_url: "gs://b2/out".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("inter-bucket"));

        // Version-specific destination error
        let err = run_compose(
            &api,
            &ComposeConfig {
                src_urls: vec!["gs://b1/a".into()],
                dst_url: "gs://b1/out#123".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("version-specific"));

        // Too many components (> 32)
        let mut many = Vec::new();
        for i in 0..=MAX_COMPOSE_ARITY {
            let name = format!("obj-{i:02}");
            api.put_object("b1", &name, b"x");
            many.push(format!("gs://b1/{name}"));
        }
        let err = run_compose(
            &api,
            &ComposeConfig {
                src_urls: many,
                dst_url: "gs://b1/too-many".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("Limit is 32"));
    }
}
