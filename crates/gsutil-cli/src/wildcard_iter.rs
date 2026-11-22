//! Async wildcard expansion for cloud URLs and local filesystem paths.
//!
//! Mirrors `gslib/wildcard_iterator.py` and `gslib/name_expansion.py`.

use std::path::{Path, PathBuf};

use gsutil_core::api::{BucketListingRef, CloudApi, CsObjectOrPrefix, ListObjectsOptions};
use gsutil_core::error::{GsutilError, Result};
use gsutil_core::url::{contains_wildcard, strip_one_slash, CloudUrl, StorageUrl};
use gsutil_core::wildcard::{build_bucket_filter_strings, WildcardMatcher};

/// Expand a bucket URL or wildcard (e.g. `gs://*`, `gs://my-bkt*`, `gs://my-bkt`).
pub async fn iter_buckets(
    api: &dyn CloudApi,
    url_str: &str,
    project_id: Option<&str>,
    fields: Option<&[String]>,
) -> Result<Vec<BucketListingRef>> {
    let url = StorageUrl::parse(url_str)?;
    let cloud = url
        .as_cloud()
        .ok_or_else(|| GsutilError::command(format!("Expected cloud URL, got {url_str}")))?;
    let api = api.for_provider(cloud.scheme.as_str())?;

    if cloud.is_provider() {
        let buckets = api.list_buckets(project_id, fields).await?;
        let mut refs = Vec::with_capacity(buckets.len());
        for b in buckets {
            if let Some(ref name) = b.name {
                let b_url = StorageUrl::Cloud(CloudUrl {
                    scheme: cloud.scheme,
                    bucket_name: Some(name.clone()),
                    object_name: None,
                    generation: None,
                });
                refs.push(BucketListingRef::Bucket {
                    url: b_url,
                    metadata: Some(Box::new(b)),
                });
            }
        }
        return Ok(refs);
    }

    let bucket_pat = cloud.bucket_name.as_deref().unwrap_or("");
    if !contains_wildcard(bucket_pat) {
        // Non-wildcard bucket: fetch metadata unless caller only asked for `["id"]`.
        let need_fetch = !matches!(fields, Some([f]) if f == "id");
        let meta = if need_fetch {
            Some(Box::new(api.get_bucket(bucket_pat, fields).await?))
        } else {
            None
        };
        let b_url = StorageUrl::Cloud(CloudUrl {
            scheme: cloud.scheme,
            bucket_name: Some(bucket_pat.to_string()),
            object_name: None,
            generation: None,
        });
        return Ok(vec![BucketListingRef::Bucket {
            url: b_url,
            metadata: meta,
        }]);
    }

    let matcher = WildcardMatcher::compile(bucket_pat)?;
    let buckets = api.list_buckets(project_id, fields).await?;
    let mut refs = Vec::new();
    for b in buckets {
        if let Some(ref name) = b.name {
            if matcher.is_match(name) {
                let b_url = StorageUrl::Cloud(CloudUrl {
                    scheme: cloud.scheme,
                    bucket_name: Some(name.clone()),
                    object_name: None,
                    generation: None,
                });
                refs.push(BucketListingRef::Bucket {
                    url: b_url,
                    metadata: Some(Box::new(b)),
                });
            }
        }
    }
    Ok(refs)
}

/// Stream-expand a cloud URL (which may contain wildcards `*`, `?`, `[...]`, `**`)
/// into matching objects and/or prefixes, invoking `on_item` page-by-page for O(page_size) memory.
pub async fn iter_all_streaming(
    api: &dyn CloudApi,
    url_str: &str,
    project_id: Option<&str>,
    all_versions: bool,
    fields: Option<&[String]>,
    on_item: &mut (dyn FnMut(BucketListingRef) -> Result<()> + Send),
) -> Result<()> {
    let url = StorageUrl::parse(url_str)?;
    let cloud = url
        .as_cloud()
        .ok_or_else(|| GsutilError::command(format!("Expected cloud URL, got {url_str}")))?;
    let api = api.for_provider(cloud.scheme.as_str())?;

    if cloud.is_provider() {
        for b in iter_buckets(api, url_str, project_id, fields).await? {
            on_item(b)?;
        }
        return Ok(());
    }

    let bucket_pat = cloud.bucket_name.as_deref().unwrap_or("");
    let buckets: Vec<String> = if contains_wildcard(bucket_pat) {
        let matcher = WildcardMatcher::compile(bucket_pat)?;
        api.list_buckets(project_id, Some(&["id".to_string()]))
            .await?
            .into_iter()
            .filter_map(|b| b.name)
            .filter(|name| matcher.is_match(name))
            .collect()
    } else {
        vec![bucket_pat.to_string()]
    };

    let Some(obj_pat) = cloud.object_name.as_deref() else {
        // Bucket URL without object part -> return bucket refs.
        for b in buckets {
            let b_url = StorageUrl::Cloud(CloudUrl {
                scheme: cloud.scheme,
                bucket_name: Some(b),
                object_name: None,
                generation: None,
            });
            on_item(BucketListingRef::Bucket {
                url: b_url,
                metadata: None,
            })?;
        }
        return Ok(());
    };

    for bucket_name in buckets {
        expand_bucket_objects(
            api,
            cloud.scheme,
            &bucket_name,
            obj_pat,
            cloud.generation.as_deref(),
            all_versions,
            fields,
            on_item,
        )
        .await?;
    }
    Ok(())
}

/// Expand a cloud URL (which may contain wildcards `*`, `?`, `[...]`, `**`) into
/// matching objects and/or prefixes.
pub async fn iter_all(
    api: &dyn CloudApi,
    url_str: &str,
    project_id: Option<&str>,
    all_versions: bool,
    fields: Option<&[String]>,
) -> Result<Vec<BucketListingRef>> {
    let mut results = Vec::new();
    iter_all_streaming(
        api,
        url_str,
        project_id,
        all_versions,
        fields,
        &mut |item| {
            results.push(item);
            Ok(())
        },
    )
    .await?;
    Ok(results)
}

/// Stream-expand only objects (filtering out prefixes/buckets) for a cloud URL.
pub async fn iter_objects_streaming(
    api: &dyn CloudApi,
    url_str: &str,
    project_id: Option<&str>,
    all_versions: bool,
    fields: Option<&[String]>,
    on_obj: &mut (dyn FnMut(BucketListingRef) -> Result<()> + Send),
) -> Result<()> {
    // Match Python WildcardIterator.IterObjects: for a non-wildcard bucket URL
    // (e.g. `gs://nonexistent`), verify bucket existence so GCS returns
    // BucketNotFoundException / NotFoundException instead of silently returning empty.
    if let Ok(url) = StorageUrl::parse(url_str) {
        if let Some(cloud) = url.as_cloud() {
            if cloud.is_bucket() {
                let bucket_pat = cloud.bucket_name.as_deref().unwrap_or("");
                if !contains_wildcard(bucket_pat) {
                    let provider_api = api.for_provider(cloud.scheme.as_str())?;
                    provider_api
                        .get_bucket(bucket_pat, Some(&["id".to_string()]))
                        .await?;
                    return Ok(());
                }
            }
        }
    }
    iter_all_streaming(
        api,
        url_str,
        project_id,
        all_versions,
        fields,
        &mut |item| {
            if item.is_object() {
                on_obj(item)?;
            }
            Ok(())
        },
    )
    .await
}

/// Expand only objects (filtering out prefixes/buckets) for a cloud URL.
pub async fn iter_objects(
    api: &dyn CloudApi,
    url_str: &str,
    project_id: Option<&str>,
    all_versions: bool,
    fields: Option<&[String]>,
) -> Result<Vec<BucketListingRef>> {
    let mut results = Vec::new();
    iter_objects_streaming(
        api,
        url_str,
        project_id,
        all_versions,
        fields,
        &mut |item| {
            results.push(item);
            Ok(())
        },
    )
    .await?;
    Ok(results)
}

#[allow(clippy::too_many_arguments)]
async fn expand_bucket_objects_inner(
    api: &dyn CloudApi,
    scheme: gsutil_core::url::CloudScheme,
    bucket_name: &str,
    obj_pat: &str,
    generation: Option<&str>,
    all_versions: bool,
    fields: Option<&[String]>,
    on_item: &mut (dyn FnMut(BucketListingRef) -> Result<()> + Send),
) -> Result<()> {
    // Non-wildcard direct object lookup when generation is specified or exact object name.
    if !contains_wildcard(obj_pat) {
        if let Some(gen) = generation {
            match api
                .get_object_metadata(bucket_name, obj_pat, Some(gen), fields)
                .await
            {
                Ok(obj) => {
                    let obj_url = StorageUrl::Cloud(CloudUrl {
                        scheme,
                        bucket_name: Some(bucket_name.to_string()),
                        object_name: Some(obj_pat.to_string()),
                        generation: obj.generation.clone().or_else(|| Some(gen.to_string())),
                    });
                    on_item(BucketListingRef::Object {
                        url: obj_url,
                        metadata: Some(Box::new(obj)),
                    })?;
                }
                Err(e) if e.is_not_found() => {}
                Err(e) => return Err(e),
            }
            return Ok(());
        }

        // List with prefix=obj_pat, delimiter="/" to match either exact object or subdir prefix.
        let opts = ListObjectsOptions {
            prefix: Some(obj_pat.to_string()),
            delimiter: Some("/".to_string()),
            all_versions,
            fields: fields.map(|f| f.to_vec()),
        };
        let trimmed = strip_one_slash(obj_pat);
        let dir_prefix = format!("{trimmed}/");

        if obj_pat.ends_with('/') {
            // Trailing-slash URL (e.g. `gs://bucket/prefix/`): if any object or
            // sub-prefix exists under this prefix, emit it as a directory Prefix.
            let mut found_any = false;
            api.list_objects_paged(bucket_name, &opts, &mut |page| {
                if !page.is_empty() {
                    found_any = true;
                }
                Ok(())
            })
            .await?;
            if found_any {
                let pref_url = StorageUrl::Cloud(CloudUrl {
                    scheme,
                    bucket_name: Some(bucket_name.to_string()),
                    object_name: Some(obj_pat.to_string()),
                    generation: None,
                });
                on_item(BucketListingRef::Prefix {
                    url: pref_url,
                    prefix: obj_pat.to_string(),
                })?;
            }
            return Ok(());
        }

        api.list_objects_paged(bucket_name, &opts, &mut |page| {
            for item in page {
                match item {
                    CsObjectOrPrefix::Object(obj) => {
                        let name = obj.name.as_deref().unwrap_or("");
                        if name == obj_pat || name == trimmed {
                            let gen_opt = if all_versions {
                                obj.generation.clone()
                            } else {
                                None
                            };
                            let obj_url = StorageUrl::Cloud(CloudUrl {
                                scheme,
                                bucket_name: Some(bucket_name.to_string()),
                                object_name: Some(name.to_string()),
                                generation: gen_opt,
                            });
                            on_item(BucketListingRef::Object {
                                url: obj_url,
                                metadata: Some(obj),
                            })?;
                        }
                    }
                    CsObjectOrPrefix::Prefix(pref) => {
                        if pref == dir_prefix || pref == obj_pat {
                            let pref_url = StorageUrl::Cloud(CloudUrl {
                                scheme,
                                bucket_name: Some(bucket_name.to_string()),
                                object_name: Some(pref.clone()),
                                generation: None,
                            });
                            on_item(BucketListingRef::Prefix {
                                url: pref_url,
                                prefix: pref,
                            })?;
                        }
                    }
                }
            }
            Ok(())
        })
        .await?;
        return Ok(());
    }

    // Wildcard expansion using build_bucket_filter_strings.
    let filter = build_bucket_filter_strings(obj_pat);
    let matcher = WildcardMatcher::compile(&filter.prefix_wildcard)?;
    let opts = ListObjectsOptions {
        prefix: filter.prefix,
        delimiter: filter.delimiter,
        all_versions,
        fields: fields.map(|f| f.to_vec()),
    };

    let mut sub_prefixes = Vec::new();
    api.list_objects_paged(bucket_name, &opts, &mut |page| {
        for item in page {
            match item {
                CsObjectOrPrefix::Object(obj) => {
                    let name = obj.name.as_deref().unwrap_or("");
                    if filter.suffix_wildcard.is_empty() && matcher.is_match(name) {
                        let gen_opt = if all_versions {
                            obj.generation.clone()
                        } else {
                            None
                        };
                        let obj_url = StorageUrl::Cloud(CloudUrl {
                            scheme,
                            bucket_name: Some(bucket_name.to_string()),
                            object_name: Some(name.to_string()),
                            generation: gen_opt,
                        });
                        on_item(BucketListingRef::Object {
                            url: obj_url,
                            metadata: Some(obj),
                        })?;
                    }
                }
                CsObjectOrPrefix::Prefix(pref) => {
                    let stripped = strip_one_slash(&pref);
                    if matcher.is_match(stripped) || matcher.is_match(&pref) {
                        if filter.suffix_wildcard.is_empty() {
                            let pref_url = StorageUrl::Cloud(CloudUrl {
                                scheme,
                                bucket_name: Some(bucket_name.to_string()),
                                object_name: Some(pref.clone()),
                                generation: None,
                            });
                            on_item(BucketListingRef::Prefix {
                                url: pref_url,
                                prefix: pref,
                            })?;
                        } else {
                            sub_prefixes.push(format!("{pref}{}", filter.suffix_wildcard));
                        }
                    }
                }
            }
        }
        Ok(())
    })
    .await?;

    for sub in sub_prefixes {
        Box::pin(expand_bucket_objects(
            api,
            scheme,
            bucket_name,
            &sub,
            generation,
            all_versions,
            fields,
            on_item,
        ))
        .await?;
    }

    Ok(())
}

// Helper wrapper without needing an external async-recursion macro crate.
#[allow(clippy::too_many_arguments)]
fn expand_bucket_objects<'a>(
    api: &'a dyn CloudApi,
    scheme: gsutil_core::url::CloudScheme,
    bucket_name: &'a str,
    obj_pat: &'a str,
    generation: Option<&'a str>,
    all_versions: bool,
    fields: Option<&'a [String]>,
    on_item: &'a mut (dyn FnMut(BucketListingRef) -> Result<()> + Send),
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(expand_bucket_objects_inner(
        api,
        scheme,
        bucket_name,
        obj_pat,
        generation,
        all_versions,
        fields,
        on_item,
    ))
}

/// Expand local filesystem paths (supporting `*`, `?`, `[...]` wildcards).
pub fn expand_local_files(pattern: &str) -> Result<Vec<PathBuf>> {
    let url = StorageUrl::parse(pattern)?;
    let file_path = url
        .as_file()
        .map(|f| f.object_name.as_str())
        .unwrap_or(pattern);

    if !contains_wildcard(file_path) {
        let p = PathBuf::from(file_path);
        if p.exists() && p.is_file() {
            return Ok(vec![p]);
        }
        return Ok(Vec::new());
    }

    // Simple directory-based glob expansion for local files.
    let path = Path::new(file_path);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_pat = path.file_name().and_then(|n| n.to_str()).unwrap_or("*");
    let matcher = WildcardMatcher::compile(file_pat)?;

    let mut matches = Vec::new();
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if matcher.is_match(name) {
                        matches.push(p);
                    }
                }
            }
        }
    }
    matches.sort();
    Ok(matches)
}
