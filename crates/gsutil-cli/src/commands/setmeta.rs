//! `gsutil setmeta` (`setheader`) command (`-h`, `-r`/`-R`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures::stream::{self, StreamExt};

use gsutil_core::api::{BucketListingRef, Object, Preconditions};
use gsutil_core::error::{no_urls_matched_target, GsutilError, Result, ServiceErrorKind};
use gsutil_core::url::StorageUrl;

use crate::context::{insist_ascii, CommandContext};
use crate::dispatch::{CommandSpec, NO_MAX};
use crate::getopt::OptPair;
use crate::wildcard_iter::iter_objects;

pub const SYNOPSIS: &str = "\n  gsutil setmeta -h [header:value|header] ... url...\n";

pub const HELP_TEXT: &str = r#"<B>SYNOPSIS</B>

  gsutil setmeta -h [header:value|header] ... url...


<B>DESCRIPTION</B>
  The gsutil setmeta command allows you to set or remove the metadata on one
  or more objects.

<B>OPTIONS</B>
  -h          Specifies a header:value to be added, or header to be removed,
              from each named object.
  -r, -R      Causes bucket or subdirectory contents to be updated recursively.
"#;

pub const SPEC: CommandSpec = CommandSpec {
    name: "setmeta",
    aliases: &["setheader"],
    help_aliases: &["setheader"],
    one_line_summary: "Set metadata on already uploaded objects",
    usage_synopsis: SYNOPSIS,
    help_text: HELP_TEXT,
    subcommands: &[],
    min_args: 1,
    max_args: NO_MAX,
    supported_sub_args: "h:rR",
    supported_private_args: &[],
    file_url_ok: false,
    provider_url_ok: false,
    urls_start_arg: 0,
    has_subcommands_and_subopts: false,
};

const SETTABLE_FIELDS: &[&str] = &[
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-type",
    "custom-time",
];

fn is_custom_metadata_header(lowercase_header: &str) -> bool {
    lowercase_header.starts_with("x-goog-meta-") || lowercase_header.starts_with("x-amz-meta-")
}

fn parse_metadata_headers(headers: &[String]) -> Result<BTreeMap<String, String>> {
    let mut metadata_minus = BTreeSet::new();
    let mut cust_metadata_minus = BTreeSet::new();
    let mut metadata_plus = BTreeMap::new();
    let mut cust_metadata_plus = BTreeMap::new();

    let mut num_plus = 0usize;
    let mut num_cust_plus = 0usize;
    let mut num_minus = 0usize;
    let mut num_cust_minus = 0usize;

    for md_arg in headers {
        let (header, value) = match md_arg.split_once(':') {
            Some((h, v)) => (h, v),
            None => (md_arg.as_str(), ""),
        };
        insist_ascii(header, &format!("Invalid non-ASCII header ({header})."))?;

        let lower = header.to_ascii_lowercase();
        let is_custom = is_custom_metadata_header(&lower);
        if !is_custom && !SETTABLE_FIELDS.contains(&lower.as_str()) {
            return Err(GsutilError::command(format!(
                "Invalid or disallowed header ({header}).\nOnly these fields (plus x-goog-meta-* fields) can be set or unset:\n['cache-control', 'content-disposition', 'content-encoding', 'content-language', 'content-type', 'custom-time']"
            )));
        }

        if !value.is_empty() {
            if is_custom {
                cust_metadata_plus.insert(header.to_string(), value.to_string());
                num_cust_plus += 1;
            } else {
                insist_ascii(
                    value,
                    &format!("Invalid non-ASCII value for header ({header})."),
                )?;
                metadata_plus.insert(lower, value.to_string());
                num_plus += 1;
            }
        } else if is_custom {
            cust_metadata_minus.insert(header.to_string());
            num_cust_minus += 1;
        } else {
            metadata_minus.insert(lower);
            num_minus += 1;
        }
    }

    let has_overlap = metadata_minus.iter().any(|k| metadata_plus.contains_key(k))
        || cust_metadata_minus
            .iter()
            .any(|k| cust_metadata_plus.contains_key(k));

    if num_plus != metadata_plus.len()
        || num_cust_plus != cust_metadata_plus.len()
        || num_minus != metadata_minus.len()
        || num_cust_minus != cust_metadata_minus.len()
        || has_overlap
    {
        return Err(GsutilError::command(
            "Each header must appear at most once.",
        ));
    }

    let mut combined = BTreeMap::new();
    for (k, v) in metadata_plus {
        combined.insert(k, v);
    }
    for (k, v) in cust_metadata_plus {
        combined.insert(k, v);
    }
    for k in metadata_minus {
        combined.insert(k, String::new());
    }
    for k in cust_metadata_minus {
        combined.insert(k, String::new());
    }
    Ok(combined)
}

fn apply_metadata_changes(existing: &Object, changes: &BTreeMap<String, String>) -> Object {
    let mut patch = Object::default();
    let mut custom_meta = existing.metadata.clone().unwrap_or_default();
    let mut custom_set = false;

    for (k, v) in changes {
        let lower = k.to_ascii_lowercase();
        let is_clear = v.is_empty();
        match lower.as_str() {
            "cache-control" => {
                if is_clear {
                    patch.clear_fields.push("cacheControl".to_string());
                } else {
                    patch.cache_control = Some(v.clone());
                }
            }
            "content-disposition" => {
                if is_clear {
                    patch.clear_fields.push("contentDisposition".to_string());
                } else {
                    patch.content_disposition = Some(v.clone());
                }
            }
            "content-encoding" => {
                if is_clear {
                    patch.clear_fields.push("contentEncoding".to_string());
                } else {
                    patch.content_encoding = Some(v.clone());
                }
            }
            "content-language" => {
                if is_clear {
                    patch.clear_fields.push("contentLanguage".to_string());
                } else {
                    patch.content_language = Some(v.clone());
                }
            }
            "content-type" => {
                if is_clear {
                    patch.clear_fields.push("contentType".to_string());
                } else {
                    patch.content_type = Some(v.clone());
                }
            }
            "custom-time" => {
                if is_clear {
                    patch.clear_fields.push("customTime".to_string());
                } else {
                    patch.custom_time = Some(v.clone());
                }
            }
            _ if is_custom_metadata_header(&lower) => {
                let meta_key = if lower.starts_with("x-amz-meta-") {
                    &k[11..]
                } else {
                    k.get(12..).unwrap_or(k)
                };
                if is_clear {
                    custom_meta.remove(meta_key);
                    patch.metadata_removals.push(meta_key.to_string());
                } else {
                    custom_meta.insert(meta_key.to_string(), v.clone());
                    custom_set = true;
                }
            }
            _ => {}
        }
    }

    if custom_set {
        patch.metadata = Some(custom_meta);
    }
    patch
}

pub async fn run(ctx: &mut CommandContext, sub_opts: &[OptPair], args: &[String]) -> Result<i32> {
    let mut header_strs = Vec::new();
    let mut recursion_requested = false;

    for (o, a) in sub_opts {
        match o.as_str() {
            "-h" => {
                if a.contains("x-goog-acl") || a.contains("x-amz-acl") {
                    return Err(GsutilError::command(
                        "gsutil setmeta no longer allows canned ACLs. Use gsutil acl set ... to set canned ACLs.",
                    ));
                }
                header_strs.push(a.clone());
            }
            "-r" | "-R" => recursion_requested = true,
            _ => {}
        }
    }

    let metadata_change = parse_metadata_headers(&header_strs)?;
    if metadata_change.is_empty() {
        return Err(GsutilError::command(
            "gsutil setmeta requires one or more headers to be provided with the -h flag. See \"gsutil help setmeta\" for more information.",
        ));
    }

    if args.len() == 1 && !recursion_requested {
        let url = StorageUrl::parse(&args[0])?;
        if !(url.is_cloud_url() && url.is_object()) {
            return Err(GsutilError::command(format!(
                "URL ({}) must name an object",
                args[0]
            )));
        }
    }

    let api = ctx.api().await?;
    let project_id = ctx.effective_project_id(None).map(ToString::to_string);
    let base_precond = ctx.preconditions_from_headers()?;

    let everything_ok = Arc::new(AtomicBool::new(true));
    let mut work_items: Vec<(StorageUrl, Object)> = Vec::new();

    for url_str in args {
        let url = StorageUrl::parse(url_str)?;
        let pattern = if recursion_requested && !url_str.ends_with("**") {
            url.create_prefix_url(Some("**"))
        } else {
            url_str.clone()
        };

        let items = iter_objects(
            api.as_ref(),
            &pattern,
            project_id.as_deref(),
            false,
            Some(&[
                "name".to_string(),
                "generation".to_string(),
                "metadata".to_string(),
                "metageneration".to_string(),
            ]),
        )
        .await?;

        if items.is_empty() {
            return Err(GsutilError::command(no_urls_matched_target(url_str)));
        }

        for blr in items {
            if let BucketListingRef::Object {
                url: obj_url,
                metadata,
            } = blr
            {
                let existing = metadata.as_deref().cloned().unwrap_or_default();
                work_items.push((obj_url, existing));
            }
        }
    }

    let concurrency = if ctx.global.parallel_operations {
        ctx.config.parallel_thread_count().max(1)
    } else {
        1
    };

    if concurrency == 1 {
        for (obj_url, existing) in work_items {
            ctx.info(&format!("Setting metadata on {obj_url}..."));
            if let Err(e) = patch_single_object(
                api.as_ref(),
                &obj_url,
                &existing,
                &metadata_change,
                &base_precond,
            )
            .await
            {
                ctx.error(&e.to_string());
                everything_ok.store(false, Ordering::Relaxed);
            }
        }
    } else {
        let quiet = ctx.global.quiet;
        let stderr_cap = ctx.stderr_capture.clone();
        let metadata_change = Arc::new(metadata_change);
        let base_precond = Arc::new(base_precond);
        stream::iter(work_items)
            .for_each_concurrent(concurrency, |(obj_url, existing)| {
                let api = api.clone();
                let metadata_change = metadata_change.clone();
                let base_precond = base_precond.clone();
                let everything_ok = everything_ok.clone();
                let stderr_cap = stderr_cap.clone();
                async move {
                    if !quiet {
                        if let Some(ref buf) = stderr_cap {
                            if let Ok(mut g) = buf.lock() {
                                use std::io::Write;
                                let _ = writeln!(g, "Setting metadata on {obj_url}...");
                            }
                        } else {
                            eprintln!("Setting metadata on {obj_url}...");
                        }
                    }
                    if let Err(e) = patch_single_object(
                        api.as_ref(),
                        &obj_url,
                        &existing,
                        &metadata_change,
                        &base_precond,
                    )
                    .await
                    {
                        if let Some(ref buf) = stderr_cap {
                            if let Ok(mut g) = buf.lock() {
                                use std::io::Write;
                                let _ = writeln!(g, "{e}");
                            }
                        } else {
                            eprintln!("{e}");
                        }
                        everything_ok.store(false, Ordering::Relaxed);
                    }
                }
            })
            .await;
    }

    if !everything_ok.load(Ordering::Relaxed) {
        return Err(GsutilError::command(
            "Metadata for some objects could not be set.",
        ));
    }

    Ok(0)
}

async fn patch_single_object(
    api: &dyn gsutil_core::api::CloudApi,
    obj_url: &StorageUrl,
    existing: &Object,
    metadata_change: &BTreeMap<String, String>,
    base_precond: &Preconditions,
) -> Result<()> {
    let provider_api = api.for_provider(obj_url.scheme())?;
    let precond = Preconditions {
        gen_match: base_precond
            .gen_match
            .or_else(|| existing.generation.as_deref().and_then(|g| g.parse().ok())),
        meta_gen_match: base_precond.meta_gen_match.or_else(|| {
            existing
                .metageneration
                .as_deref()
                .and_then(|mg| mg.parse().ok())
        }),
    };
    let patch = apply_metadata_changes(existing, metadata_change);
    let bucket = obj_url.bucket_name().unwrap_or("");
    let name = obj_url.object_name().unwrap_or("");

    let mut attempts = 0;
    loop {
        attempts += 1;
        match provider_api
            .patch_object_metadata(
                bucket,
                name,
                &patch,
                None,
                obj_url.generation(),
                Some(&precond),
                Some(&["id".to_string()]),
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(GsutilError::Service(se))
                if se.kind == ServiceErrorKind::Precondition && attempts < 3 =>
            {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            Err(e) => return Err(e),
        }
    }
}
