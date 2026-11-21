//! `gsutil rm` (`del`, `delete`, `remove`) command (`-a`, `-f`, `-I`, `-r`/`-R`).

use std::io::{self, BufRead};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use futures::stream::{self, StreamExt};

use gsutil_core::api::BucketListingRef;
use gsutil_core::error::{no_urls_matched_target, GsutilError, Result, ServiceErrorKind};
use gsutil_core::url::StorageUrl;

use crate::context::CommandContext;
use crate::dispatch::{CommandSpec, NO_MAX};
use crate::getopt::OptPair;
use crate::wildcard_iter::{iter_buckets, iter_objects};

pub const SYNOPSIS: &str = "\n  gsutil rm [-f] [-r] url...\n  gsutil rm [-f] [-r] -I\n";

pub const HELP_TEXT: &str = r#"<B>SYNOPSIS</B>

  gsutil rm [-f] [-r] url...
  gsutil rm [-f] [-r] -I


<B>DESCRIPTION</B>
  The gsutil rm command removes objects and/or buckets.

<B>OPTIONS</B>
  -f          Continues silently despite errors when removing multiple objects.
  -I          Read the list of objects to remove from stdin.
  -R, -r      Remove bucket or subdirectory contents recursively (implies -a).
  -a          Delete all versions of an object.
"#;

pub const SPEC: CommandSpec = CommandSpec {
    name: "rm",
    aliases: &["del", "delete", "remove"],
    help_aliases: &["del", "delete", "remove"],
    one_line_summary: "Remove objects",
    usage_synopsis: SYNOPSIS,
    help_text: HELP_TEXT,
    subcommands: &[],
    min_args: 0,
    max_args: NO_MAX,
    supported_sub_args: "afIrR",
    supported_private_args: &[],
    file_url_ok: false,
    provider_url_ok: false,
    urls_start_arg: 0,
    has_subcommands_and_subopts: false,
};

pub async fn run(ctx: &mut CommandContext, sub_opts: &[OptPair], args: &[String]) -> Result<i32> {
    let mut continue_on_error = ctx.global.parallel_operations;
    let mut read_args_from_stdin = false;
    let mut all_versions = false;
    let mut recursion_requested = false;

    for (o, _) in sub_opts {
        match o.as_str() {
            "-a" => all_versions = true,
            "-f" => continue_on_error = true,
            "-I" => read_args_from_stdin = true,
            "-r" | "-R" => {
                recursion_requested = true;
                all_versions = true;
            }
            _ => {}
        }
    }

    let url_strs: Vec<String> = if read_args_from_stdin {
        if !args.is_empty() {
            return Err(GsutilError::command(
                "No arguments allowed with the -I flag.",
            ));
        }
        let stdin = io::stdin();
        stdin
            .lock()
            .lines()
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        if args.is_empty() {
            return Err(GsutilError::command(
                "The rm command (without -I) expects at least one URL.",
            ));
        }
        args.to_vec()
    };

    let api = ctx.api().await?;
    let project_id = ctx.effective_project_id(None).map(ToString::to_string);
    let preconditions = ctx.preconditions_from_headers()?;

    let mut bucket_urls_to_delete: Vec<StorageUrl> = Vec::new();
    let mut targets: Vec<StorageUrl> = Vec::new();
    let mut seen_targets: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut deferred_nomatch_err: Option<GsutilError> = None;
    let mut nomatch_error_count: usize = 0;

    for url_str in &url_strs {
        let url = StorageUrl::parse(url_str)?;
        if url.is_file_url() {
            return Err(GsutilError::command(
                "\"rm\" command does not support \"file://\" URLs. Did you mean to use a gs:// URL?",
            ));
        }

        if url.is_bucket() || url.is_provider() {
            if !recursion_requested {
                return Err(GsutilError::command(format!(
                    "Omitting bucket \"{url_str}\". (Did you mean to do rm -r?)"
                )));
            }
            let buckets = match iter_buckets(
                api.as_ref(),
                url_str,
                project_id.as_deref(),
                Some(&["id".to_string()]),
            )
            .await
            {
                Ok(b) => b,
                Err(e) if e.is_not_found() => {
                    return Err(GsutilError::command(format!(
                        "Encountered non-existent bucket {url_str} during listing"
                    )));
                }
                Err(e) => return Err(e),
            };
            for b in buckets {
                let b_url = b.url().clone();
                let pattern = b_url.create_prefix_url(Some("**"));
                let objs = match iter_objects(
                    api.as_ref(),
                    &pattern,
                    project_id.as_deref(),
                    all_versions,
                    Some(&["name".to_string(), "generation".to_string()]),
                )
                .await
                {
                    Ok(o) => o,
                    Err(e) if e.is_not_found() => {
                        return Err(GsutilError::command(format!(
                            "Encountered non-existent bucket {b_url} during listing"
                        )));
                    }
                    Err(e) => return Err(e),
                };
                for o in objs {
                    if let BucketListingRef::Object { url: obj_url, .. } = o {
                        if seen_targets.insert(obj_url.url_string()) {
                            targets.push(obj_url);
                        }
                    }
                }
                bucket_urls_to_delete.push(b_url);
            }
        } else {
            let mut matched = Vec::new();
            if recursion_requested {
                if let Some(prefix_before_star) = url_str.strip_suffix("/*") {
                    // `rm -r gs://bucket/*` removes both root objects (including `dir_$folder$`)
                    // and all nested objects, without deleting the bucket itself.
                    let all_pat = format!("{prefix_before_star}/**");
                    matched.extend(
                        iter_objects(
                            api.as_ref(),
                            &all_pat,
                            project_id.as_deref(),
                            all_versions,
                            Some(&["name".to_string(), "generation".to_string()]),
                        )
                        .await?,
                    );
                } else {
                    let pattern = if !url_str.ends_with("**") {
                        url.create_prefix_url(Some("**"))
                    } else {
                        url_str.clone()
                    };
                    matched.extend(
                        iter_objects(
                            api.as_ref(),
                            &pattern,
                            project_id.as_deref(),
                            all_versions,
                            Some(&["name".to_string(), "generation".to_string()]),
                        )
                        .await?,
                    );
                    // Also check for `_$folder$` placeholder object (e.g. `gs://b/abc` -> `gs://b/abc_$folder$`).
                    if !gsutil_core::url::contains_wildcard(url_str) {
                        let trimmed = gsutil_core::url::strip_one_slash(url_str);
                        let folder_marker = format!("{trimmed}_$folder$");
                        if let Ok(folder_objs) = iter_objects(
                            api.as_ref(),
                            &folder_marker,
                            project_id.as_deref(),
                            all_versions,
                            Some(&["name".to_string(), "generation".to_string()]),
                        )
                        .await
                        {
                            matched.extend(folder_objs);
                        }
                    }
                    // Also check exact object when recursion_requested turned a file path into `path/**`.
                    if matched.is_empty() {
                        matched.extend(
                            iter_objects(
                                api.as_ref(),
                                url_str,
                                project_id.as_deref(),
                                all_versions,
                                Some(&["name".to_string(), "generation".to_string()]),
                            )
                            .await?,
                        );
                    }
                }
            } else {
                matched = iter_objects(
                    api.as_ref(),
                    url_str,
                    project_id.as_deref(),
                    all_versions,
                    Some(&["name".to_string(), "generation".to_string()]),
                )
                .await?;
            }

            if matched.is_empty() {
                let err = GsutilError::command(no_urls_matched_target(url_str));
                nomatch_error_count += 1;
                if continue_on_error {
                    ctx.error(&err.to_string());
                    continue;
                }
                // Process any targets already matched by earlier URLs before failing,
                // matching Python gsutil's lazy iterator behavior (`test_some_missing`).
                deferred_nomatch_err = Some(err);
                break;
            }
            for o in matched {
                if let BucketListingRef::Object { url: obj_url, .. } = o {
                    if seen_targets.insert(obj_url.url_string()) {
                        targets.push(obj_url);
                    }
                }
            }
        }
    }

    let total_targets = targets.len();
    if ctx.global.parallel_operations
        && !read_args_from_stdin
        && !ctx.global.quiet
        && total_targets > 0
    {
        let force_est = ctx
            .config
            .get_bool("GSUtil", "task_estimation_force", false);
        let threshold = ctx
            .config
            .get("GSUtil", "task_estimation_threshold")
            .and_then(|v| v.trim().parse::<i64>().ok())
            .unwrap_or(50_000);
        if force_est || (threshold > 0 && (total_targets as i64) >= threshold) {
            ctx.error(&format!(
                "Estimated work for this command: objects: {total_targets}"
            ));
        }
    }

    let op_failure_count = Arc::new(AtomicUsize::new(0));
    let removed_count = Arc::new(AtomicUsize::new(0));
    let concurrency = if ctx.global.parallel_operations {
        ctx.config.parallel_thread_count().max(1)
    } else {
        1
    };

    if concurrency == 1 {
        for obj_url in &targets {
            ctx.info(&format!("Removing {obj_url}..."));
            let bucket = obj_url.bucket_name().unwrap_or("");
            let name = obj_url.object_name().unwrap_or("");
            let provider_api = api.for_provider(obj_url.scheme())?;
            match provider_api
                .delete_object(bucket, name, obj_url.generation(), Some(&preconditions))
                .await
            {
                Ok(()) => {
                    removed_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) if e.is_not_found() => {
                    ctx.info(&format!("Cannot find {obj_url}"));
                }
                Err(e) => {
                    if !continue_on_error {
                        return Err(e);
                    }
                    op_failure_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    } else {
        let quiet = ctx.global.quiet;
        let precond = preconditions.clone();
        let removed_ref = removed_count.clone();
        stream::iter(targets)
            .for_each_concurrent(concurrency, |obj_url| {
                let api = api.clone();
                let failures = op_failure_count.clone();
                let removed = removed_ref.clone();
                let precond = precond.clone();
                async move {
                    if !quiet {
                        eprintln!("Removing {obj_url}...");
                    }
                    let bucket = obj_url.bucket_name().unwrap_or("");
                    let name = obj_url.object_name().unwrap_or("");
                    let res = match api.for_provider(obj_url.scheme()) {
                        Ok(provider_api) => {
                            provider_api
                                .delete_object(bucket, name, obj_url.generation(), Some(&precond))
                                .await
                        }
                        Err(e) => Err(e),
                    };
                    match res {
                        Ok(()) => {
                            removed.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) if e.is_not_found() => {
                            if !quiet {
                                eprintln!("Cannot find {obj_url}");
                            }
                        }
                        Err(_) => {
                            failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
            .await;
    }

    let removed = removed_count.load(Ordering::Relaxed);
    if !ctx.global.quiet && removed > 0 {
        if ctx.global.parallel_operations {
            ctx.info(&format!("[{removed}/{total_targets} objects]"));
        } else {
            ctx.info(&format!("[{removed} objects]"));
        }
        ctx.info(&format!("Operation completed over {removed} objects."));
    }

    if let Some(err) = deferred_nomatch_err {
        return Err(err);
    }

    // Delete any buckets slated for recursive deletion.
    for b_url in &bucket_urls_to_delete {
        ctx.info(&format!("Removing {b_url}..."));
        let bucket = b_url.bucket_name().unwrap_or("");
        let provider_api = api.for_provider(b_url.scheme())?;
        let mut attempts = 0;
        loop {
            attempts += 1;
            match provider_api.delete_bucket(bucket, None).await {
                Ok(()) => break,
                Err(GsutilError::Service(se))
                    if se.kind == ServiceErrorKind::NotEmpty && attempts < 3 =>
                {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    let total_failures = op_failure_count.load(Ordering::Relaxed) + nomatch_error_count;
    if total_failures > 0 {
        return Err(GsutilError::command(format!(
            "{total_failures} files/objects could not be removed."
        )));
    }

    Ok(0)
}
