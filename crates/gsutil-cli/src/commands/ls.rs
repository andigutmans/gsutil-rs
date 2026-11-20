//! `gsutil ls` (`dir`, `list`) command (`-l`, `-L`, `-a`, `-b`, `-d`, `-e`, `-h`, `-p`, `-r`/`-R`).

use gsutil_core::api::{BucketListingRef, CloudApi};
use gsutil_core::error::{no_urls_matched_target, GsutilError, Result};
use gsutil_core::url::{contains_wildcard, StorageUrl};

use crate::context::{insist_ascii, CommandContext};
use crate::dispatch::{CommandSpec, NO_MAX};
use crate::format::{
    format_bucket_info_long_long, format_full_info_about_object, format_ls_timestamp,
    make_human_readable,
};
use crate::getopt::OptPair;
use crate::wildcard_iter::{iter_all, iter_buckets};

pub const SYNOPSIS: &str = "\n  gsutil ls [-a] [-b] [-d] [-l] [-L] [-r] [-p proj_id] url...\n";

pub const HELP_TEXT: &str = r#"<B>SYNOPSIS</B>

  gsutil ls [-a] [-b] [-d] [-l] [-L] [-r] [-p proj_id] url...


<B>DESCRIPTION</B>
  Retrieves a list of providers, buckets, or objects matching the criteria,
  ordered in the list lexicographically by name.

<B>OPTIONS</B>
  -l          Prints long listing (size, creation time, URL).
  -L          Prints full metadata details for objects and buckets.
  -d          List matching subdirectory names instead of contents.
  -b          Prints info about the bucket when used with a bucket URL.
  -h          When used with -l, prints object sizes in human readable format.
  -p proj_id  Specifies the project ID or project number to use for listing buckets.
  -R, -r      Requests a recursive listing.
  -a          Includes non-current object versions / generations.
  -e          Include ETag in long listing (-l) output.
"#;

pub const SPEC: CommandSpec = CommandSpec {
    name: "ls",
    aliases: &["dir", "list"],
    help_aliases: &["dir", "list"],
    one_line_summary: "List providers, buckets, or objects",
    usage_synopsis: SYNOPSIS,
    help_text: HELP_TEXT,
    subcommands: &[],
    min_args: 0,
    max_args: NO_MAX,
    supported_sub_args: "aebdlLhp:rR",
    supported_private_args: &[],
    file_url_ok: false,
    provider_url_ok: true,
    urls_start_arg: 0,
    has_subcommands_and_subopts: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListingStyle {
    Short,
    Long,
    LongLong,
}

struct LsOpts {
    style: ListingStyle,
    get_bucket_info: bool,
    recursive: bool,
    all_versions: bool,
    include_etag: bool,
    human_readable: bool,
    list_subdir_contents: bool,
    project_id: Option<String>,
}

pub async fn run(ctx: &mut CommandContext, sub_opts: &[OptPair], args: &[String]) -> Result<i32> {
    let mut opts = LsOpts {
        style: ListingStyle::Short,
        get_bucket_info: false,
        recursive: false,
        all_versions: false,
        include_etag: false,
        human_readable: false,
        list_subdir_contents: true,
        project_id: None,
    };

    for (o, a) in sub_opts {
        match o.as_str() {
            "-a" => opts.all_versions = true,
            "-e" => opts.include_etag = true,
            "-b" => opts.get_bucket_info = true,
            "-h" => opts.human_readable = true,
            "-l" => opts.style = ListingStyle::Long,
            "-L" => opts.style = ListingStyle::LongLong,
            "-p" => {
                insist_ascii(a, "Invalid non-ASCII character found in project ID")?;
                opts.project_id = Some(a.clone());
            }
            "-r" | "-R" => opts.recursive = true,
            "-d" => opts.list_subdir_contents = false,
            _ => {}
        }
    }

    let url_args: Vec<String> = if args.is_empty() {
        vec!["gs://".to_string()]
    } else {
        args.to_vec()
    };

    let api = ctx.api().await?;
    let effective_project = ctx
        .effective_project_id(opts.project_id.as_deref())
        .map(ToString::to_string);
    let mut total_objs = 0u64;
    let mut total_bytes = 0u64;
    let mut got_nomatch_errors = false;
    let mut got_bucket_nomatch_errors = false;

    for url_str in &url_args {
        let storage_url = StorageUrl::parse(url_str)?;
        if storage_url.is_file_url() {
            return Err(GsutilError::command("Only cloud URLs are supported for ls"));
        }

        if storage_url.is_provider() {
            let fields = bucket_fields_for_style(opts.style);
            let blrs = iter_buckets(
                api.as_ref(),
                &format!("{}://*", storage_url.scheme()),
                effective_project.as_deref(),
                fields.as_deref(),
            )
            .await?;
            for blr in blrs {
                print_bucket_info(ctx, &blr, opts.style)?;
            }
        } else if storage_url.is_bucket() && opts.get_bucket_info {
            let fields = bucket_fields_for_style(opts.style);
            let blrs = iter_buckets(
                api.as_ref(),
                url_str,
                effective_project.as_deref(),
                fields.as_deref(),
            )
            .await?;
            let mut count = 0usize;
            for blr in blrs {
                if !contains_wildcard(url_str) {
                    if let BucketListingRef::Bucket {
                        url: ref b_url,
                        metadata: None,
                    } = blr
                    {
                        api.get_bucket(
                            b_url.bucket_name().unwrap_or(""),
                            Some(&["id".to_string()]),
                        )
                        .await?;
                    }
                }
                print_bucket_info(ctx, &blr, opts.style)?;
                count += 1;
            }
            if !contains_wildcard(url_str) && count == 0 {
                got_bucket_nomatch_errors = true;
            }
        } else {
            let (matched, objs, bytes) = list_url(
                ctx,
                api.as_ref(),
                &storage_url,
                url_args.len() > 1,
                effective_project.as_deref(),
                &opts,
            )
            .await?;
            total_objs += objs;
            total_bytes += bytes;
            if !matched {
                if storage_url.is_bucket() {
                    got_bucket_nomatch_errors = true;
                } else {
                    ctx.error(&no_urls_matched_target(url_str));
                    got_nomatch_errors = true;
                }
            }
        }
    }

    if total_objs > 0 && matches!(opts.style, ListingStyle::Long | ListingStyle::LongLong) {
        ctx.println(&format!(
            "TOTAL: {total_objs} objects, {total_bytes} bytes ({})",
            make_human_readable(total_bytes)
        ))?;
    }

    if got_nomatch_errors {
        return Err(GsutilError::command("One or more URLs matched no objects."));
    }
    if got_bucket_nomatch_errors {
        return Err(gsutil_core::error::ServiceError::not_found(
            "One or more bucket URLs matched no buckets.",
            Some(404),
            None,
        )
        .into());
    }

    Ok(0)
}

fn bucket_fields_for_style(style: ListingStyle) -> Option<Vec<String>> {
    match style {
        ListingStyle::Short | ListingStyle::Long => Some(vec!["id".to_string()]),
        ListingStyle::LongLong => None,
    }
}

fn print_bucket_info(
    ctx: &CommandContext,
    blr: &BucketListingRef,
    style: ListingStyle,
) -> Result<()> {
    match style {
        ListingStyle::Short | ListingStyle::Long => ctx.println(&blr.url().url_string()),
        ListingStyle::LongLong => {
            if let BucketListingRef::Bucket {
                url,
                metadata: Some(bucket),
            } = blr
            {
                let formatted = format_bucket_info_long_long(&url.url_string(), bucket);
                ctx.println(&formatted)?;
            } else {
                ctx.println(&blr.url().url_string())?;
            }
            Ok(())
        }
    }
}

fn print_object(ctx: &CommandContext, blr: &BucketListingRef, opts: &LsOpts) -> Result<(u64, u64)> {
    let BucketListingRef::Object { url, metadata } = blr else {
        return Ok((0, 0));
    };
    let url_str = url.url_string();
    match opts.style {
        ListingStyle::Short => {
            ctx.println(&url_str)?;
            Ok((1, 0))
        }
        ListingStyle::Long => {
            let obj = metadata.as_ref();
            let size = obj.map_or(0, |o| o.size_bytes());
            let size_str = if opts.human_readable {
                make_human_readable(size)
            } else {
                size.to_string()
            };
            let ts = format_ls_timestamp(obj.and_then(|o| o.time_created.as_deref()));
            let mut line = format!("{size_str:>10}  {ts}  {url_str}");
            if opts.all_versions {
                let mg = obj
                    .and_then(|o| o.metageneration.as_deref())
                    .unwrap_or("None");
                line.push_str(&format!("  metageneration={mg}"));
            }
            if opts.include_etag {
                let etag = obj.and_then(|o| o.etag.as_deref()).unwrap_or("None");
                line.push_str(&format!("  etag={etag}"));
            }
            ctx.println(&line)?;
            Ok((1, size))
        }
        ListingStyle::LongLong => {
            if let Some(obj) = metadata {
                let (lines, objs, bytes) = format_full_info_about_object(&url_str, obj, true);
                for l in lines {
                    ctx.println(&l)?;
                }
                Ok((objs, bytes))
            } else {
                ctx.println(&url_str)?;
                Ok((1, 0))
            }
        }
    }
}

fn print_prefix(ctx: &CommandContext, blr: &BucketListingRef, style: ListingStyle) -> Result<()> {
    match style {
        ListingStyle::Short => ctx.println(&blr.url().url_string()),
        ListingStyle::Long | ListingStyle::LongLong => {
            ctx.println(&format!("{:<33}{}", "", blr.url().url_string()))
        }
    }
}

async fn list_url(
    ctx: &CommandContext,
    api: &dyn CloudApi,
    storage_url: &StorageUrl,
    print_bucket_header: bool,
    project_id: Option<&str>,
    opts: &LsOpts,
) -> Result<(bool, u64, u64)> {
    let mut total_objs = 0u64;
    let mut total_bytes = 0u64;

    if storage_url.is_bucket() {
        if print_bucket_header {
            ctx.println(&format!("{}:", storage_url.url_string()))?;
        }
        let pattern = if opts.recursive {
            storage_url.create_prefix_url(Some("**"))
        } else {
            storage_url.create_prefix_url(Some("*"))
        };
        let items = iter_all(api, &pattern, project_id, opts.all_versions, None).await?;
        for blr in &items {
            match blr {
                BucketListingRef::Object { .. } => {
                    let (o, b) = print_object(ctx, blr, opts)?;
                    total_objs += o;
                    total_bytes += b;
                }
                BucketListingRef::Prefix { .. } => {
                    print_prefix(ctx, blr, opts.style)?;
                }
                BucketListingRef::Bucket { .. } => {}
            }
        }
        return Ok((true, total_objs, total_bytes));
    }

    // Object or subdirectory URL.
    let items = iter_all(
        api,
        &storage_url.url_string(),
        project_id,
        opts.all_versions,
        None,
    )
    .await?;

    if items.is_empty() {
        return Ok((false, 0, 0));
    }

    let mut subdirs = Vec::new();
    for blr in &items {
        match blr {
            BucketListingRef::Object { .. } => {
                let (o, b) = print_object(ctx, blr, opts)?;
                total_objs += o;
                total_bytes += b;
            }
            BucketListingRef::Prefix { .. } => {
                if !opts.list_subdir_contents {
                    print_prefix(ctx, blr, opts.style)?;
                } else {
                    subdirs.push(blr.url().clone());
                }
            }
            BucketListingRef::Bucket { .. } => {}
        }
    }

    for subdir in subdirs {
        let pattern = if opts.recursive {
            subdir.create_prefix_url(Some("**"))
        } else {
            subdir.create_prefix_url(Some("*"))
        };
        if items.len() > 1 || opts.recursive {
            ctx.println(&format!("{}:", subdir.url_string()))?;
        }
        let sub_items = iter_all(api, &pattern, project_id, opts.all_versions, None).await?;
        for sub_blr in &sub_items {
            match sub_blr {
                BucketListingRef::Object { .. } => {
                    let (o, b) = print_object(ctx, sub_blr, opts)?;
                    total_objs += o;
                    total_bytes += b;
                }
                BucketListingRef::Prefix { .. } => {
                    print_prefix(ctx, sub_blr, opts.style)?;
                }
                BucketListingRef::Bucket { .. } => {}
            }
        }
    }

    Ok((true, total_objs, total_bytes))
}
