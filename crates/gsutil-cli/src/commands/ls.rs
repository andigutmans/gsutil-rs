//! `gsutil ls` (`dir`, `list`) command (`-l`, `-L`, `-a`, `-b`, `-d`, `-e`, `-h`, `-p`, `-r`/`-R`).

use gsutil_core::api::{BucketListingRef, CloudApi, CsObjectOrPrefix, ListObjectsOptions};
use gsutil_core::error::{no_urls_matched_target, GsutilError, Result, ServiceErrorKind};
use gsutil_core::url::{contains_wildcard, CloudScheme, CloudUrl, StorageUrl};

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
            let blrs = match iter_buckets(
                api.as_ref(),
                url_str,
                effective_project.as_deref(),
                fields.as_deref(),
            )
            .await
            {
                Ok(b) => b,
                Err(GsutilError::Service(ref se))
                    if se.kind == ServiceErrorKind::BadRequest
                        && opts.style == ListingStyle::LongLong
                        && (se.reason.contains("Uniform bucket-level access")
                            || se.reason.contains("legacy ACL")) =>
                {
                    let no_acl_fields: Vec<String> = [
                        "id",
                        "name",
                        "location",
                        "locationType",
                        "storageClass",
                        "versioning",
                        "logging",
                        "website",
                        "cors",
                        "lifecycle",
                        "billing",
                        "labels",
                        "encryption",
                        "timeCreated",
                        "updated",
                        "metageneration",
                        "iamConfiguration",
                        "retentionPolicy",
                        "defaultEventBasedHold",
                        "autoclass",
                        "customPlacementConfig",
                        "rpo",
                    ]
                    .into_iter()
                    .map(String::from)
                    .collect();
                    iter_buckets(
                        api.as_ref(),
                        url_str,
                        effective_project.as_deref(),
                        Some(&no_acl_fields),
                    )
                    .await?
                }
                Err(e) => return Err(e),
            };
            let mut count = 0usize;
            for blr in blrs {
                if !contains_wildcard(url_str) {
                    if let BucketListingRef::Bucket {
                        url: ref b_url,
                        metadata: None,
                    } = blr
                    {
                        let provider_api = api.for_provider(b_url.scheme())?;
                        provider_api
                            .get_bucket(
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

type LsFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(u64, u64, u64)>> + 'a>>;

#[allow(clippy::too_many_arguments)]
fn recurse_prefix_and_print<'a>(
    ctx: &'a CommandContext,
    api: &'a dyn CloudApi,
    scheme: CloudScheme,
    bucket: String,
    prefix: String,
    opts: &'a LsOpts,
    mut print_initial_newline: bool,
) -> LsFuture<'a> {
    Box::pin(async move {
        let provider_api = api.for_provider(scheme.as_str())?;
        let list_opts = ListObjectsOptions {
            prefix: Some(prefix.clone()),
            delimiter: Some("/".to_string()),
            all_versions: opts.all_versions,
            fields: None,
        };
        let raw_items = provider_api.list_objects(&bucket, &list_opts).await?;
        let mut num_dirs = 0u64;
        let mut num_objs = 0u64;
        let mut num_bytes = 0u64;

        for item in raw_items {
            match item {
                CsObjectOrPrefix::Object(obj) => {
                    let name = obj.name.clone().unwrap_or_default();
                    let gen_opt = if opts.all_versions {
                        obj.generation.clone()
                    } else {
                        None
                    };
                    let obj_url = StorageUrl::Cloud(CloudUrl {
                        scheme,
                        bucket_name: Some(bucket.clone()),
                        object_name: Some(name),
                        generation: gen_opt,
                    });
                    let blr = BucketListingRef::Object {
                        url: obj_url,
                        metadata: Some(obj),
                    };
                    let (o, b) = print_object(ctx, &blr, opts)?;
                    num_objs += o;
                    num_bytes += b;
                }
                CsObjectOrPrefix::Prefix(sub_prefix) => {
                    if sub_prefix == prefix {
                        continue;
                    }
                    let pref_url = StorageUrl::Cloud(CloudUrl {
                        scheme,
                        bucket_name: Some(bucket.clone()),
                        object_name: Some(sub_prefix.clone()),
                        generation: None,
                    });
                    let blr = BucketListingRef::Prefix {
                        url: pref_url.clone(),
                        prefix: sub_prefix.clone(),
                    };
                    if opts.recursive {
                        if print_initial_newline {
                            ctx.println("")?;
                        } else {
                            print_initial_newline = true;
                        }
                        ctx.println(&format!("{}:", pref_url.url_string()))?;
                        let (nd, no, nb) = recurse_prefix_and_print(
                            ctx,
                            api,
                            scheme,
                            bucket.clone(),
                            sub_prefix,
                            opts,
                            true,
                        )
                        .await?;
                        num_dirs += nd;
                        num_objs += no;
                        num_bytes += nb;
                    } else {
                        print_prefix(ctx, &blr, opts.style)?;
                        num_dirs += 1;
                    }
                }
            }
        }
        Ok((num_dirs, num_objs, num_bytes))
    })
}

#[allow(clippy::too_many_arguments)]
fn recurse_expand_and_print<'a>(
    ctx: &'a CommandContext,
    api: &'a dyn CloudApi,
    pattern: String,
    project_id: Option<&'a str>,
    opts: &'a LsOpts,
    mut print_initial_newline: bool,
) -> LsFuture<'a> {
    Box::pin(async move {
        let items = iter_all(api, &pattern, project_id, opts.all_versions, None).await?;
        let mut num_dirs = 0u64;
        let mut num_objs = 0u64;
        let mut num_bytes = 0u64;

        for blr in &items {
            match blr {
                BucketListingRef::Object { .. } => {
                    let (o, b) = print_object(ctx, blr, opts)?;
                    num_objs += o;
                    num_bytes += b;
                }
                BucketListingRef::Prefix { url, prefix } => {
                    if opts.recursive {
                        if print_initial_newline {
                            ctx.println("")?;
                        } else {
                            print_initial_newline = true;
                        }
                        ctx.println(&format!("{}:", url.url_string()))?;
                        if let Some(cloud) = url.as_cloud() {
                            let (nd, no, nb) = recurse_prefix_and_print(
                                ctx,
                                api,
                                cloud.scheme,
                                cloud.bucket_name.clone().unwrap_or_default(),
                                prefix.clone(),
                                opts,
                                true,
                            )
                            .await?;
                            num_dirs += nd;
                            num_objs += no;
                            num_bytes += nb;
                        }
                    } else {
                        print_prefix(ctx, blr, opts.style)?;
                        num_dirs += 1;
                    }
                }
                BucketListingRef::Bucket { .. } => {}
            }
        }
        Ok((num_dirs, num_objs, num_bytes))
    })
}

async fn list_url(
    ctx: &CommandContext,
    api: &dyn CloudApi,
    storage_url: &StorageUrl,
    print_bucket_header: bool,
    project_id: Option<&str>,
    opts: &LsOpts,
) -> Result<(bool, u64, u64)> {
    if storage_url.is_bucket() {
        if print_bucket_header {
            ctx.println(&format!("{}:", storage_url.url_string()))?;
        }
        let pattern = storage_url.create_prefix_url(Some("*"));
        let (_, total_objs, total_bytes) =
            recurse_expand_and_print(ctx, api, pattern, project_id, opts, false).await?;
        return Ok((true, total_objs, total_bytes));
    }

    if opts.recursive {
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
        let mut total_objs = 0u64;
        let mut total_bytes = 0u64;
        let mut print_newline = false;
        for blr in &items {
            match blr {
                BucketListingRef::Object { .. } => {
                    let (o, b) = print_object(ctx, blr, opts)?;
                    total_objs += o;
                    total_bytes += b;
                    print_newline = true;
                }
                BucketListingRef::Prefix { url, prefix } => {
                    if print_newline {
                        ctx.println("")?;
                    } else {
                        print_newline = true;
                    }
                    ctx.println(&format!("{}:", url.url_string()))?;
                    if let Some(cloud) = url.as_cloud() {
                        let (_, no, nb) = recurse_prefix_and_print(
                            ctx,
                            api,
                            cloud.scheme,
                            cloud.bucket_name.clone().unwrap_or_default(),
                            prefix.clone(),
                            opts,
                            true,
                        )
                        .await?;
                        total_objs += no;
                        total_bytes += nb;
                    }
                }
                BucketListingRef::Bucket { .. } => {}
            }
        }
        return Ok((true, total_objs, total_bytes));
    }

    // Non-recursive object or subdirectory URL.
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

    let mut total_objs = 0u64;
    let mut total_bytes = 0u64;
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
        let subdir_url_str = subdir.url_string();
        if contains_wildcard(&subdir_url_str) {
            return Err(GsutilError::command(format!(
                "Cloud folder {subdir_url_str} contains a wildcard; gsutil does not currently support objects with wildcards in their name."
            )));
        }
        if items.len() > 1 {
            ctx.println(&format!("{subdir_url_str}:"))?;
        }
        if let Some(cloud) = subdir.as_cloud() {
            let (_, no, nb) = recurse_prefix_and_print(
                ctx,
                api,
                cloud.scheme,
                cloud.bucket_name.clone().unwrap_or_default(),
                cloud.object_name.clone().unwrap_or_default(),
                opts,
                true,
            )
            .await?;
            total_objs += no;
            total_bytes += nb;
        }
    }

    Ok((true, total_objs, total_bytes))
}
