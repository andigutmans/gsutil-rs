//! `gsutil du` command (`-0`, `-a`, `-c`, `-e`, `-h`, `-s`, `-X`).

use std::fs::File;
use std::io::{self, BufRead, BufReader};

use gsutil_core::api::BucketListingRef;
use gsutil_core::error::{GsutilError, Result};
use gsutil_core::url::{contains_wildcard, strip_one_slash, StorageUrl};
use gsutil_core::wildcard::WildcardMatcher;

use crate::context::CommandContext;
use crate::dispatch::{CommandSpec, NO_MAX};
use crate::format::make_human_readable;
use crate::getopt::OptPair;
use crate::wildcard_iter::{iter_buckets, iter_objects};

pub const SYNOPSIS: &str = "\n  gsutil du url...\n";

pub const HELP_TEXT: &str = r#"<B>SYNOPSIS</B>

  gsutil du url...


<B>DESCRIPTION</B>
  The du command displays the amount of space in bytes used up by the
  objects in a bucket, subdirectory, or project.

<B>OPTIONS</B>
  -0          Ends each output line with a 0 byte rather than a newline.
  -a          Includes both live and noncurrent object versions.
  -c          Includes a total size at the end of the output.
  -e          Exclude a pattern from the report (can be specified multiple times).
  -h          Prints object sizes in human-readable format.
  -s          Displays only the total size for each argument.
  -X          Exclude patterns from the given file (one per line, or - for stdin).
"#;

pub const SPEC: CommandSpec = CommandSpec {
    name: "du",
    aliases: &[],
    help_aliases: &[],
    one_line_summary: "Display object size usage",
    usage_synopsis: SYNOPSIS,
    help_text: HELP_TEXT,
    subcommands: &[],
    min_args: 0,
    max_args: NO_MAX,
    supported_sub_args: "0ace:hsX:",
    supported_private_args: &[],
    file_url_ok: false,
    provider_url_ok: true,
    urls_start_arg: 0,
    has_subcommands_and_subopts: false,
};

pub async fn run(ctx: &mut CommandContext, sub_opts: &[OptPair], args: &[String]) -> Result<i32> {
    let mut line_ending = "\n";
    let mut all_versions = false;
    let mut produce_total = false;
    let mut human_readable = false;
    let mut summary_only = false;
    let mut exclude_patterns: Vec<String> = Vec::new();

    for (o, a) in sub_opts {
        match o.as_str() {
            "-0" => line_ending = "\0",
            "-a" => all_versions = true,
            "-c" => produce_total = true,
            "-e" => exclude_patterns.push(a.clone()),
            "-h" => human_readable = true,
            "-s" => summary_only = true,
            "-X" => {
                if a == "-" {
                    let stdin = io::stdin();
                    for line in stdin.lock().lines() {
                        exclude_patterns.push(line?.trim().to_string());
                    }
                } else {
                    let file = File::open(a)?;
                    for line in BufReader::new(file).lines() {
                        exclude_patterns.push(line?.trim().to_string());
                    }
                }
            }
            _ => {}
        }
    }

    let matchers: Vec<WildcardMatcher> = exclude_patterns
        .iter()
        .filter(|p| !p.is_empty())
        .map(|p| WildcardMatcher::compile(p))
        .collect::<Result<Vec<_>>>()?;

    let url_args: Vec<String> = if args.is_empty() {
        vec!["gs://".to_string()]
    } else {
        args.to_vec()
    };

    let api = ctx.api().await?;
    let project_id = ctx.effective_project_id(None).map(ToString::to_string);
    let mut total_bytes = 0u64;
    let mut got_nomatch_errors = false;

    for url_arg in &url_args {
        let top_url = StorageUrl::parse(url_arg)?;
        if top_url.is_file_url() {
            return Err(GsutilError::command("Only cloud URLs are supported for du"));
        }

        let top_refs: Vec<BucketListingRef> = if top_url.is_provider() {
            iter_buckets(
                api.as_ref(),
                &format!("{}://*", top_url.scheme()),
                project_id.as_deref(),
                Some(&["id".to_string()]),
            )
            .await?
        } else if top_url.is_bucket() {
            iter_buckets(
                api.as_ref(),
                &format!(
                    "{}://{}",
                    top_url.scheme(),
                    top_url.bucket_name().unwrap_or("")
                ),
                project_id.as_deref(),
                Some(&["id".to_string()]),
            )
            .await?
        } else {
            vec![BucketListingRef::Object {
                url: top_url.clone(),
                metadata: None,
            }]
        };

        for blr in top_refs {
            let target_url = blr.url();
            let target_str = target_url.url_string();
            let query_pattern = if target_url.is_bucket() || target_str.ends_with('/') {
                target_url.create_prefix_url(Some("**"))
            } else {
                target_str.clone()
            };

            let mut objs = iter_objects(
                api.as_ref(),
                &query_pattern,
                project_id.as_deref(),
                all_versions,
                Some(&["name".to_string(), "size".to_string()]),
            )
            .await?;

            // If a non-wildcard object URL (e.g. `gs://bkt/subdir`) matched a prefix rather
            // than an object, recurse into that prefix (matching `LsHelper(..., should_recurse=True)`).
            if objs.is_empty()
                && !target_url.is_bucket()
                && !target_str.ends_with('/')
                && !contains_wildcard(&target_str)
            {
                let sub_pattern = target_url.create_prefix_url(Some("**"));
                objs = iter_objects(
                    api.as_ref(),
                    &sub_pattern,
                    project_id.as_deref(),
                    all_versions,
                    Some(&["name".to_string(), "size".to_string()]),
                )
                .await?;
            }

            let mut exp_objs = 0u64;
            let mut exp_bytes = 0u64;

            for obj_blr in objs {
                if let BucketListingRef::Object { url, metadata } = obj_blr {
                    let obj_url_str = url.url_string();
                    let obj_name = url.object_name().unwrap_or("");
                    if matchers
                        .iter()
                        .any(|m| m.is_match(obj_name) || m.is_match(&obj_url_str))
                    {
                        continue;
                    }
                    let size = metadata.as_ref().map_or(0, |m| m.size_bytes());
                    exp_objs += 1;
                    exp_bytes += size;

                    if !summary_only {
                        let size_str = if human_readable {
                            make_human_readable(size)
                        } else {
                            size.to_string()
                        };
                        let line = format!("{size_str:<11}  {obj_url_str}{line_ending}");
                        ctx.write_stdout(line.as_bytes())?;
                    }
                }
            }

            if target_url.is_object()
                && exp_objs == 0
                && contains_wildcard(url_arg)
                && exclude_patterns.is_empty()
            {
                got_nomatch_errors = true;
            }
            total_bytes += exp_bytes;

            if summary_only {
                let name = strip_one_slash(&blr.url().url_string()).to_string();
                let size_str = if human_readable {
                    make_human_readable(exp_bytes)
                } else {
                    exp_bytes.to_string()
                };
                let line = format!("{size_str:<11}  {name}{line_ending}");
                ctx.write_stdout(line.as_bytes())?;
            }
        }
    }

    if produce_total {
        let size_str = if human_readable {
            make_human_readable(total_bytes)
        } else {
            total_bytes.to_string()
        };
        let line = format!("{size_str:<11}  total{line_ending}");
        ctx.write_stdout(line.as_bytes())?;
    }
    ctx.flush_stdout()?;

    if got_nomatch_errors {
        return Err(GsutilError::command("One or more URLs matched no objects."));
    }

    Ok(0)
}
