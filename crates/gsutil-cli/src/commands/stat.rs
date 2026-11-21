//! `gsutil stat` command.

use gsutil_core::api::BucketListingRef;
use gsutil_core::error::{no_urls_matched_target, GsutilError, Result};
use gsutil_core::url::{contains_wildcard, StorageUrl};

use crate::context::CommandContext;
use crate::dispatch::{CommandSpec, NO_MAX};
use crate::format::format_full_info_about_object;
use crate::getopt::OptPair;
use crate::wildcard_iter::iter_objects;

pub const SYNOPSIS: &str = "\n  gsutil stat url...\n";

pub const HELP_TEXT: &str = r#"<B>SYNOPSIS</B>

  gsutil stat url...


<B>DESCRIPTION</B>
  The stat command outputs object metadata for the specified object URLs.
  If run with the ``gsutil -q`` option nothing is printed, and it returns
  exit status 0 for an existing object and 1 for a non-existent object.
"#;

pub const SPEC: CommandSpec = CommandSpec {
    name: "stat",
    aliases: &[],
    help_aliases: &[],
    one_line_summary: "Display object status",
    usage_synopsis: SYNOPSIS,
    help_text: HELP_TEXT,
    subcommands: &[],
    min_args: 1,
    max_args: NO_MAX,
    supported_sub_args: "",
    supported_private_args: &[],
    file_url_ok: false,
    provider_url_ok: false,
    urls_start_arg: 0,
    has_subcommands_and_subopts: false,
};

pub async fn run(ctx: &mut CommandContext, _sub_opts: &[OptPair], args: &[String]) -> Result<i32> {
    let api = ctx.api().await?;
    let project_id = ctx.effective_project_id(None).map(ToString::to_string);
    let mut found_nonmatching_arg = false;

    for url_str in args {
        let mut arg_matches = 0usize;
        let url = StorageUrl::parse(url_str)?;
        if !url.is_object() {
            return Err(GsutilError::command(
                "The stat command only works with object URLs",
            ));
        }

        let res = if contains_wildcard(url_str) {
            iter_objects(api.as_ref(), url_str, project_id.as_deref(), false, None).await
        } else {
            let bucket = url.bucket_name().unwrap_or("");
            let obj_name = url.object_name().unwrap_or("");
            let provider_api = api.for_provider(url.scheme())?;
            provider_api
                .get_object_metadata(bucket, obj_name, url.generation(), None)
                .await
                .map(|meta| {
                    vec![BucketListingRef::Object {
                        url: url.clone(),
                        metadata: Some(Box::new(meta)),
                    }]
                })
        };

        match res {
            Ok(items) => {
                for blr in items {
                    if let BucketListingRef::Object {
                        url: obj_url,
                        metadata: Some(meta),
                    } = blr
                    {
                        arg_matches += 1;
                        if !ctx.global.quiet {
                            let (lines, _, _) =
                                format_full_info_about_object(&obj_url.url_string(), &meta, false);
                            for line in lines {
                                ctx.println(&line)?;
                            }
                        }
                    }
                }
            }
            Err(e) if e.is_access_denied() => {
                ctx.info(&format!(
                    "You aren't authorized to read {url_str} - skipping"
                ));
            }
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(e),
        }

        if arg_matches == 0 {
            ctx.info(&no_urls_matched_target(url_str));
            found_nonmatching_arg = true;
        }
    }

    Ok(if found_nonmatching_arg { 1 } else { 0 })
}
