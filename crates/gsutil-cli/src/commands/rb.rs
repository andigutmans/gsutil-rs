//! `gsutil rb` (`deletebucket`, `removebucket`, `removebuckets`, `rmdir`) command.

use gsutil_core::error::{no_urls_matched_target, GsutilError, Result, ServiceErrorKind};
use gsutil_core::url::StorageUrl;

use crate::context::CommandContext;
use crate::dispatch::{CommandSpec, NO_MAX};
use crate::getopt::OptPair;
use crate::wildcard_iter::iter_buckets;

pub const SYNOPSIS: &str = "\n  gsutil rb [-f] gs://<bucket_name>...\n";

pub const HELP_TEXT: &str = r#"<B>SYNOPSIS</B>

  gsutil rb [-f] gs://<bucket_name>...


<B>DESCRIPTION</B>
  Delete one or more buckets. Buckets must be empty before you can delete them.

<B>OPTIONS</B>
  -f          Continues silently (without printing error messages) despite
              errors when removing buckets. If some buckets couldn't be removed,
              gsutil's exit status will be non-zero even if this flag is set.
"#;

pub const SPEC: CommandSpec = CommandSpec {
    name: "rb",
    aliases: &["deletebucket", "removebucket", "removebuckets", "rmdir"],
    help_aliases: &["deletebucket", "removebucket", "removebuckets", "rmdir"],
    one_line_summary: "Remove buckets",
    usage_synopsis: SYNOPSIS,
    help_text: HELP_TEXT,
    subcommands: &[],
    min_args: 1,
    max_args: NO_MAX,
    supported_sub_args: "f",
    supported_private_args: &[],
    file_url_ok: false,
    provider_url_ok: false,
    urls_start_arg: 0,
    has_subcommands_and_subopts: false,
};

pub async fn run(ctx: &mut CommandContext, sub_opts: &[OptPair], args: &[String]) -> Result<i32> {
    let continue_on_error = sub_opts.iter().any(|(o, _)| o == "-f");
    let api = ctx.api().await?;
    let project_id = ctx.effective_project_id(None).map(ToString::to_string);
    let id_fields = vec!["id".to_string()];

    let mut did_some_work = false;
    let mut some_failed = false;

    for url_str in args {
        let wildcard_url = StorageUrl::parse(url_str)?;
        if wildcard_url.is_object() {
            return Err(GsutilError::command(
                "\"rb\" command requires a provider or bucket URL",
            ));
        }

        let blrs = match iter_buckets(
            api.as_ref(),
            url_str,
            project_id.as_deref(),
            Some(&id_fields),
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                some_failed = true;
                if continue_on_error {
                    continue;
                }
                return Err(e);
            }
        };

        for blr in blrs {
            let url = blr.url();
            let bucket_name = url.bucket_name().unwrap_or("");
            ctx.info(&format!("Removing {url}..."));
            match api.delete_bucket(bucket_name, None).await {
                Ok(()) => {
                    did_some_work = true;
                }
                Err(GsutilError::Service(se)) if se.kind == ServiceErrorKind::NotEmpty => {
                    some_failed = true;
                    if continue_on_error {
                        continue;
                    }
                    if se.reason.contains("VersionedBucketNotEmpty") {
                        return Err(GsutilError::command(format!(
                            "Bucket is not empty. Note: this is a versioned bucket, so to delete all objects\nyou need to use:\n\tgsutil rm -r {url}"
                        )));
                    }
                    return Err(GsutilError::Service(se));
                }
                Err(e) => {
                    some_failed = true;
                    if !continue_on_error {
                        return Err(e);
                    }
                }
            }
        }
    }

    if !did_some_work {
        let formatted_args = args
            .iter()
            .map(|a| format!("'{a}'"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(GsutilError::command(no_urls_matched_target(&format!(
            "[{formatted_args}]"
        ))));
    }

    Ok(if some_failed { 1 } else { 0 })
}
