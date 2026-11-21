//! `gsutil cat` command (`-h`, `-r range`).

use std::io::{self, Read};

use futures::StreamExt;
use regex::Regex;

use gsutil_core::api::{BucketListingRef, DownloadOptions};
use gsutil_core::error::{no_urls_matched_target, GsutilError, Result};
use gsutil_core::url::StorageUrl;

use crate::context::CommandContext;
use crate::dispatch::{CommandSpec, NO_MAX};
use crate::getopt::OptPair;
use crate::wildcard_iter::iter_objects;

pub const SYNOPSIS: &str = "\n  gsutil cat [-h] url...\n";

pub const HELP_TEXT: &str = r#"<B>SYNOPSIS</B>

  gsutil cat [-h] url...


<B>DESCRIPTION</B>
  The cat command outputs the contents of one or more URLs to stdout.

<B>OPTIONS</B>
  -h          Prints short header for each object.

  -r range    Causes gsutil to output just the specified byte range of the
              object (start-end, start-, or -numbytes).
"#;

pub const SPEC: CommandSpec = CommandSpec {
    name: "cat",
    aliases: &[],
    help_aliases: &[],
    one_line_summary: "Concatenate object content to stdout",
    usage_synopsis: SYNOPSIS,
    help_text: HELP_TEXT,
    subcommands: &[],
    min_args: 1,
    max_args: NO_MAX,
    supported_sub_args: "hr:",
    supported_private_args: &[],
    file_url_ok: false,
    provider_url_ok: false,
    urls_start_arg: 0,
    has_subcommands_and_subopts: false,
};

fn parse_range(raw: &str) -> Result<(Option<i64>, Option<u64>)> {
    let trimmed = raw.trim();
    if trimmed == "-" {
        return Ok((Some(0), None));
    }
    let re = Regex::new(r"^(?:(?P<start>[0-9]+)-(?P<end>[0-9]*)|(?P<endslice>-[0-9]+))$")
        .expect("valid regex");
    let Some(caps) = re.captures(trimmed) else {
        return Err(GsutilError::command(format!("Invalid range ({trimmed})")));
    };
    if let Some(es) = caps.name("endslice") {
        let val: i64 = es
            .as_str()
            .parse()
            .map_err(|_| GsutilError::command(format!("Invalid range ({trimmed})")))?;
        return Ok((Some(val), None));
    }
    let start: i64 = caps
        .name("start")
        .map(|m| m.as_str().parse())
        .transpose()
        .map_err(|_| GsutilError::command(format!("Invalid range ({trimmed})")))?
        .unwrap_or(0);
    let end: Option<u64> = match caps.name("end") {
        Some(m) if !m.as_str().is_empty() => Some(
            m.as_str()
                .parse()
                .map_err(|_| GsutilError::command(format!("Invalid range ({trimmed})")))?,
        ),
        _ => None,
    };
    Ok((Some(start), end))
}

pub async fn run(ctx: &mut CommandContext, sub_opts: &[OptPair], args: &[String]) -> Result<i32> {
    let mut show_header = false;
    let mut start_byte: Option<i64> = Some(0);
    let mut end_byte: Option<u64> = None;

    for (o, a) in sub_opts {
        match o.as_str() {
            "-h" => show_header = true,
            "-r" => {
                let (s, e) = parse_range(a)?;
                start_byte = s;
                end_byte = e;
            }
            _ => return Err(SPEC.raise_invalid_argument()),
        }
    }

    if args.first().map(String::as_str) == Some("-")
        || args.first().map(String::as_str) == Some("file://-")
    {
        let mut stdin = io::stdin().lock();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = stdin.read(&mut buf)?;
            if n == 0 {
                break;
            }
            ctx.write_stdout(&buf[..n])?;
        }
        ctx.flush_stdout()?;
        return Ok(0);
    }

    let api = ctx.api().await?;
    let project_id = ctx.effective_project_id(None).map(ToString::to_string);
    let mut printed_one = false;

    for url_str in args {
        let mut did_some_work = false;
        let parsed = StorageUrl::parse(url_str)?;
        let items = if parsed.is_object() && !gsutil_core::url::contains_wildcard(url_str) {
            let bucket = parsed.bucket_name().unwrap_or("");
            let obj_name = parsed.object_name().unwrap_or("");
            let provider_api = api.for_provider(parsed.scheme())?;
            match provider_api
                .get_object_metadata(bucket, obj_name, parsed.generation(), None)
                .await
            {
                Ok(meta) => vec![BucketListingRef::Object {
                    url: parsed,
                    metadata: Some(Box::new(meta)),
                }],
                Err(e) if e.is_not_found() => Vec::new(),
                Err(e) => return Err(e),
            }
        } else {
            iter_objects(api.as_ref(), url_str, project_id.as_deref(), false, None).await?
        };

        for blr in items {
            if let BucketListingRef::Object {
                url: obj_url,
                metadata,
            } = blr
            {
                did_some_work = true;
                if show_header {
                    if printed_one {
                        ctx.error("");
                    }
                    ctx.error(&format!("==> {obj_url} <=="));
                    printed_one = true;
                }

                // Match CatHelper: if 0 < size <= start_byte, output nothing for this object
                // and continue to any remaining objects.
                if let (Some(meta), Some(sb)) = (&metadata, start_byte) {
                    let obj_size = meta.size_bytes();
                    if obj_size > 0 && sb >= 0 && (sb as u64) >= obj_size {
                        continue;
                    }
                }

                let storage_url = StorageUrl::parse(&obj_url.url_string())?;
                let bucket = storage_url.bucket_name().unwrap_or("");
                let name = storage_url.object_name().unwrap_or("");
                let compressed = metadata
                    .as_ref()
                    .and_then(|m| m.content_encoding.as_deref())
                    .is_some_and(|e| e.eq_ignore_ascii_case("gzip"));

                let decryption_key = if let Some(sha) = metadata
                    .as_ref()
                    .and_then(|m| m.customer_encryption.as_ref())
                    .and_then(|ce| ce.key_sha256.as_deref())
                {
                    let found = crate::encryption::find_matching_csek(&ctx.config, sha)?;
                    if found.is_none() {
                        return Err(GsutilError::Encryption(format!(
                            "Missing decryption key with SHA256 hash {sha}. No decryption key matches object {obj_url}"
                        )));
                    }
                    found
                } else {
                    crate::encryption::primary_decryption_key(&ctx.config)?
                };

                let opts = DownloadOptions {
                    generation: storage_url.generation().map(ToString::to_string),
                    start_byte: if start_byte == Some(0) && end_byte.is_none() {
                        None
                    } else {
                        start_byte
                    },
                    end_byte,
                    compressed_encoding: compressed,
                    decryption_key,
                    ..Default::default()
                };

                let provider_api = api.for_provider(storage_url.scheme())?;
                let mut stream = provider_api
                    .get_object_media_stream(bucket, name, &opts)
                    .await?;
                while let Some(chunk_res) = stream.next().await {
                    let chunk = chunk_res.map_err(|e| {
                        if e.kind() == io::ErrorKind::BrokenPipe {
                            GsutilError::BrokenPipe
                        } else {
                            GsutilError::Io(e)
                        }
                    })?;
                    ctx.write_stdout(&chunk)?;
                }
                ctx.flush_stdout()?;
            }
        }

        if !did_some_work {
            return Err(GsutilError::command(no_urls_matched_target(url_str)));
        }
    }

    Ok(0)
}
