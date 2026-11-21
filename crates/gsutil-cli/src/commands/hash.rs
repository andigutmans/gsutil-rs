//! `gsutil hash` command (local files and cloud objects, `-c`, `-m`, `-h`).

use std::fs::File;

use gsutil_core::api::BucketListingRef;
use gsutil_core::error::{GsutilError, Result};
use gsutil_core::hash::{base64_to_hex_hash, hash_reader};
use gsutil_core::url::StorageUrl;

use crate::context::CommandContext;
use crate::dispatch::{CommandSpec, NO_MAX};
use crate::getopt::OptPair;
use crate::wildcard_iter::{expand_local_files, iter_objects};

pub const SYNOPSIS: &str = "\n  gsutil hash [-c] [-h] [-m] filename...\n";

pub const HELP_TEXT: &str = r#"<B>SYNOPSIS</B>

  gsutil hash [-c] [-h] [-m] filename...


<B>DESCRIPTION</B>
  Calculate hashes on local files, which can be used to compare with
  ``gsutil ls -L`` output. If a specific hash option is not provided, this
  command calculates all gsutil-supported hashes for the files.

<B>OPTIONS</B>
  -c          Calculate a CRC32c hash for the specified files.

  -h          Output hashes in hex format. By default, gsutil uses base64.

  -m          Calculate a MD5 hash for the specified files.
"#;

pub const SPEC: CommandSpec = CommandSpec {
    name: "hash",
    aliases: &[],
    help_aliases: &["checksum"],
    one_line_summary: "Calculate file hashes",
    usage_synopsis: SYNOPSIS,
    help_text: HELP_TEXT,
    subcommands: &[],
    min_args: 1,
    max_args: NO_MAX,
    supported_sub_args: "chm",
    supported_private_args: &[],
    file_url_ok: true,
    provider_url_ok: false,
    urls_start_arg: 0,
    has_subcommands_and_subopts: false,
};

pub async fn run(ctx: &mut CommandContext, sub_opts: &[OptPair], args: &[String]) -> Result<i32> {
    let mut calc_crc32c = false;
    let mut calc_md5 = false;
    let mut hex_output = false;
    let mut found_hash_opt = false;

    for (o, _) in sub_opts {
        match o.as_str() {
            "-c" => {
                calc_crc32c = true;
                found_hash_opt = true;
            }
            "-m" => {
                calc_md5 = true;
                found_hash_opt = true;
            }
            "-h" => {
                hex_output = true;
            }
            _ => {}
        }
    }

    if !found_hash_opt {
        calc_crc32c = true;
        calc_md5 = true;
    }

    let output_format = if hex_output { "hex" } else { "base64" };
    let mut matched_one = false;

    for url_str in args {
        let url = StorageUrl::parse(url_str)?;
        if url.is_file_url() {
            let files = expand_local_files(url_str)?;
            for path in files {
                matched_one = true;
                let mut file = File::open(&path)?;
                let hashes = hash_reader(&mut file, calc_crc32c, calc_md5)?;
                ctx.println(&format!("Hashes [{output_format}] for {}:", path.display()))?;
                if calc_crc32c {
                    let val = if hex_output {
                        // Python crcmod.Crc.hexdigest() returns UPPERCASE hex.
                        hashes.crc32c_hex().unwrap_or_default().to_ascii_uppercase()
                    } else {
                        hashes.crc32c_base64().unwrap_or_default()
                    };
                    ctx.println(&format!("\tHash (crc32c):\t\t{val}"))?;
                }
                if calc_md5 {
                    let val = if hex_output {
                        hashes.md5_hex().unwrap_or_default()
                    } else {
                        hashes.md5_base64().unwrap_or_default()
                    };
                    ctx.println(&format!("\tHash (md5):\t\t{val}"))?;
                }
            }
        } else {
            let api = ctx.api().await?;
            let fields = vec![
                "crc32c".to_string(),
                "customerEncryption".to_string(),
                "md5Hash".to_string(),
                "size".to_string(),
                "name".to_string(),
            ];
            let objs = iter_objects(
                api.as_ref(),
                url_str,
                ctx.effective_project_id(None),
                false,
                Some(&fields),
            )
            .await?;

            for blr in objs {
                if let BucketListingRef::Object {
                    url: obj_url,
                    metadata: Some(meta),
                } = blr
                {
                    matched_one = true;
                    let obj_name = obj_url.object_name().unwrap_or("");
                    let show_md5 = calc_md5 && meta.md5_hash.is_some();
                    let show_crc = calc_crc32c && meta.crc32c.is_some();
                    if !show_md5 && !show_crc {
                        ctx.warn(&format!("No hashes present for {url_str}"));
                        continue;
                    }
                    ctx.println(&format!("Hashes [{output_format}] for {obj_name}:"))?;
                    if show_md5 {
                        if let Some(ref md5) = meta.md5_hash {
                            let val = if hex_output {
                                base64_to_hex_hash(md5)?
                            } else {
                                md5.clone()
                            };
                            ctx.println(&format!("\tHash (md5):\t\t{val}"))?;
                        }
                    }
                    if show_crc {
                        if let Some(ref crc) = meta.crc32c {
                            let val = if hex_output {
                                base64_to_hex_hash(crc)?
                            } else {
                                crc.clone()
                            };
                            ctx.println(&format!("\tHash (crc32c):\t\t{val}"))?;
                        }
                    }
                }
            }
        }
    }

    if !matched_one {
        return Err(GsutilError::command("No files matched"));
    }

    Ok(0)
}
