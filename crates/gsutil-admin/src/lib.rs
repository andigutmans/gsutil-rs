//! Admin & security command handlers for `gsutil-rs`.
//!
//! Implements all 21 admin and security commands against `gsutil_core::api::CloudApi`:
//! - Bucket config: `versioning`, `cors`, `lifecycle`, `logging`, `web`, `label`,
//!   `requesterpays`, `defstorageclass`, `ubla`, `bucketpolicyonly`, `pap`, `rpo`,
//!   `autoclass`, `retention`.
//! - Security & messaging: `acl`, `defacl`, `iam`, `kms`, `hmac`, `notification`, `signurl`.

pub mod acl;
pub mod bucket_config;
pub mod iam;
pub mod kms_hmac_notif;
pub mod signurl;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::io::Write;

use gsutil_core::api::{CloudApi, CsObjectOrPrefix, KmsApi, ListObjectsOptions, PubsubApi};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{no_urls_matched_target, GsutilError, Result};
use gsutil_core::url::{contains_wildcard, CloudUrl, StorageUrl};
use gsutil_core::wildcard::{build_bucket_filter_strings, WildcardMatcher};

pub const SECONDS_IN_DAY: u64 = 24 * 60 * 60;
pub const SECONDS_IN_MONTH: u64 = 31 * SECONDS_IN_DAY; // 2,678,400s (retention_util.py)
pub const SECONDS_IN_YEAR: u64 = 31_557_600; // int(365.25 * 86400)

/// Shared execution context passed to admin command handlers.
pub struct AdminContext<'a> {
    pub api: &'a dyn CloudApi,
    pub config: &'a BotoConfig,
    pub project_id: Option<String>,
    pub parallel_operations: bool,
    pub quiet: bool,
    pub debug_level: u8,
    pub headers: BTreeMap<String, String>,
    pub kms_api: Option<&'a dyn KmsApi>,
    pub pubsub_api: Option<&'a dyn PubsubApi>,
    /// Optional interactive confirmation override for tests (returns `true` to proceed).
    /// When `None`, prompts on stdin/stderr matching Python `retention_util._ConfirmWithUserPrompt`.
    pub confirm_fn: Option<&'a dyn Fn(&str) -> bool>,
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

impl<'a> AdminContext<'a> {
    pub fn effective_project_id(&self) -> Option<&str> {
        self.project_id
            .as_deref()
            .or_else(|| self.config.default_project_id())
    }

    /// Write an informational status line to `stderr` unless `-q` (`quiet`) is set.
    pub fn info(&mut self, msg: &str) -> Result<()> {
        if !self.quiet {
            writeln!(self.err, "{msg}")?;
        }
        Ok(())
    }

    /// Emit Python gsutil's `-m` seek-ahead estimation line when `-m` is active
    /// and `task_estimation_force` is true or `count >= task_estimation_threshold`.
    pub(crate) fn maybe_report_seek_ahead(&mut self, count: usize) -> Result<()> {
        if !self.parallel_operations || count == 0 {
            return Ok(());
        }
        let force = self
            .config
            .get_bool("GSUtil", "task_estimation_force", false);
        let threshold =
            self.config
                .get_u64("GSUtil", "task_estimation_threshold", 50_000) as usize;
        if threshold > 0 && (force || count >= threshold) {
            writeln!(
                self.err,
                "Estimated work for this command: objects: {count}"
            )?;
        }
        Ok(())
    }

    /// Prompt the user for `[y|N]` confirmation (default `false`).
    pub fn confirm(&mut self, question: &str) -> Result<bool> {
        if let Some(cb) = self.confirm_fn {
            return Ok(cb(question));
        }
        let prompt = format!("{question} [y|N]: ");
        loop {
            write!(self.err, "{prompt}")?;
            self.err.flush()?;
            let mut line = String::new();
            let n = std::io::stdin().read_line(&mut line)?;
            if n == 0 {
                return Ok(false);
            }
            match line.trim().to_ascii_lowercase().as_str() {
                "" | "n" | "no" => return Ok(false),
                "y" | "yes" => return Ok(true),
                _ => {
                    writeln!(self.err, "\tPlease respond with 'yes'/'y' or 'no'/'n'.")?;
                }
            }
        }
    }
}

/// Returns `true` if `cmd` is one of the 21 admin/security commands handled by `gsutil-admin`.
pub fn is_admin_command(cmd: &str) -> bool {
    matches!(
        cmd,
        "versioning"
            | "cors"
            | "lifecycle"
            | "logging"
            | "web"
            | "label"
            | "requesterpays"
            | "defstorageclass"
            | "ubla"
            | "bucketpolicyonly"
            | "pap"
            | "rpo"
            | "autoclass"
            | "retention"
            | "acl"
            | "defacl"
            | "iam"
            | "kms"
            | "hmac"
            | "notification"
            | "signurl"
    )
}

/// Dispatch an admin/security command by canonical command name.
/// Returns `None` if `cmd` is not an admin command.
pub async fn dispatch_admin_command(
    cmd: &str,
    ctx: &mut AdminContext<'_>,
    args: &[String],
) -> Option<Result<()>> {
    match cmd {
        "versioning" => Some(bucket_config::run_versioning(ctx, args).await),
        "cors" => Some(bucket_config::run_cors(ctx, args).await),
        "lifecycle" => Some(bucket_config::run_lifecycle(ctx, args).await),
        "logging" => Some(bucket_config::run_logging(ctx, args).await),
        "web" => Some(bucket_config::run_web(ctx, args).await),
        "label" => Some(bucket_config::run_label(ctx, args).await),
        "requesterpays" => Some(bucket_config::run_requesterpays(ctx, args).await),
        "defstorageclass" => Some(bucket_config::run_defstorageclass(ctx, args).await),
        "ubla" => Some(bucket_config::run_ubla(ctx, args, false).await),
        "bucketpolicyonly" => Some(bucket_config::run_ubla(ctx, args, true).await),
        "pap" => Some(bucket_config::run_pap(ctx, args).await),
        "rpo" => Some(bucket_config::run_rpo(ctx, args).await),
        "autoclass" => Some(bucket_config::run_autoclass(ctx, args).await),
        "retention" => Some(bucket_config::run_retention(ctx, args).await),
        "acl" => Some(acl::run_acl(ctx, args).await),
        "defacl" => Some(acl::run_defacl(ctx, args).await),
        "iam" => Some(iam::run_iam(ctx, args).await),
        "kms" => Some(kms_hmac_notif::run_kms(ctx, args).await),
        "hmac" => Some(kms_hmac_notif::run_hmac(ctx, args).await),
        "notification" => Some(kms_hmac_notif::run_notification(ctx, args).await),
        "signurl" => Some(signurl::run_signurl(ctx, args).await),
        _ => None,
    }
}

/// Validate `"on"` or `"off"` (case-insensitive) matching `text_util.InsistOnOrOff`.
pub(crate) fn insist_on_or_off(val: &str, msg: &str) -> Result<bool> {
    match val.to_ascii_lowercase().as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(GsutilError::command(msg)),
    }
}

/// Expand one or more bucket URL arguments (supporting bucket wildcards like `gs://bkt-*`).
pub(crate) async fn expand_bucket_urls(
    ctx: &AdminContext<'_>,
    url_args: &[String],
    cmd_name: &str,
) -> Result<Vec<CloudUrl>> {
    if url_args.is_empty() {
        return Err(GsutilError::command(format!(
            "The {cmd_name} command requires at least one bucket URL."
        )));
    }
    let mut results = Vec::new();
    for raw in url_args {
        let url = StorageUrl::parse(raw)?;
        let cloud = match url {
            StorageUrl::Cloud(c) if c.is_bucket() => c,
            StorageUrl::Cloud(c) if c.is_provider() => {
                return Err(GsutilError::command(format!(
                    "The {cmd_name} command does not support provider-only URLs: {raw}"
                )));
            }
            _ => {
                return Err(GsutilError::command(format!(
                    "The {cmd_name} command must specify a bucket URL (e.g. gs://bucket), got: {raw}"
                )));
            }
        };
        let bname = cloud.bucket_name.as_deref().unwrap_or("");
        if contains_wildcard(bname) {
            let matcher = WildcardMatcher::compile(bname)?;
            let api = ctx.api.for_provider(cloud.scheme.as_str())?;
            let buckets = api.list_buckets(ctx.effective_project_id(), None).await?;
            for b in buckets {
                let name = b.name.or(b.id).unwrap_or_default();
                if matcher.is_match(&name) {
                    results.push(CloudUrl {
                        scheme: cloud.scheme,
                        bucket_name: Some(name),
                        object_name: None,
                        generation: None,
                    });
                }
            }
        } else {
            results.push(cloud);
        }
    }
    if results.is_empty() {
        return Err(GsutilError::command(no_urls_matched_target(
            &url_args.join(", "),
        )));
    }
    Ok(results)
}

/// Expand cloud URLs (buckets or objects, with optional wildcards / recursion).
pub(crate) async fn expand_cloud_urls(
    ctx: &AdminContext<'_>,
    url_args: &[String],
    recursive: bool,
    all_versions: bool,
) -> Result<Vec<CloudUrl>> {
    if url_args.is_empty() {
        return Err(GsutilError::command("Expected at least one URL argument."));
    }
    let mut results = Vec::new();
    for raw in url_args {
        let url = StorageUrl::parse(raw)?;
        let cloud = match url {
            StorageUrl::Cloud(c) if !c.is_provider() => c,
            _ => {
                return Err(GsutilError::command(format!(
                    "Expected a cloud bucket or object URL, got: {raw}"
                )));
            }
        };
        let api = ctx.api.for_provider(cloud.scheme.as_str())?;

        if cloud.is_bucket() {
            let bname = cloud.bucket_name.as_deref().unwrap_or("");
            let matched_buckets = if contains_wildcard(bname) {
                let matcher = WildcardMatcher::compile(bname)?;
                api.list_buckets(ctx.effective_project_id(), None)
                    .await?
                    .into_iter()
                    .filter_map(|b| {
                        let name = b.name.or(b.id)?;
                        matcher.is_match(&name).then_some(name)
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![bname.to_string()]
            };

            for b in matched_buckets {
                if recursive {
                    let listed = api
                        .list_objects(
                            &b,
                            &ListObjectsOptions {
                                prefix: None,
                                delimiter: None,
                                all_versions,
                                fields: None,
                            },
                        )
                        .await?;
                    for item in listed {
                        if let CsObjectOrPrefix::Object(obj) = item {
                            if let Some(name) = obj.name {
                                results.push(CloudUrl {
                                    scheme: cloud.scheme,
                                    bucket_name: Some(b.clone()),
                                    object_name: Some(name),
                                    generation: if all_versions { obj.generation } else { None },
                                });
                            }
                        }
                    }
                } else {
                    results.push(CloudUrl {
                        scheme: cloud.scheme,
                        bucket_name: Some(b),
                        object_name: None,
                        generation: None,
                    });
                }
            }
        } else {
            // Object URL (possibly with wildcard or recursive prefix)
            let bname = cloud.bucket_name.as_deref().unwrap_or("");
            let oname = cloud.object_name.as_deref().unwrap_or("");
            if contains_wildcard(oname) || recursive {
                let pattern = if recursive && !contains_wildcard(oname) {
                    format!("{}/**", oname.trim_end_matches('/'))
                } else {
                    oname.to_string()
                };
                let filter = build_bucket_filter_strings(&pattern);
                let matcher = WildcardMatcher::compile(&filter.prefix_wildcard)?;
                let listed = api
                    .list_objects(
                        bname,
                        &ListObjectsOptions {
                            prefix: filter.prefix,
                            delimiter: filter.delimiter,
                            all_versions,
                            fields: None,
                        },
                    )
                    .await?;
                for item in listed {
                    if let CsObjectOrPrefix::Object(obj) = item {
                        if let Some(name) = obj.name {
                            if matcher.is_match(&name) {
                                results.push(CloudUrl {
                                    scheme: cloud.scheme,
                                    bucket_name: Some(bname.to_string()),
                                    object_name: Some(name),
                                    generation: if all_versions { obj.generation } else { None },
                                });
                            }
                        }
                    }
                }
            } else {
                results.push(cloud);
            }
        }
    }

    if results.is_empty() {
        return Err(GsutilError::command(no_urls_matched_target(
            &url_args.join(", "),
        )));
    }
    Ok(results)
}

/// Format a bucket URL without trailing slash (matching Python `str(bucket_url).rstrip('/')`).
pub(crate) fn bucket_display_no_slash(url: &CloudUrl) -> String {
    format!(
        "{}://{}",
        url.scheme,
        url.bucket_name.as_deref().unwrap_or("")
    )
}

/// Read a JSON file path or `"-"` (stdin) into a String.
pub(crate) fn read_json_arg(path: &str) -> Result<String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                GsutilError::command(format!(
                    "Could not find the file \"{path}\". No such file or directory"
                ))
            } else {
                GsutilError::command(format!("Could not read file \"{path}\": {e}"))
            }
        })
    }
}

/// Parse a `signurl -d` duration string like `"10s"`, `"5m"`, `"2h"`, `"7d"` into seconds.
pub fn parse_duration_secs(s: &str) -> Result<u64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(GsutilError::command(format!("Invalid duration: \"{s}\"")));
    }
    let last = trimmed.chars().last().unwrap();
    let (num_str, mult) = match last {
        's' | 'S' => (&trimmed[..trimmed.len() - 1], 1u64),
        'm' | 'M' => (&trimmed[..trimmed.len() - 1], 60u64),
        'h' | 'H' => (&trimmed[..trimmed.len() - 1], 3600u64),
        'd' | 'D' => (&trimmed[..trimmed.len() - 1], SECONDS_IN_DAY),
        'y' | 'Y' => (&trimmed[..trimmed.len() - 1], SECONDS_IN_YEAR),
        c if c.is_ascii_digit() => (trimmed, 1u64),
        _ => {
            return Err(GsutilError::command(format!(
                "Invalid duration \"{s}\": expected integer with optional s/m/h/d/y suffix."
            )));
        }
    };
    let n: u64 = num_str.parse().map_err(|_| {
        GsutilError::command(format!(
            "Invalid duration \"{s}\": expected positive integer."
        ))
    })?;
    n.checked_mul(mult)
        .ok_or_else(|| GsutilError::command(format!("Duration overflow: \"{s}\"")))
}

/// Parse a GCS Retention Policy duration matching `gslib/utils/retention_util.py`:
/// - `<N>s`: seconds (`N * 1`)
/// - `<N>d`: days (`N * 86,400`)
/// - `<N>m`: months (`N * 31 * 86,400 = 2,678,400`)
/// - `<N>y`: years (`N * 31,557,600`)
///
/// Hours (`h`) and bare numbers are explicitly rejected!
pub fn parse_retention_duration_secs(s: &str) -> Result<u64> {
    let trimmed = s.trim();
    if trimmed.len() < 2 {
        return Err(GsutilError::command(format!(
            "Incorrect retention period specified: {s}"
        )));
    }
    let last = trimmed.chars().last().unwrap();
    let num_str = &trimmed[..trimmed.len() - 1];
    let mult = match last {
        's' | 'S' => 1u64,
        'd' | 'D' => SECONDS_IN_DAY,
        'm' | 'M' => SECONDS_IN_MONTH,
        'y' | 'Y' => SECONDS_IN_YEAR,
        _ => {
            return Err(GsutilError::command(format!(
                "Incorrect retention period specified: {s}"
            )));
        }
    };
    if num_str.is_empty() || !num_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(GsutilError::command(format!(
            "Incorrect retention period specified: {s}"
        )));
    }
    let n: u64 = num_str
        .parse()
        .map_err(|_| GsutilError::command(format!("Incorrect retention period specified: {s}")))?;
    if n == 0 {
        return Err(GsutilError::command(format!(
            "Incorrect retention period specified: {s}"
        )));
    }
    n.checked_mul(mult)
        .ok_or_else(|| GsutilError::command(format!("Retention period overflow: {s}")))
}

/// Normalize GCS storage class shorthand aliases matching `gslib/utils/text_util.py`.
pub fn normalize_storage_class(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "std" | "standard" => "STANDARD".to_string(),
        "nl" | "nearline" => "NEARLINE".to_string(),
        "cl" | "coldline" => "COLDLINE".to_string(),
        "ar" | "archive" => "ARCHIVE".to_string(),
        "dra" | "durable_reduced_availability" => "DURABLE_REDUCED_AVAILABILITY".to_string(),
        "mr" | "multi_regional" => "MULTI_REGIONAL".to_string(),
        "r" | "regional" => "REGIONAL".to_string(),
        _ => raw.trim().to_ascii_uppercase(),
    }
}
