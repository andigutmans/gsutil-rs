//! `gsutil mb` (`makebucket`, `createbucket`, `md`, `mkdir`) command.

use regex::Regex;

use gsutil_core::api::{
    Bucket, BucketAutoclass, BucketCustomPlacementConfig, BucketEncryption, BucketIamConfiguration,
    BucketRetentionPolicy, UniformBucketLevelAccess,
};
use gsutil_core::error::{GsutilError, Result, ServiceErrorKind};
use gsutil_core::url::StorageUrl;

use crate::context::{insist_ascii, insist_on_or_off, CommandContext};
use crate::dispatch::{CommandSpec, NO_MAX};
use crate::getopt::OptPair;

pub const SYNOPSIS: &str = "\n  gsutil mb [-b (on|off)] [-c <class>] [-k <key>] [-l <location>] [-p <project>]\n            [--autoclass] [--retention <time>] [--pap <setting>]\n            [--placement <region1>,<region2>]\n            [--rpo ASYNC_TURBO|DEFAULT] gs://<bucket_name>...\n";

pub const HELP_TEXT: &str = r#"<B>SYNOPSIS</B>

  gsutil mb [-b (on|off)] [-c <class>] [-k <key>] [-l <location>] [-p <project>]
            [--autoclass] [--retention <time>] [--pap <setting>]
            [--placement <region1>,<region2>]
            [--rpo ASYNC_TURBO|DEFAULT] gs://<bucket_name>...


<B>DESCRIPTION</B>
  Create one or more new buckets.

<B>OPTIONS</B>
  --autoclass            Enables the Autoclass feature.
  -b <on|off>            Specifies the uniform bucket-level access setting.
  -c class               Specifies the default storage class.
  -k <key>               Set the default KMS key.
  -l location            Specifies the bucket location (default: US).
  -p project             Specifies the project ID or number.
  -s class               Same as -c.
  --retention time       Specifies the retention policy (e.g., 30d, 1y).
  --pap setting          Specifies public access prevention (enforced|inherited).
  --placement reg1,reg2  Two regions forming a custom dual-region.
  --rpo setting          Specifies replication setting (ASYNC_TURBO|DEFAULT).
"#;

pub const SPEC: CommandSpec = CommandSpec {
    name: "mb",
    aliases: &["makebucket", "createbucket", "md", "mkdir"],
    help_aliases: &[
        "createbucket",
        "makebucket",
        "md",
        "mkdir",
        "location",
        "dra",
        "dras",
        "reduced_availability",
        "durable_reduced_availability",
        "rr",
        "reduced_redundancy",
        "standard",
        "storage class",
        "nearline",
        "nl",
    ],
    one_line_summary: "Make buckets",
    usage_synopsis: SYNOPSIS,
    help_text: HELP_TEXT,
    subcommands: &[],
    min_args: 1,
    max_args: NO_MAX,
    supported_sub_args: "b:c:l:p:s:k:",
    supported_private_args: &["autoclass", "retention=", "pap=", "placement=", "rpo="],
    file_url_ok: false,
    provider_url_ok: false,
    urls_start_arg: 0,
    has_subcommands_and_subopts: false,
};

fn normalize_storage_class(sc: &str) -> String {
    match sc.to_ascii_lowercase().as_str() {
        "standard" | "std" => "STANDARD".to_string(),
        "nearline" | "nl" => "NEARLINE".to_string(),
        "coldline" | "cl" => "COLDLINE".to_string(),
        "archive" | "ar" => "ARCHIVE".to_string(),
        "multi_regional" | "multi-regional" | "mra" => "MULTI_REGIONAL".to_string(),
        "regional" | "reg" => "REGIONAL".to_string(),
        "dra" | "durable_reduced_availability" => "DURABLE_REDUCED_AVAILABILITY".to_string(),
        other => other.to_ascii_uppercase(),
    }
}

/// Parse retention duration strings like `"10s"`, `"30d"`, `"6m"`, `"1y"` into seconds.
fn parse_retention_seconds(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if trimmed.len() < 2 {
        return Err(GsutilError::command(format!(
            "Incorrect retention period specified: {raw}"
        )));
    }
    let (num_str, unit) = trimmed.split_at(trimmed.len() - 1);
    let num: u64 = num_str.parse().map_err(|_| {
        GsutilError::command(format!("Incorrect retention period specified: {raw}"))
    })?;
    let mult: u64 = match unit.to_ascii_lowercase().as_str() {
        "s" => 1,
        "d" => 86_400,
        "m" => 2_678_400,  // 31 days (matches gslib/utils/retention_util.py)
        "y" => 31_557_600, // 365.25 days (matches gslib/utils/retention_util.py)
        _ => {
            return Err(GsutilError::command(format!(
                "Incorrect retention period specified: {raw}"
            )));
        }
    };
    num.checked_mul(mult)
        .ok_or_else(|| GsutilError::command(format!("Retention period overflow: {raw}")))
}

fn validate_cmek(key: &str) -> Result<()> {
    let re = Regex::new(r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$")
        .expect("valid regex");
    if !re.is_match(key) {
        return Err(GsutilError::command(format!(
            "Invalid KMS key name: {key}.\nKMS keys should follow the format \"projects/<project-id>/locations/<location>/keyRings/<keyring>/cryptoKeys/<key>\""
        )));
    }
    Ok(())
}

fn validate_bucket_name(name: &str) -> Result<()> {
    let bucket_re =
        Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9\._-]{1,253}[a-zA-Z0-9]$").expect("valid regex");
    let too_long_comp = Regex::new(r"[-_a-z0-9]{64}").expect("valid regex");
    if !bucket_re.is_match(name) || too_long_comp.is_match(name) {
        return Err(GsutilError::invalid_url(format!(
            "Invalid bucket name in URL \"{name}\""
        )));
    }
    Ok(())
}

pub async fn run(ctx: &mut CommandContext, sub_opts: &[OptPair], args: &[String]) -> Result<i32> {
    let mut autoclass = false;
    let mut bucket_policy_only: Option<bool> = None;
    let mut kms_key: Option<String> = None;
    let mut location: Option<String> = None;
    let mut storage_class: Option<String> = None;
    let mut project_id: Option<String> = None;
    let mut retention_secs: Option<u64> = None;
    let mut placements: Option<Vec<String>> = None;
    let mut pap: Option<String> = None;
    let mut rpo: Option<String> = None;

    for (o, a) in sub_opts {
        match o.as_str() {
            "--autoclass" => autoclass = true,
            "-k" => {
                validate_cmek(a)?;
                kms_key = Some(a.clone());
            }
            "-l" => location = Some(a.clone()),
            "-p" => {
                insist_ascii(a, "Invalid non-ASCII character found in project ID")?;
                project_id = Some(a.clone());
            }
            "-c" | "-s" => storage_class = Some(normalize_storage_class(a)),
            "--retention" => retention_secs = Some(parse_retention_seconds(a)?),
            "--rpo" => {
                let trimmed = a.trim();
                if trimmed != "ASYNC_TURBO" && trimmed != "DEFAULT" {
                    return Err(GsutilError::command(format!(
                        "Invalid value for --rpo. Must be one of: ASYNC_TURBO|DEFAULT, provided: {a}"
                    )));
                }
                rpo = Some(trimmed.to_string());
            }
            "-b" => {
                insist_on_or_off(a, "Only on and off values allowed for -b option")?;
                bucket_policy_only = Some(a == "on");
            }
            "--pap" => pap = Some(a.clone()),
            "--placement" => {
                let parts: Vec<String> = a.split(',').map(ToString::to_string).collect();
                if parts.len() != 2 {
                    return Err(GsutilError::command(format!(
                        "Please specify two regions separated by comma without space. Specified: {a}"
                    )));
                }
                placements = Some(parts);
            }
            _ => {}
        }
    }

    let mut metadata = Bucket {
        location,
        rpo,
        storage_class,
        ..Default::default()
    };

    if autoclass {
        metadata.autoclass = Some(BucketAutoclass {
            enabled: Some(true),
            ..Default::default()
        });
    }

    if bucket_policy_only.is_some() || pap.is_some() {
        metadata.iam_configuration = Some(BucketIamConfiguration {
            bucket_policy_only: bucket_policy_only.map(|en| UniformBucketLevelAccess {
                enabled: Some(en),
                locked_time: None,
            }),
            uniform_bucket_level_access: bucket_policy_only.map(|en| UniformBucketLevelAccess {
                enabled: Some(en),
                locked_time: None,
            }),
            public_access_prevention: pap,
        });
    }

    if let Some(ref key) = kms_key {
        metadata.encryption = Some(BucketEncryption {
            default_kms_key_name: Some(key.clone()),
        });
    }

    if let Some(locs) = placements {
        metadata.custom_placement_config = Some(BucketCustomPlacementConfig {
            data_locations: Some(locs),
        });
    }

    let api = ctx.api().await?;
    let effective_project = ctx
        .effective_project_id(project_id.as_deref())
        .map(ToString::to_string);

    for bucket_url_str in args {
        let bucket_url = StorageUrl::parse(bucket_url_str)?;
        if let Some(secs) = retention_secs {
            if bucket_url.scheme() != "gs" {
                return Err(GsutilError::command(
                    "Retention policy can only be specified for GCS buckets.",
                ));
            }
            metadata.retention_policy = Some(BucketRetentionPolicy {
                retention_period: Some(secs.to_string()),
                ..Default::default()
            });
        }

        if !bucket_url.is_bucket() {
            return Err(GsutilError::command(format!(
                "The mb command requires a URL that specifies a bucket.\n\"{bucket_url}\" is not valid."
            )));
        }

        let bucket_name = bucket_url.bucket_name().unwrap_or("");
        validate_bucket_name(bucket_name)?;

        ctx.info(&format!("Creating {bucket_url}..."));
        let provider_api = api.for_provider(bucket_url.scheme())?;
        match provider_api
            .create_bucket(
                bucket_name,
                effective_project.as_deref(),
                Some(&metadata),
                None,
            )
            .await
        {
            Ok(_) => {}
            Err(GsutilError::Service(se))
                if se.kind == ServiceErrorKind::AccessDenied && se.reason.contains("key") =>
            {
                let mut msg = format!("{} To authorize, run:\n  gsutil kms authorize", se.reason);
                if let Some(ref k) = kms_key {
                    msg.push_str(&format!(" \\\n    -k {k}"));
                }
                if let Some(ref p) = effective_project {
                    msg.push_str(&format!(" \\\n    -p {p}"));
                }
                return Err(GsutilError::command(msg));
            }
            Err(e) => return Err(e),
        }
    }

    Ok(0)
}
