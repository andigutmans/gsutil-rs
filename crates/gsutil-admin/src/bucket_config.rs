//! Bucket configuration commands (14 commands):
//! `versioning`, `cors`, `lifecycle`, `logging`, `web`, `label`,
//! `requesterpays`, `defstorageclass`, `ubla`, `bucketpolicyonly`,
//! `pap`, `rpo`, `autoclass`, `retention`.

use std::collections::BTreeMap;

use chrono::DateTime;
use gsutil_core::api::{
    Bucket, BucketAutoclass, BucketBilling, BucketCors, BucketIamConfiguration, BucketLifecycle,
    BucketLogging, BucketRetentionPolicy, BucketVersioning, BucketWebsite, Object, Preconditions,
    UniformBucketLevelAccess,
};
use gsutil_core::error::{GsutilError, Result, ServiceError};
use gsutil_core::url::{urls_are_for_single_provider, StorageUrl};

use crate::{
    bucket_display_no_slash, expand_bucket_urls, expand_cloud_urls, insist_on_or_off,
    normalize_storage_class, parse_retention_duration_secs, read_json_arg, AdminContext,
    SECONDS_IN_DAY, SECONDS_IN_MONTH, SECONDS_IN_YEAR,
};

// ---------------------------------------------------------------------------
// 1. versioning (get | set on|off)
// ---------------------------------------------------------------------------

pub async fn run_versioning(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "versioning requires a subcommand (get|set) and bucket URL(s).",
        ));
    }
    match args[0].as_str() {
        "get" => {
            let fields = ["versioning".to_string()];
            let buckets = expand_bucket_urls(ctx, &args[1..], "versioning").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx.api.get_bucket(name, Some(&fields)).await?;
                let enabled = meta.versioning.and_then(|v| v.enabled).unwrap_or(false);
                let state = if enabled { "Enabled" } else { "Suspended" };
                writeln!(ctx.out, "{}: {state}", bucket_display_no_slash(&b))?;
            }
            Ok(())
        }
        "set" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "versioning set requires on|off and at least one bucket URL.",
                ));
            }
            let enabled = insist_on_or_off(
                &args[1],
                "Argument to \"versioning set\" must be either <on|off>.",
            )?;
            let fields = ["versioning".to_string()];
            let buckets = expand_bucket_urls(ctx, &args[2..], "versioning").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let verb = if enabled { "Enabling" } else { "Suspending" };
                writeln!(
                    ctx.err,
                    "{verb} versioning for {}...",
                    b.bucket_url_string()
                )?;
                let patch = Bucket {
                    versioning: Some(BucketVersioning {
                        enabled: Some(enabled),
                    }),
                    ..Default::default()
                };
                ctx.api
                    .patch_bucket(name, &patch, None, None, None, Some(&fields))
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the versioning command."
        ))),
    }
}

// ---------------------------------------------------------------------------
// 2. cors (get | set <json-file>)
// ---------------------------------------------------------------------------

pub async fn run_cors(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "cors requires a subcommand (get|set) and arguments.",
        ));
    }
    match args[0].as_str() {
        "get" => {
            let fields = ["cors".to_string()];
            let buckets = expand_bucket_urls(ctx, &args[1..], "cors").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx.api.get_bucket(name, Some(&fields)).await?;
                match meta.cors {
                    Some(cors)
                        if !cors.is_empty()
                            && cors.iter().any(|c| {
                                c.origin.is_some()
                                    || c.method.is_some()
                                    || c.response_header.is_some()
                                    || c.max_age_seconds.is_some()
                            }) =>
                    {
                        let json = serde_json::to_string_pretty(&cors).map_err(|e| {
                            GsutilError::command(format!("Failed to serialize CORS config: {e}"))
                        })?;
                        writeln!(ctx.out, "{json}")?;
                    }
                    _ => {
                        writeln!(
                            ctx.out,
                            "{} has no CORS configuration.",
                            b.bucket_url_string()
                        )?;
                    }
                }
            }
            Ok(())
        }
        "set" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "cors set requires a JSON file and at least one bucket URL.",
                ));
            }
            if !urls_are_for_single_provider(&args[2..])? {
                return Err(GsutilError::command(
                    "cors command spanning providers not allowed.",
                ));
            }
            let raw_json = read_json_arg(&args[1])?;
            if raw_json.trim_start().starts_with('<') {
                return Err(GsutilError::command(
                    "XML CORS data provided; please convert to JSON format.",
                ));
            }
            let val: serde_json::Value = serde_json::from_str(&raw_json).map_err(|e| {
                GsutilError::command(format!("Invalid CORS JSON in \"{}\": {e}", args[1]))
            })?;
            if !val.is_array() {
                return Err(GsutilError::command(
                    "CORS configuration should be formatted as a list of JSON objects.",
                ));
            }
            let cors: Vec<BucketCors> = serde_json::from_value(val).map_err(|e| {
                GsutilError::command(format!("Invalid CORS JSON in \"{}\": {e}", args[1]))
            })?;
            let buckets = expand_bucket_urls(ctx, &args[2..], "cors").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                writeln!(ctx.err, "Setting CORS on {}...", b.bucket_url_string())?;
                let patch = Bucket {
                    cors: Some(cors.clone()),
                    ..Default::default()
                };
                ctx.api
                    .patch_bucket(name, &patch, None, None, None, None)
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the cors command."
        ))),
    }
}

// ---------------------------------------------------------------------------
// 3. lifecycle (get | set <json-file>)
// ---------------------------------------------------------------------------

pub async fn run_lifecycle(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(GsutilError::command(
            "The lifecycle command requires at least 2 arguments.",
        ));
    }
    match args[0].as_str() {
        "get" => {
            if args.len() < 2 {
                return Err(GsutilError::command(
                    "The lifecycle command requires at least 2 arguments.",
                ));
            }
            let fields = ["lifecycle".to_string()];
            let buckets = expand_bucket_urls(ctx, &args[1..], "lifecycle").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx.api.get_bucket(name, Some(&fields)).await?;
                match meta.lifecycle {
                    Some(lc) if lc.rule.as_ref().is_some_and(|r| !r.is_empty()) => {
                        let json = serde_json::to_string_pretty(&lc).map_err(|e| {
                            GsutilError::command(format!(
                                "Failed to serialize lifecycle config: {e}"
                            ))
                        })?;
                        writeln!(ctx.out, "{json}")?;
                    }
                    _ => {
                        writeln!(
                            ctx.out,
                            "{} has no lifecycle configuration.",
                            b.bucket_url_string()
                        )?;
                    }
                }
            }
            Ok(())
        }
        "set" => {
            if args.len() < 2 {
                return Err(GsutilError::command(
                    "The lifecycle command requires at least 2 arguments.",
                ));
            }
            if args.len() < 3 || !urls_are_for_single_provider(&args[2..])? {
                return Err(GsutilError::command(
                    "lifecycle command spanning providers not allowed.",
                ));
            }
            let raw_json = read_json_arg(&args[1])?;
            if raw_json.trim_start().starts_with('<') {
                return Err(GsutilError::command(
                    "XML lifecycle data provided; please convert to JSON format.",
                ));
            }
            // Accept either `{"lifecycle": {"rule": [...]}}` or `{"rule": [...]}` or `{}`.
            let val: serde_json::Value = serde_json::from_str(&raw_json).map_err(|e| {
                GsutilError::command(format!("Invalid lifecycle JSON in \"{}\": {e}", args[1]))
            })?;
            let lc_val = val.get("lifecycle").cloned().unwrap_or(val);
            if let Some(obj) = lc_val.as_object() {
                for key in obj.keys() {
                    if key != "rule" {
                        return Err(GsutilError::command(format!(
                            "Invalid lifecycle config in \"{}\": unknown field \"{key}\".",
                            args[1]
                        )));
                    }
                }
                if let Some(rules) = obj.get("rule").and_then(|r| r.as_array()) {
                    const VALID_CONDITIONS: &[&str] = &[
                        "age",
                        "createdBefore",
                        "customTimeBefore",
                        "daysSinceCustomTime",
                        "daysSinceNoncurrentTime",
                        "isLive",
                        "matchesPrefix",
                        "matchesStorageClass",
                        "matchesSuffix",
                        "noncurrentTimeBefore",
                        "numNewerVersions",
                    ];
                    for rule in rules {
                        let Some(rmap) = rule.as_object() else {
                            return Err(GsutilError::command(format!(
                                "Invalid lifecycle rule in \"{}\".",
                                args[1]
                            )));
                        };
                        if !rmap.contains_key("action") {
                            return Err(GsutilError::command(format!(
                                "Invalid lifecycle rule in \"{}\": missing \"action\".",
                                args[1]
                            )));
                        }
                        if let Some(cond) = rmap.get("condition").and_then(|c| c.as_object()) {
                            for ck in cond.keys() {
                                if !VALID_CONDITIONS.contains(&ck.as_str()) {
                                    return Err(GsutilError::command(format!(
                                        "Invalid lifecycle condition \"{ck}\" in \"{}\".",
                                        args[1]
                                    )));
                                }
                            }
                        }
                    }
                }
            } else {
                return Err(GsutilError::command(format!(
                    "Invalid lifecycle JSON in \"{}\": expected JSON object.",
                    args[1]
                )));
            }
            let lifecycle: BucketLifecycle = serde_json::from_value(lc_val).map_err(|e| {
                GsutilError::command(format!("Invalid lifecycle config in \"{}\": {e}", args[1]))
            })?;
            let is_empty = lifecycle.rule.as_ref().is_none_or(|r| r.is_empty());
            let buckets = expand_bucket_urls(ctx, &args[2..], "lifecycle").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                ctx.info(&format!(
                    "Setting lifecycle configuration on {}...",
                    b.bucket_url_string()
                ))?;
                let patch = if is_empty {
                    Bucket {
                        clear_fields: vec!["lifecycle".to_string()],
                        ..Default::default()
                    }
                } else {
                    Bucket {
                        lifecycle: Some(lifecycle.clone()),
                        ..Default::default()
                    }
                };
                ctx.api
                    .for_provider(b.scheme.as_str())?
                    .patch_bucket(name, &patch, None, None, None, None)
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the lifecycle command."
        ))),
    }
}

// ---------------------------------------------------------------------------
// 4. logging (get | set on -b <log_bucket> [-o <prefix>] | set off)
// ---------------------------------------------------------------------------

pub async fn run_logging(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "logging requires a subcommand (get|set) and arguments.",
        ));
    }
    match args[0].as_str() {
        "get" => {
            let fields = ["logging".to_string()];
            let buckets = expand_bucket_urls(ctx, &args[1..], "logging").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx.api.get_bucket(name, Some(&fields)).await?;
                match meta.logging {
                    Some(log) if log.log_bucket.is_some() => {
                        let json = serde_json::to_string_pretty(&log).map_err(|e| {
                            GsutilError::command(format!("Failed to serialize logging config: {e}"))
                        })?;
                        writeln!(ctx.out, "{json}")?;
                    }
                    _ => {
                        writeln!(
                            ctx.out,
                            "{} has no logging configuration.",
                            b.bucket_url_string()
                        )?;
                    }
                }
            }
            Ok(())
        }
        "set" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "The logging command requires at least 3 arguments.",
                ));
            }
            let enabled = match args[1].to_ascii_lowercase().as_str() {
                "on" => true,
                "off" => false,
                other => {
                    return Err(GsutilError::command(format!(
                        "Invalid subcommand \"{other}\" for the \"logging set\" command."
                    )));
                }
            };
            let mut log_bucket: Option<String> = None;
            let mut log_bucket_url_raw: Option<String> = None;
            let mut log_prefix: Option<String> = None;
            let mut url_args = Vec::new();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "-b" => {
                        i += 1;
                        let val = args.get(i).ok_or_else(|| {
                            GsutilError::command("Option -b requires a log bucket argument.")
                        })?;
                        let parsed = StorageUrl::parse(val)?;
                        match parsed {
                            StorageUrl::Cloud(c) if c.is_bucket() => {
                                log_bucket = c.bucket_name;
                                log_bucket_url_raw = Some(val.clone());
                            }
                            _ => {
                                return Err(GsutilError::command(format!(
                                    "Log bucket \"{val}\" must specify a bucket URL."
                                )));
                            }
                        }
                    }
                    "-o" => {
                        i += 1;
                        let val = args.get(i).ok_or_else(|| {
                            GsutilError::command("Option -o requires a log object prefix argument.")
                        })?;
                        log_prefix = Some(val.clone());
                    }
                    other => url_args.push(other.to_string()),
                }
                i += 1;
            }
            if enabled && log_bucket.is_none() {
                return Err(GsutilError::command(
                    "logging set on requires '-b <log_bucket>'.",
                ));
            }
            if url_args.is_empty() {
                return Err(GsutilError::command(
                    "The logging command requires at least 3 arguments.",
                ));
            }
            let mut provider_check = url_args.clone();
            if let Some(ref lb) = log_bucket_url_raw {
                provider_check.push(lb.clone());
            }
            if !urls_are_for_single_provider(&provider_check)? {
                return Err(GsutilError::command(
                    "logging command spanning providers not allowed.",
                ));
            }
            let buckets = expand_bucket_urls(ctx, &url_args, "logging").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let patch = if enabled {
                    ctx.info(&format!("Enabling logging on {}...", b.bucket_url_string()))?;
                    Bucket {
                        logging: Some(BucketLogging {
                            log_bucket: log_bucket.clone(),
                            log_object_prefix: Some(
                                log_prefix.clone().unwrap_or_else(|| name.to_string()),
                            ),
                        }),
                        ..Default::default()
                    }
                } else {
                    ctx.info(&format!(
                        "Disabling logging on {}...",
                        b.bucket_url_string()
                    ))?;
                    Bucket {
                        clear_fields: vec!["logging".to_string()],
                        ..Default::default()
                    }
                };
                ctx.api
                    .for_provider(b.scheme.as_str())?
                    .patch_bucket(name, &patch, None, None, None, None)
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the logging command."
        ))),
    }
}

// ---------------------------------------------------------------------------
// 5. web (get | set [-m <main_page>] [-e <error_page>])
// ---------------------------------------------------------------------------

pub async fn run_web(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "web requires a subcommand (get|set) and arguments.",
        ));
    }
    match args[0].as_str() {
        "get" => {
            let fields = ["website".to_string()];
            let buckets = expand_bucket_urls(ctx, &args[1..], "web").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx.api.get_bucket(name, Some(&fields)).await?;
                match meta.website {
                    Some(w) if w.main_page_suffix.is_some() || w.not_found_page.is_some() => {
                        let json = serde_json::to_string_pretty(&w).map_err(|e| {
                            GsutilError::command(format!("Failed to serialize website config: {e}"))
                        })?;
                        writeln!(ctx.out, "{json}")?;
                    }
                    _ => {
                        writeln!(
                            ctx.out,
                            "{} has no website configuration.",
                            b.bucket_url_string()
                        )?;
                    }
                }
            }
            Ok(())
        }
        "set" => {
            let mut main_page: Option<String> = None;
            let mut error_page: Option<String> = None;
            let mut url_args = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-m" => {
                        i += 1;
                        main_page = Some(
                            args.get(i)
                                .ok_or_else(|| GsutilError::command("Option -m requires a value."))?
                                .clone(),
                        );
                    }
                    "-e" => {
                        i += 1;
                        error_page = Some(
                            args.get(i)
                                .ok_or_else(|| GsutilError::command("Option -e requires a value."))?
                                .clone(),
                        );
                    }
                    other => url_args.push(other.to_string()),
                }
                i += 1;
            }
            let buckets = expand_bucket_urls(ctx, &url_args, "web").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                ctx.info(&format!(
                    "Setting website configuration on {}...",
                    b.bucket_url_string()
                ))?;
                let patch = if main_page.is_none() && error_page.is_none() {
                    Bucket {
                        clear_fields: vec!["website".to_string()],
                        ..Default::default()
                    }
                } else {
                    Bucket {
                        website: Some(BucketWebsite {
                            main_page_suffix: main_page.clone(),
                            not_found_page: error_page.clone(),
                        }),
                        ..Default::default()
                    }
                };
                ctx.api
                    .for_provider(b.scheme.as_str())?
                    .patch_bucket(name, &patch, None, None, None, None)
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the web command."
        ))),
    }
}

// ---------------------------------------------------------------------------
// 6. label (get | set <json-file> | ch [-l k:v] [-d k])
// ---------------------------------------------------------------------------

pub async fn run_label(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "label requires a subcommand (get|set|ch) and arguments.",
        ));
    }
    match args[0].as_str() {
        "get" => {
            let fields = ["labels".to_string()];
            let buckets = expand_bucket_urls(ctx, &args[1..], "label").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx.api.get_bucket(name, Some(&fields)).await?;
                match meta.labels {
                    Some(labels) if !labels.is_empty() => {
                        let json = serde_json::to_string_pretty(&labels).map_err(|e| {
                            GsutilError::command(format!("Failed to serialize labels: {e}"))
                        })?;
                        writeln!(ctx.out, "{json}")?;
                    }
                    _ => {
                        writeln!(
                            ctx.out,
                            "{} has no label configuration.",
                            b.bucket_url_string()
                        )?;
                    }
                }
            }
            Ok(())
        }
        "set" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "The label command requires at least 3 arguments.",
                ));
            }
            let raw_json = read_json_arg(&args[1])?;
            let labels: BTreeMap<String, String> =
                serde_json::from_str(&raw_json).map_err(|e| {
                    GsutilError::command(format!("Invalid label JSON in \"{}\": {e}", args[1]))
                })?;
            let buckets = expand_bucket_urls(ctx, &args[2..], "label").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let api = ctx.api.for_provider(b.scheme.as_str())?;
                let existing = api.get_bucket(name, Some(&["labels".to_string()])).await?;
                let removals: Vec<String> = existing
                    .labels
                    .unwrap_or_default()
                    .keys()
                    .filter(|k| !labels.contains_key(*k))
                    .cloned()
                    .collect();
                ctx.info(&format!(
                    "Setting label configuration on {}...",
                    b.bucket_url_string()
                ))?;
                let patch = Bucket {
                    labels: if labels.is_empty() {
                        None
                    } else {
                        Some(labels.clone())
                    },
                    label_removals: removals,
                    ..Default::default()
                };
                api.patch_bucket(name, &patch, None, None, None, None)
                    .await?;
            }
            Ok(())
        }
        "ch" => {
            let mut updates: Vec<(String, Option<String>)> = Vec::new();
            let mut url_args = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-l" => {
                        i += 1;
                        let kv = args
                            .get(i)
                            .ok_or_else(|| GsutilError::command("Option -l requires key:value."))?;
                        let (k, v) = kv.split_once(':').ok_or_else(|| {
                            GsutilError::command(format!(
                                "Found incorrectly formatted option for \"gsutil label ch\": \"{kv}\". Expected key:value."
                            ))
                        })?;
                        if k.is_empty() || v.contains(':') {
                            return Err(GsutilError::command(format!(
                                "Found incorrectly formatted option for \"gsutil label ch\": \"{kv}\". Expected key:value."
                            )));
                        }
                        updates.push((k.to_string(), Some(v.to_string())));
                    }
                    "-d" => {
                        i += 1;
                        let k = args.get(i).ok_or_else(|| {
                            GsutilError::command("Option -d requires a label key.")
                        })?;
                        if k.contains(':') {
                            return Err(GsutilError::command(format!(
                                "Found incorrectly formatted option for \"gsutil label ch\": \"{k}\". To delete a label, provide only its key."
                            )));
                        }
                        updates.push((k.clone(), None));
                    }
                    other => url_args.push(other.to_string()),
                }
                i += 1;
            }
            if updates.is_empty() {
                return Err(GsutilError::command(
                    "Please specify at least one label change with the -l or -d flags.",
                ));
            }
            let buckets = expand_bucket_urls(ctx, &url_args, "label").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let mut set_labels: BTreeMap<String, String> = BTreeMap::new();
                let mut removals: Vec<String> = Vec::new();
                for (k, v_opt) in &updates {
                    match v_opt {
                        Some(v) => {
                            removals.retain(|rk| rk != k);
                            set_labels.insert(k.clone(), v.clone());
                        }
                        None => {
                            set_labels.remove(k);
                            if !removals.iter().any(|rk| rk == k) {
                                removals.push(k.clone());
                            }
                        }
                    }
                }
                ctx.info(&format!(
                    "Setting label configuration on {}...",
                    b.bucket_url_string()
                ))?;
                let patch = Bucket {
                    labels: if set_labels.is_empty() {
                        None
                    } else {
                        Some(set_labels)
                    },
                    label_removals: removals,
                    ..Default::default()
                };
                ctx.api
                    .for_provider(b.scheme.as_str())?
                    .patch_bucket(name, &patch, None, None, None, None)
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the label command."
        ))),
    }
}

// ---------------------------------------------------------------------------
// 7. requesterpays (get | set on|off)
// ---------------------------------------------------------------------------

pub async fn run_requesterpays(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "requesterpays requires a subcommand (get|set) and arguments.",
        ));
    }
    match args[0].as_str() {
        "get" => {
            let fields = ["billing".to_string()];
            let buckets = expand_bucket_urls(ctx, &args[1..], "requesterpays").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx.api.get_bucket(name, Some(&fields)).await?;
                let enabled = meta.billing.and_then(|b| b.requester_pays).unwrap_or(false);
                let state = if enabled { "Enabled" } else { "Disabled" };
                writeln!(ctx.out, "{}: {state}", bucket_display_no_slash(&b))?;
            }
            Ok(())
        }
        "set" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "requesterpays set requires on|off and bucket URL(s).",
                ));
            }
            let enabled = insist_on_or_off(
                &args[1],
                "Argument to \"requesterpays set\" must be either \"on\" or \"off\".",
            )?;
            let buckets = expand_bucket_urls(ctx, &args[2..], "requesterpays").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let verb = if enabled { "Enabling" } else { "Disabling" };
                writeln!(
                    ctx.err,
                    "{verb} requester pays for {}...",
                    b.bucket_url_string()
                )?;
                let patch = Bucket {
                    billing: Some(BucketBilling {
                        requester_pays: Some(enabled),
                    }),
                    ..Default::default()
                };
                ctx.api
                    .patch_bucket(name, &patch, None, None, None, None)
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the requesterpays command."
        ))),
    }
}

// ---------------------------------------------------------------------------
// 8. defstorageclass (get | set <storage_class>)
// ---------------------------------------------------------------------------

pub async fn run_defstorageclass(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "defstorageclass requires a subcommand (get|set) and arguments.",
        ));
    }
    let check_gs_urls = |urls: &[String]| -> Result<()> {
        for raw in urls {
            let parsed = StorageUrl::parse(raw)?;
            if !matches!(parsed, StorageUrl::Cloud(ref c) if c.scheme.as_str() == "gs") {
                return Err(GsutilError::command(format!(
                    "\"defstorageclass\" does not support the URL \"{raw}\". Did you mean to use a gs:// URL?"
                )));
            }
        }
        Ok(())
    };
    let fields = ["storageClass".to_string()];
    match args[0].as_str() {
        "get" => {
            check_gs_urls(&args[1..])?;
            let buckets = expand_bucket_urls(ctx, &args[1..], "defstorageclass").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx
                    .api
                    .for_provider(b.scheme.as_str())?
                    .get_bucket(name, Some(&fields))
                    .await?;
                let sc = meta.storage_class.as_deref().unwrap_or("STANDARD");
                writeln!(ctx.out, "{}: {sc}", bucket_display_no_slash(&b))?;
            }
            Ok(())
        }
        "set" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "The defstorageclass command requires at least 3 arguments.",
                ));
            }
            check_gs_urls(&args[2..])?;
            let sc = normalize_storage_class(&args[1]);
            const VALID_STORAGE_CLASSES: &[&str] = &[
                "STANDARD",
                "NEARLINE",
                "COLDLINE",
                "ARCHIVE",
                "MULTI_REGIONAL",
                "REGIONAL",
                "DURABLE_REDUCED_AVAILABILITY",
            ];
            if !VALID_STORAGE_CLASSES.contains(&sc.as_str()) {
                return Err(GsutilError::Service(ServiceError::bad_request(
                    "Invalid storage class",
                    Some(400),
                    Some(format!("Invalid storage class \"{}\".", args[1])),
                )));
            }
            let buckets = expand_bucket_urls(ctx, &args[2..], "defstorageclass").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                ctx.info(&format!(
                    "Setting default storage class to \"{sc}\" for bucket {}",
                    bucket_display_no_slash(&b)
                ))?;
                let patch = Bucket {
                    storage_class: Some(sc.clone()),
                    ..Default::default()
                };
                ctx.api
                    .for_provider(b.scheme.as_str())?
                    .patch_bucket(name, &patch, None, None, None, Some(&fields))
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the defstorageclass command."
        ))),
    }
}

// ---------------------------------------------------------------------------
// 9 & 10. ubla / bucketpolicyonly (get | set on|off)
// ---------------------------------------------------------------------------

pub async fn run_ubla(ctx: &mut AdminContext<'_>, args: &[String], legacy_bpo: bool) -> Result<()> {
    let cmd_name = if legacy_bpo {
        "bucketpolicyonly"
    } else {
        "ubla"
    };
    let label = if legacy_bpo {
        "Bucket Policy Only"
    } else {
        "Uniform bucket-level access"
    };
    if args.len() < 2 {
        return Err(GsutilError::command(format!(
            "{cmd_name} requires a subcommand (get|set) and arguments."
        )));
    }
    let fields = ["iamConfiguration".to_string()];
    match args[0].as_str() {
        "get" => {
            let buckets = expand_bucket_urls(ctx, &args[1..], cmd_name).await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx.api.get_bucket(name, Some(&fields)).await?;
                let ubla = meta
                    .iam_configuration
                    .and_then(|c| c.uniform_bucket_level_access.or(c.bucket_policy_only));
                let enabled = ubla.as_ref().and_then(|u| u.enabled).unwrap_or(false);
                let enabled_str = if enabled { "True" } else { "False" };
                let locked_line = ubla
                    .and_then(|u| u.locked_time)
                    .map(|lt| format!("  LockedTime: {}\n", format_ubla_locked_time(&lt)))
                    .unwrap_or_default();
                writeln!(
                    ctx.out,
                    "{label} setting for {}:\n  Enabled: {enabled_str}\n{locked_line}",
                    bucket_display_no_slash(&b)
                )?;
            }
            Ok(())
        }
        "set" => {
            if args.len() < 3 {
                return Err(GsutilError::command(format!(
                    "{cmd_name} set requires on|off and bucket URL(s)."
                )));
            }
            let enabled =
                insist_on_or_off(&args[1], "Only on and off values allowed for set option")?;
            let buckets = expand_bucket_urls(ctx, &args[2..], cmd_name).await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let verb = if enabled { "Enabling" } else { "Disabling" };
                writeln!(
                    ctx.out,
                    "{verb} {label} for {}...",
                    bucket_display_no_slash(&b)
                )?;
                let ubla_val = UniformBucketLevelAccess {
                    enabled: Some(enabled),
                    locked_time: None,
                };
                let iam_cfg = BucketIamConfiguration {
                    uniform_bucket_level_access: Some(ubla_val.clone()),
                    bucket_policy_only: Some(ubla_val),
                    public_access_prevention: None,
                };
                let patch = Bucket {
                    iam_configuration: Some(iam_cfg),
                    ..Default::default()
                };
                ctx.api
                    .patch_bucket(name, &patch, None, None, None, Some(&fields))
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\", use get|set instead."
        ))),
    }
}

// ---------------------------------------------------------------------------
// 11. pap (get | set enforced|inherited)
// ---------------------------------------------------------------------------

pub async fn run_pap(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "pap requires a subcommand (get|set) and arguments.",
        ));
    }
    let fields = ["iamConfiguration".to_string()];
    match args[0].as_str() {
        "get" => {
            let buckets = expand_bucket_urls(ctx, &args[1..], "pap").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx
                    .api
                    .for_provider(b.scheme.as_str())?
                    .get_bucket(name, Some(&fields))
                    .await?;
                let pap = meta
                    .iam_configuration
                    .and_then(|c| c.public_access_prevention)
                    .unwrap_or_else(|| "inherited".to_string());
                writeln!(ctx.out, "{}: {pap}", bucket_display_no_slash(&b))?;
            }
            Ok(())
        }
        "set" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "pap set requires enforced|inherited and bucket URL(s).",
                ));
            }
            let mode = args[1].as_str();
            if mode != "enforced" && mode != "inherited" {
                return Err(GsutilError::command(format!(
                    "{mode} is not a valid value for pap set. Must be \"enforced\" or \"inherited\"."
                )));
            }
            let buckets = expand_bucket_urls(ctx, &args[2..], "pap").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                writeln!(
                    ctx.out,
                    "Setting Public Access Prevention {mode} for {}",
                    bucket_display_no_slash(&b)
                )?;
                let patch = Bucket {
                    iam_configuration: Some(BucketIamConfiguration {
                        public_access_prevention: Some(mode.to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                ctx.api
                    .for_provider(b.scheme.as_str())?
                    .patch_bucket(name, &patch, None, None, None, Some(&fields))
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the pap command."
        ))),
    }
}

// ---------------------------------------------------------------------------
// 12. rpo (get | set ASYNC_TURBO|DEFAULT)
// ---------------------------------------------------------------------------

pub async fn run_rpo(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "rpo requires a subcommand (get|set) and arguments.",
        ));
    }
    let fields = ["rpo".to_string()];
    match args[0].as_str() {
        "get" => {
            let buckets = expand_bucket_urls(ctx, &args[1..], "rpo").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx.api.get_bucket(name, Some(&fields)).await?;
                let rpo = meta.rpo.as_deref().unwrap_or("None");
                writeln!(ctx.out, "{}: {rpo}", bucket_display_no_slash(&b))?;
            }
            Ok(())
        }
        "set" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "rpo set requires ASYNC_TURBO|DEFAULT and bucket URL(s).",
                ));
            }
            let val = args[1].as_str();
            if val != "ASYNC_TURBO" && val != "DEFAULT" {
                return Err(GsutilError::command(
                    "Invalid value for rpo set. Should be one of ASYNC_TURBO|DEFAULT",
                ));
            }
            let buckets = expand_bucket_urls(ctx, &args[2..], "rpo").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                writeln!(
                    ctx.err,
                    "Setting rpo {val} for {}",
                    bucket_display_no_slash(&b)
                )?;
                let patch = Bucket {
                    rpo: Some(val.to_string()),
                    ..Default::default()
                };
                ctx.api
                    .patch_bucket(name, &patch, None, None, None, None)
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "rpo only supports get|set, got \"{other}\""
        ))),
    }
}

// ---------------------------------------------------------------------------
// 13. autoclass (get | set on|off)
// ---------------------------------------------------------------------------

pub async fn run_autoclass(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "autoclass requires a subcommand (get|set) and arguments.",
        ));
    }
    let fields = ["autoclass".to_string()];
    match args[0].as_str() {
        "get" => {
            let buckets = expand_bucket_urls(ctx, &args[1..], "autoclass").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx.api.get_bucket(name, Some(&fields)).await?;
                let (enabled, toggle_time) = match meta.autoclass {
                    Some(ac) => (
                        ac.enabled.unwrap_or(false),
                        ac.toggle_time.unwrap_or_else(|| "None".to_string()),
                    ),
                    None => (false, "None".to_string()),
                };
                let enabled_str = if enabled { "True" } else { "False" };
                writeln!(
                    ctx.out,
                    "{}:\n  Enabled: {enabled_str}\n  Toggle Time: {toggle_time}",
                    bucket_display_no_slash(&b)
                )?;
            }
            Ok(())
        }
        "set" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "autoclass set requires on|off and bucket URL(s).",
                ));
            }
            let enabled =
                insist_on_or_off(&args[1], "Only on and off values allowed for set option")?;
            let buckets = expand_bucket_urls(ctx, &args[2..], "autoclass").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                writeln!(
                    ctx.out,
                    "Setting Autoclass {} for {}",
                    args[1],
                    bucket_display_no_slash(&b)
                )?;
                let patch = Bucket {
                    autoclass: Some(BucketAutoclass {
                        enabled: Some(enabled),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                ctx.api
                    .patch_bucket(name, &patch, None, None, None, None)
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "autoclass only supports get|set, got \"{other}\""
        ))),
    }
}

/// Format UBLA/BPO `lockedTime` RFC3339 string as Python's `YYYY-MM-DD HH:MM:SS.ffffff+00:00`.
fn format_ubla_locked_time(raw: &str) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        let utc = dt.with_timezone(&chrono::Utc);
        let micros = utc.timestamp_subsec_micros();
        return format!("{}.{:06}+00:00", utc.format("%Y-%m-%d %H:%M:%S"), micros);
    }
    raw.to_string()
}

/// Format retention period in seconds matching `retention_util._RetentionPeriodToString`.
fn format_retention_duration(period: u64) -> String {
    if period.is_multiple_of(SECONDS_IN_YEAR) {
        format!("    Duration: {} Year(s)", period / SECONDS_IN_YEAR)
    } else if period.is_multiple_of(SECONDS_IN_MONTH) {
        format!("    Duration: {} Month(s)", period / SECONDS_IN_MONTH)
    } else if period.is_multiple_of(SECONDS_IN_DAY) {
        format!("    Duration: {} Day(s)", period / SECONDS_IN_DAY)
    } else if period > SECONDS_IN_DAY {
        format!(
            "    Duration: {} Seconds (~{} Day(s))",
            period,
            period / SECONDS_IN_DAY
        )
    } else {
        format!("    Duration: {} Second(s)", period)
    }
}

/// Format a bucket's retention policy matching `retention_util.RetentionPolicyToString`.
fn format_retention_policy(rp: Option<&BucketRetentionPolicy>, bucket_url: &str) -> String {
    if let Some(rp) = rp {
        if let Some(period) = rp
            .retention_period
            .as_deref()
            .and_then(|p| p.parse::<u64>().ok())
            .filter(|&p| p > 0)
        {
            let locked = if rp.is_locked.unwrap_or(false) {
                "(LOCKED)"
            } else {
                "(UNLOCKED)"
            };
            let dur = format_retention_duration(period);
            let eff = rp
                .effective_time
                .as_deref()
                .map(|raw| {
                    DateTime::parse_from_rfc3339(raw)
                        .map(|dt| dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
                        .unwrap_or_else(|_| raw.to_string())
                })
                .unwrap_or_else(|| "None".to_string());
            return format!("  Retention Policy {locked}:\n{dur}\n    Effective Time: {eff}");
        }
    }
    format!("{bucket_url} has no Retention Policy.")
}

// ---------------------------------------------------------------------------
// 14. retention (set|clear|get|lock|event-default|event|temp)
// ---------------------------------------------------------------------------

pub async fn run_retention(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "retention requires a subcommand (set|clear|get|lock|event-default|event|temp).",
        ));
    }
    match args[0].as_str() {
        "set" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "retention set requires <duration> and bucket URL(s).",
                ));
            }
            let secs = parse_retention_duration_secs(&args[1])?;
            let buckets = expand_bucket_urls(ctx, &args[2..], "retention").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                ctx.info(&format!(
                    "Setting Retention Policy on {}...",
                    b.bucket_url_string()
                ))?;
                let patch = Bucket {
                    retention_policy: Some(BucketRetentionPolicy {
                        retention_period: Some(secs.to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                ctx.api
                    .for_provider(b.scheme.as_str())?
                    .patch_bucket(name, &patch, None, None, None, None)
                    .await?;
            }
            Ok(())
        }
        "clear" => {
            let fields = ["retentionPolicy".to_string()];
            let buckets = expand_bucket_urls(ctx, &args[1..], "retention").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let api = ctx.api.for_provider(b.scheme.as_str())?;
                let meta = api.get_bucket(name, Some(&fields)).await?;
                if meta
                    .retention_policy
                    .as_ref()
                    .and_then(|rp| rp.is_locked)
                    .unwrap_or(false)
                {
                    return Err(GsutilError::command(format!(
                        "Bucket \"{}\" has a locked Retention Policy which cannot be removed.",
                        b.bucket_url_string()
                    )));
                }
                ctx.info(&format!(
                    "Clearing Retention Policy on {}...",
                    b.bucket_url_string()
                ))?;
                let patch = Bucket {
                    clear_fields: vec!["retentionPolicy".to_string()],
                    ..Default::default()
                };
                api.patch_bucket(name, &patch, None, None, None, Some(&fields))
                    .await?;
            }
            Ok(())
        }
        "get" => {
            if args[1..].iter().any(|a| a.starts_with('-')) {
                return Err(GsutilError::command("Incorrect option(s) specified."));
            }
            let fields = ["retentionPolicy".to_string()];
            let buckets = expand_bucket_urls(ctx, &args[1..], "retention").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx
                    .api
                    .for_provider(b.scheme.as_str())?
                    .get_bucket(name, Some(&fields))
                    .await?;
                writeln!(
                    ctx.out,
                    "{}",
                    format_retention_policy(meta.retention_policy.as_ref(), &b.bucket_url_string())
                )?;
            }
            Ok(())
        }
        "lock" => {
            if args[1..].iter().any(|a| a.starts_with('-')) {
                return Err(GsutilError::command("Incorrect option(s) specified."));
            }
            let fields = ["retentionPolicy".to_string(), "metageneration".to_string()];
            let buckets = expand_bucket_urls(ctx, &args[1..], "retention").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx
                    .api
                    .for_provider(b.scheme.as_str())?
                    .get_bucket(name, Some(&fields))
                    .await?;
                if meta
                    .retention_policy
                    .as_ref()
                    .and_then(|rp| rp.retention_period.as_deref())
                    .and_then(|p| p.parse::<u64>().ok())
                    .unwrap_or(0)
                    == 0
                {
                    return Err(GsutilError::command(format!(
                        "Bucket \"{}\" does not have an Unlocked Retention Policy.",
                        b.bucket_url_string()
                    )));
                }
                if meta
                    .retention_policy
                    .as_ref()
                    .and_then(|rp| rp.is_locked)
                    .unwrap_or(false)
                {
                    ctx.info(&format!(
                        "Retention Policy on {} is already locked.",
                        b.bucket_url_string()
                    ))?;
                    continue;
                }
                let policy_str =
                    format_retention_policy(meta.retention_policy.as_ref(), &b.bucket_url_string());
                let question = format!(
                    "This will PERMANENTLY set the Retention Policy on gs://{name} to:\n\n\
                     {policy_str}\n\nThis setting cannot be reverted!  Continue?"
                );
                if !ctx.confirm(&question)? {
                    ctx.info(&format!(
                        "  Abort Locking Retention Policy on {}",
                        b.bucket_url_string()
                    ))?;
                    continue;
                }
                let metagen: i64 = meta
                    .metageneration
                    .as_deref()
                    .and_then(|m| m.parse().ok())
                    .unwrap_or(1);
                ctx.info(&format!(
                    "Locking Retention Policy on {}...",
                    b.bucket_url_string()
                ))?;
                ctx.api
                    .for_provider(b.scheme.as_str())?
                    .lock_retention_policy(name, metagen)
                    .await?;
            }
            Ok(())
        }
        "event-default" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "retention event-default requires set|release and bucket URL(s).",
                ));
            }
            let enable = match args[1].as_str() {
                "set" => true,
                "release" => false,
                other => {
                    return Err(GsutilError::command(format!(
                        "Invalid subcommand \"{other}\" for the \"retention event-default\" command."
                    )));
                }
            };
            let buckets = expand_bucket_urls(ctx, &args[2..], "retention").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let patch = Bucket {
                    default_event_based_hold: Some(enable),
                    ..Default::default()
                };
                ctx.api
                    .patch_bucket(name, &patch, None, None, None, None)
                    .await?;
            }
            Ok(())
        }
        "event" | "temp" => {
            let is_event = args[0] == "event";
            if args.len() < 3 {
                return Err(GsutilError::command(format!(
                    "retention {} requires set|release and object URL(s).",
                    args[0]
                )));
            }
            let enable = match args[1].as_str() {
                "set" => true,
                "release" => false,
                other => {
                    return Err(GsutilError::command(format!(
                        "Invalid subcommand \"{other}\" for the \"retention {}\" command.",
                        args[0]
                    )));
                }
            };
            let objs = expand_cloud_urls(ctx, &args[2..], false, false).await?;
            for o in objs {
                let bname = o.bucket_name.as_deref().unwrap_or("");
                let oname = o.object_name.as_deref().ok_or_else(|| {
                    GsutilError::command(format!(
                        "retention {} requires object URLs, got bucket {}",
                        args[0],
                        o.url_string()
                    ))
                })?;
                let patch = if is_event {
                    Object {
                        event_based_hold: Some(enable),
                        ..Default::default()
                    }
                } else {
                    Object {
                        temporary_hold: Some(enable),
                        ..Default::default()
                    }
                };
                ctx.api
                    .patch_object_metadata(
                        bname,
                        oname,
                        &patch,
                        None,
                        o.generation.as_deref(),
                        Some(&Preconditions::default()),
                        None,
                    )
                    .await?;
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the retention command."
        ))),
    }
}
