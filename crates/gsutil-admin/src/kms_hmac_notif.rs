//! `kms`, `hmac`, and `notification` command handlers.
//!
//! Matches `gslib/commands/kms.py`, `gslib/commands/hmac.py`, and
//! `gslib/commands/notification.py`.

use std::collections::BTreeMap;

use chrono::DateTime;
use gsutil_core::api::{Bucket, BucketEncryption, CreateNotificationOptions, HmacKeyMetadata};
use gsutil_core::error::{GsutilError, Result};

use crate::{expand_bucket_urls, AdminContext};

// ---------------------------------------------------------------------------
// kms (encryption | authorize | serviceaccount)
// ---------------------------------------------------------------------------

pub async fn run_kms(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(GsutilError::command(
            "kms requires a subcommand (encryption|authorize|serviceaccount).",
        ));
    }
    match args[0].as_str() {
        "serviceaccount" => {
            let mut project_override: Option<String> = None;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "-p" {
                    i += 1;
                    project_override = Some(
                        args.get(i)
                            .ok_or_else(|| {
                                GsutilError::command("Option -p requires a project ID.")
                            })?
                            .clone(),
                    );
                }
                i += 1;
            }
            let project = project_override
                .as_deref()
                .or_else(|| ctx.effective_project_id())
                .ok_or_else(|| {
                    GsutilError::project_id("No project ID specified for kms serviceaccount.")
                })?;
            let sa = ctx.api.get_project_service_account(project).await?;
            writeln!(ctx.out, "{}", sa.email_address.unwrap_or_default())?;
            Ok(())
        }
        "encryption" => {
            let mut clear_default = false;
            let mut kms_key: Option<String> = None;
            let mut url_args = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-d" => clear_default = true,
                    "-k" => {
                        i += 1;
                        kms_key = Some(
                            args.get(i)
                                .ok_or_else(|| {
                                    GsutilError::command("Option -k requires a KMS key name.")
                                })?
                                .clone(),
                        );
                    }
                    other => url_args.push(other.to_string()),
                }
                i += 1;
            }
            if clear_default && kms_key.is_some() {
                return Err(GsutilError::command(
                    "Cannot specify both -d and -k for kms encryption.",
                ));
            }
            let buckets = expand_bucket_urls(ctx, &url_args, "kms").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                if clear_default {
                    writeln!(
                        ctx.out,
                        "Clearing default encryption key for {}...",
                        b.bucket_url_string()
                    )?;
                    let patch = Bucket {
                        encryption: Some(BucketEncryption {
                            default_kms_key_name: None,
                        }),
                        ..Default::default()
                    };
                    ctx.api
                        .patch_bucket(name, &patch, None, None, None, None)
                        .await?;
                } else if let Some(ref key) = kms_key {
                    writeln!(
                        ctx.out,
                        "Setting default KMS key for bucket {}...",
                        b.bucket_url_string()
                    )?;
                    let patch = Bucket {
                        encryption: Some(BucketEncryption {
                            default_kms_key_name: Some(key.clone()),
                        }),
                        ..Default::default()
                    };
                    ctx.api
                        .patch_bucket(name, &patch, None, None, None, None)
                        .await?;
                } else {
                    let meta = ctx.api.get_bucket(name, None).await?;
                    match meta.encryption.and_then(|e| e.default_kms_key_name) {
                        Some(key) if !key.is_empty() => {
                            writeln!(
                                ctx.out,
                                "Default encryption key for {}:\n{key}",
                                b.bucket_url_string()
                            )?;
                        }
                        _ => {
                            writeln!(
                                ctx.out,
                                "Bucket {} has no default encryption key",
                                b.bucket_url_string()
                            )?;
                        }
                    }
                }
            }
            Ok(())
        }
        "authorize" => {
            let mut project_override: Option<String> = None;
            let mut kms_key: Option<String> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-p" => {
                        i += 1;
                        project_override = Some(
                            args.get(i)
                                .ok_or_else(|| {
                                    GsutilError::command("Option -p requires a project ID.")
                                })?
                                .clone(),
                        );
                    }
                    "-k" => {
                        i += 1;
                        kms_key = Some(
                            args.get(i)
                                .ok_or_else(|| {
                                    GsutilError::command("Option -k requires a KMS key name.")
                                })?
                                .clone(),
                        );
                    }
                    other => {
                        return Err(GsutilError::command(format!(
                            "Unexpected argument \"{other}\" for kms authorize."
                        )));
                    }
                }
                i += 1;
            }
            let key = kms_key
                .ok_or_else(|| GsutilError::command("kms authorize requires -k <kms_key_name>."))?;
            let project = project_override
                .or_else(|| ctx.effective_project_id().map(ToString::to_string))
                .ok_or_else(|| {
                    GsutilError::project_id("No project ID specified for kms authorize.")
                })?;
            let sa = ctx.api.get_project_service_account(&project).await?;
            let email = sa.email_address.unwrap_or_default();
            writeln!(
                ctx.out,
                "Authorized project {project} ({email}) to encrypt and decrypt with key:\n{key}"
            )?;
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the kms command."
        ))),
    }
}

// ---------------------------------------------------------------------------
// hmac (create | delete | get | list | update)
// ---------------------------------------------------------------------------

fn format_hmac_timestamp(raw: Option<&str>) -> String {
    let Some(s) = raw else {
        return "None".to_string();
    };
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    }
    s.to_string()
}

fn format_hmac_metadata(m: &HmacKeyMetadata) -> String {
    let fmt_line = |label: &str, val: &str, nl: bool| -> String {
        let mut s = format!("\t{:<22} {}", format!("{label}:"), val);
        if nl {
            s.push('\n');
        }
        s
    };
    let mut out = format!("Access ID {}:\n", m.access_id.as_deref().unwrap_or(""));
    out.push_str(&fmt_line("State", m.state.as_deref().unwrap_or(""), true));
    out.push_str(&fmt_line(
        "Service Account",
        m.service_account_email.as_deref().unwrap_or(""),
        true,
    ));
    out.push_str(&fmt_line(
        "Project",
        m.project_id.as_deref().unwrap_or(""),
        true,
    ));
    out.push_str(&fmt_line(
        "Time Created",
        &format_hmac_timestamp(m.time_created.as_deref()),
        true,
    ));
    out.push_str(&fmt_line(
        "Time Last Updated",
        &format_hmac_timestamp(m.updated.as_deref()),
        true,
    ));
    out.push_str(&fmt_line("Etag", m.etag.as_deref().unwrap_or(""), false));
    out
}

pub async fn run_hmac(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(GsutilError::command(
            "hmac requires a subcommand (create|delete|get|list|update).",
        ));
    }
    let subcmd = args[0].as_str();
    let mut project_override: Option<String> = None;
    let mut show_deleted = false;
    let mut long_listing = false;
    let mut sa_filter: Option<String> = None;
    let mut state: Option<String> = None;
    let mut etag: Option<String> = None;
    let mut positional = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => {
                i += 1;
                project_override = Some(
                    args.get(i)
                        .ok_or_else(|| GsutilError::command("Option -p requires a project ID."))?
                        .clone(),
                );
            }
            "-a" => show_deleted = true,
            "-l" => long_listing = true,
            "-u" => {
                i += 1;
                sa_filter = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            GsutilError::command("Option -u requires a service account email.")
                        })?
                        .clone(),
                );
            }
            "-s" => {
                i += 1;
                state = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            GsutilError::command("Option -s requires ACTIVE or INACTIVE.")
                        })?
                        .clone(),
                );
            }
            "-e" => {
                i += 1;
                etag = Some(
                    args.get(i)
                        .ok_or_else(|| GsutilError::command("Option -e requires an etag."))?
                        .clone(),
                );
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }

    let project = project_override
        .as_deref()
        .or_else(|| ctx.effective_project_id())
        .ok_or_else(|| GsutilError::project_id("No project ID specified for hmac command."))?;

    match subcmd {
        "create" => {
            let sa = positional.first().ok_or_else(|| {
                GsutilError::command("hmac create requires a service account email.")
            })?;
            let resp = ctx.api.create_hmac_key(project, sa).await?;
            writeln!(
                ctx.out,
                "Access ID:   {}",
                resp.metadata.access_id.as_deref().unwrap_or("")
            )?;
            writeln!(ctx.out, "Secret:      {}", resp.secret)?;
            Ok(())
        }
        "delete" => {
            let access_id = positional.first().ok_or_else(|| {
                GsutilError::command("hmac delete requires an Access ID to be specified.")
            })?;
            ctx.api.delete_hmac_key(project, access_id).await
        }
        "get" => {
            let access_id = positional.first().ok_or_else(|| {
                GsutilError::command("hmac get requires an Access ID to be specified.")
            })?;
            let meta = ctx.api.get_hmac_key(project, access_id).await?;
            writeln!(ctx.out, "{}", format_hmac_metadata(&meta))?;
            Ok(())
        }
        "list" => {
            let keys = ctx
                .api
                .list_hmac_keys(project, sa_filter.as_deref(), show_deleted)
                .await?;
            for k in keys {
                if long_listing {
                    writeln!(ctx.out, "{}\n", format_hmac_metadata(&k))?;
                } else {
                    writeln!(
                        ctx.out,
                        "{}\t{:<12} {}",
                        k.access_id.as_deref().unwrap_or(""),
                        k.state.as_deref().unwrap_or(""),
                        k.service_account_email.as_deref().unwrap_or("")
                    )?;
                }
            }
            Ok(())
        }
        "update" => {
            let access_id = positional.first().ok_or_else(|| {
                GsutilError::command("hmac update requires an Access ID to be specified.")
            })?;
            let new_state = state.as_deref().ok_or_else(|| {
                GsutilError::command("A state flag (-s) must be specified for hmac update.")
            })?;
            if new_state != "ACTIVE" && new_state != "INACTIVE" {
                return Err(GsutilError::command(format!(
                    "The state flag value must be one of ACTIVE, INACTIVE; got \"{new_state}\"."
                )));
            }
            let updated = ctx
                .api
                .update_hmac_key(project, access_id, new_state, etag.as_deref())
                .await?;
            writeln!(ctx.out, "{}", format_hmac_metadata(&updated))?;
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the hmac command."
        ))),
    }
}

// ---------------------------------------------------------------------------
// notification (create | delete | list | watchbucket | stopchannel)
// ---------------------------------------------------------------------------

pub async fn run_notification(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(GsutilError::command(
            "notification requires a subcommand (create|delete|list|watchbucket|stopchannel).",
        ));
    }
    match args[0].as_str() {
        "create" => {
            let mut topic: Option<String> = None;
            let mut payload_format = "JSON_API_V1".to_string();
            let mut event_types: Vec<String> = Vec::new();
            let mut custom_attrs: BTreeMap<String, String> = BTreeMap::new();
            let mut prefix: Option<String> = None;
            let mut url_args = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-t" => {
                        i += 1;
                        topic = Some(
                            args.get(i)
                                .ok_or_else(|| {
                                    GsutilError::command("Option -t requires a topic name.")
                                })?
                                .clone(),
                        );
                    }
                    "-f" => {
                        i += 1;
                        let fmt = args.get(i).ok_or_else(|| {
                            GsutilError::command("Option -f requires json or none.")
                        })?;
                        payload_format = match fmt.to_ascii_lowercase().as_str() {
                            "json" | "json_api_v1" => "JSON_API_V1".to_string(),
                            "none" => "NONE".to_string(),
                            _ => {
                                return Err(GsutilError::command(format!(
                                    "Payload format must be \"json\" or \"none\", got \"{fmt}\"."
                                )));
                            }
                        };
                    }
                    "-e" => {
                        i += 1;
                        event_types.push(
                            args.get(i)
                                .ok_or_else(|| {
                                    GsutilError::command("Option -e requires an event type.")
                                })?
                                .clone(),
                        );
                    }
                    "-m" => {
                        i += 1;
                        let kv = args
                            .get(i)
                            .ok_or_else(|| GsutilError::command("Option -m requires key:value."))?;
                        let (k, v) = kv.split_once(':').ok_or_else(|| {
                            GsutilError::command(format!(
                                "Custom attribute \"{kv}\" must be of the form key:value."
                            ))
                        })?;
                        custom_attrs.insert(k.to_string(), v.to_string());
                    }
                    "-p" => {
                        i += 1;
                        prefix = Some(
                            args.get(i)
                                .ok_or_else(|| {
                                    GsutilError::command("Option -p requires an object prefix.")
                                })?
                                .clone(),
                        );
                    }
                    "-s" => {} // skip topic creation (handled at Pub/Sub layer)
                    other => url_args.push(other.to_string()),
                }
                i += 1;
            }
            let buckets = expand_bucket_urls(ctx, &url_args, "notification").await?;
            let b = &buckets[0];
            let bname = b.bucket_name.as_deref().unwrap_or("");
            let pubsub_topic = topic.unwrap_or_else(|| {
                let proj = ctx.effective_project_id().unwrap_or("default");
                format!("projects/{proj}/topics/{bname}")
            });
            let opts = CreateNotificationOptions {
                pubsub_topic,
                payload_format,
                event_types: if event_types.is_empty() {
                    None
                } else {
                    Some(event_types)
                },
                custom_attributes: if custom_attrs.is_empty() {
                    None
                } else {
                    Some(custom_attrs)
                },
                object_name_prefix: prefix,
            };
            let created = ctx.api.create_notification_config(bname, &opts).await?;
            writeln!(
                ctx.out,
                "Created notification config {}",
                created.self_link.or(created.id).unwrap_or_default()
            )?;
            Ok(())
        }
        "list" => {
            let buckets = expand_bucket_urls(ctx, &args[1..], "notification").await?;
            for b in buckets {
                let bname = b.bucket_name.as_deref().unwrap_or("");
                let configs = ctx.api.list_notification_configs(bname).await?;
                for n in configs {
                    let id = n.id.as_deref().unwrap_or("");
                    writeln!(
                        ctx.out,
                        "projects/_/buckets/{bname}/notificationConfigs/{id}"
                    )?;
                    if let Some(ref topic) = n.topic {
                        writeln!(ctx.out, "\tCloud Pub/Sub topic: {topic}")?;
                    }
                    if let Some(ref attrs) = n.custom_attributes {
                        if !attrs.is_empty() {
                            writeln!(ctx.out, "\tCustom attributes:")?;
                            for (k, v) in attrs {
                                writeln!(ctx.out, "\t\t{k}: {v}")?;
                            }
                        }
                    }
                    if let Some(ref events) = n.event_types {
                        if !events.is_empty() {
                            writeln!(ctx.out, "\tFilters:")?;
                            writeln!(ctx.out, "\t\tEvent Types: {}", events.join(", "))?;
                        }
                    }
                    if let Some(ref pfx) = n.object_name_prefix {
                        writeln!(ctx.out, "\t\tObject name prefix: '{pfx}'")?;
                    }
                }
            }
            Ok(())
        }
        "delete" => {
            if args.len() < 2 {
                return Err(GsutilError::command(
                    "notification delete requires at least one notification config or bucket URL.",
                ));
            }
            for target in &args[1..] {
                if let Some((bname, nid)) = parse_notification_config_path(target) {
                    ctx.api.delete_notification_config(bname, nid).await?;
                } else {
                    // Delete all notifications on the bucket.
                    let buckets =
                        expand_bucket_urls(ctx, std::slice::from_ref(target), "notification")
                            .await?;
                    for b in buckets {
                        let bname = b.bucket_name.as_deref().unwrap_or("");
                        let configs = ctx.api.list_notification_configs(bname).await?;
                        for n in configs {
                            if let Some(id) = n.id {
                                ctx.api.delete_notification_config(bname, &id).await?;
                            }
                        }
                    }
                }
            }
            Ok(())
        }
        "watchbucket" => {
            let mut channel_id: Option<String> = None;
            let mut token: Option<String> = None;
            let mut positional = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-i" => {
                        i += 1;
                        channel_id = Some(
                            args.get(i)
                                .ok_or_else(|| {
                                    GsutilError::command("Option -i requires a channel ID.")
                                })?
                                .clone(),
                        );
                    }
                    "-t" => {
                        i += 1;
                        token = Some(
                            args.get(i)
                                .ok_or_else(|| GsutilError::command("Option -t requires a token."))?
                                .clone(),
                        );
                    }
                    other => positional.push(other.to_string()),
                }
                i += 1;
            }
            if positional.len() < 2 {
                return Err(GsutilError::command(
                    "notification watchbucket requires <app_url> and <bucket_url>.",
                ));
            }
            let app_url = &positional[0];
            let buckets =
                expand_bucket_urls(ctx, &positional[1..], "notification watchbucket").await?;
            let bname = buckets[0].bucket_name.as_deref().unwrap_or("");
            let cid = channel_id.unwrap_or_else(|| format!("gsutil-channel-{bname}"));
            let ch = ctx
                .api
                .watch_bucket(bname, app_url, &cid, token.as_deref())
                .await?;
            writeln!(
                ctx.out,
                "Successfully set up watch notification channel for {}:\n  Channel identifier: {}\n  Resource identifier: {}",
                buckets[0].bucket_url_string(),
                ch.id.as_deref().unwrap_or(""),
                ch.resource_id.as_deref().unwrap_or("")
            )?;
            Ok(())
        }
        "stopchannel" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "notification stopchannel requires <channel_id> and <resource_id>.",
                ));
            }
            ctx.api.stop_channel(&args[1], &args[2]).await?;
            writeln!(
                ctx.out,
                "Successfully stopped channel {} (resource {})",
                args[1], args[2]
            )?;
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the notification command."
        ))),
    }
}

/// Parse `projects/_/buckets/<bucket>/notificationConfigs/<id>`.
fn parse_notification_config_path(s: &str) -> Option<(&str, &str)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() == 6
        && parts[0] == "projects"
        && parts[2] == "buckets"
        && parts[4] == "notificationConfigs"
    {
        Some((parts[3], parts[5]))
    } else {
        None
    }
}
