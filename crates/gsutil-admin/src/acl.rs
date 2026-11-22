//! `acl` (`get|set|ch`) and `defacl` (`get|set|ch`) command handlers.
//!
//! Matches `gslib/commands/acl.py` and `gslib/commands/defacl.py`.

use gsutil_core::api::{Bucket, BucketAccessControl, Object, ObjectAccessControl, ProjectTeam};
use gsutil_core::error::{GsutilError, Result, ServiceError};
use gsutil_core::url::{CloudScheme, StorageUrl};

use crate::{expand_bucket_urls, expand_cloud_urls, read_json_arg, AdminContext};

const CANNED_ACLS: &[&str] = &[
    "authenticated-read",
    "authenticatedRead",
    "bucket-owner-full-control",
    "bucketOwnerFullControl",
    "bucket-owner-read",
    "bucketOwnerRead",
    "private",
    "project-private",
    "projectPrivate",
    "public-read",
    "publicRead",
    "public-read-write",
    "publicReadWrite",
];

fn normalize_canned_acl(acl: &str) -> Option<&'static str> {
    match acl {
        "authenticated-read" | "authenticatedRead" => Some("authenticatedRead"),
        "bucket-owner-full-control" | "bucketOwnerFullControl" => Some("bucketOwnerFullControl"),
        "bucket-owner-read" | "bucketOwnerRead" => Some("bucketOwnerRead"),
        "private" => Some("private"),
        "project-private" | "projectPrivate" => Some("projectPrivate"),
        "public-read" | "publicRead" => Some("publicRead"),
        "public-read-write" | "publicReadWrite" => Some("publicReadWrite"),
        _ => None,
    }
}

fn is_canned_acl(s: &str) -> bool {
    CANNED_ACLS.contains(&s)
}

#[derive(Debug, Clone)]
enum AclChange {
    Grant {
        entity: Option<String>,
        entity_id: Option<String>,
        project_team: Option<ProjectTeam>,
        role: String,
    },
    Delete {
        raw_id: String,
        entity: String,
    },
}

fn is_canonical_hex_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_acl_role(r: &str) -> Result<String> {
    match r.to_ascii_uppercase().as_str() {
        "R" | "READ" | "READER" => Ok("READER".to_string()),
        "W" | "WRITE" | "WRITER" => Ok("WRITER".to_string()),
        "O" | "FC" | "FULL_CONTROL" | "OWNER" => Ok("OWNER".to_string()),
        _ => Err(GsutilError::command(format!(
            "Invalid ACL permission \"{r}\"; expected R/READER, W/WRITER, or O/OWNER."
        ))),
    }
}

fn parse_acl_grant(flag: &str, raw_id: &str, role: String) -> AclChange {
    let lower = raw_id.to_ascii_lowercase();
    if lower == "allusers" || lower == "all" {
        return AclChange::Grant {
            entity: Some("allUsers".to_string()),
            entity_id: None,
            project_team: None,
            role,
        };
    }
    if lower == "allauthenticatedusers" || lower == "allauth" {
        return AclChange::Grant {
            entity: Some("allAuthenticatedUsers".to_string()),
            entity_id: None,
            project_team: None,
            role,
        };
    }
    match flag {
        "-u" => {
            if is_canonical_hex_id(raw_id) {
                AclChange::Grant {
                    entity: Some(format!("user-{raw_id}")),
                    entity_id: Some(raw_id.to_string()),
                    project_team: None,
                    role,
                }
            } else {
                let entity = if raw_id.starts_with("user-") {
                    raw_id.to_string()
                } else {
                    format!("user-{raw_id}")
                };
                AclChange::Grant {
                    entity: Some(entity),
                    entity_id: None,
                    project_team: None,
                    role,
                }
            }
        }
        "-g" => {
            if is_canonical_hex_id(raw_id) {
                AclChange::Grant {
                    entity: Some(format!("group-{raw_id}")),
                    entity_id: Some(raw_id.to_string()),
                    project_team: None,
                    role,
                }
            } else if raw_id.starts_with("group-") || raw_id.starts_with("domain-") {
                AclChange::Grant {
                    entity: Some(raw_id.to_string()),
                    entity_id: None,
                    project_team: None,
                    role,
                }
            } else if raw_id.contains('@') {
                AclChange::Grant {
                    entity: Some(format!("group-{raw_id}")),
                    entity_id: None,
                    project_team: None,
                    role,
                }
            } else {
                AclChange::Grant {
                    entity: Some(format!("domain-{raw_id}")),
                    entity_id: None,
                    project_team: None,
                    role,
                }
            }
        }
        "-p" => {
            let trimmed = raw_id.strip_prefix("project-").unwrap_or(raw_id);
            let entity = format!("project-{trimmed}");
            let project_team = trimmed.split_once('-').map(|(team, proj)| ProjectTeam {
                project_number: Some(proj.to_string()),
                team: Some(team.to_string()),
            });
            AclChange::Grant {
                entity: Some(entity),
                entity_id: None,
                project_team,
                role,
            }
        }
        _ => AclChange::Grant {
            entity: Some(raw_id.to_string()),
            entity_id: None,
            project_team: None,
            role,
        },
    }
}

fn normalize_delete_entity(raw_id: &str) -> String {
    let lower = raw_id.to_ascii_lowercase();
    if lower == "allusers" || lower == "all" {
        return "allUsers".to_string();
    }
    if lower == "allauthenticatedusers" || lower == "allauth" {
        return "allAuthenticatedUsers".to_string();
    }
    raw_id.to_string()
}

fn matches_delete_target(
    entry_entity: Option<&str>,
    entry_email: Option<&str>,
    entry_id: Option<&str>,
    raw_id: &str,
    normalized: &str,
) -> bool {
    if entry_entity == Some(normalized) || entry_entity == Some(raw_id) {
        return true;
    }
    if entry_email == Some(raw_id) || entry_email == Some(normalized) {
        return true;
    }
    if entry_id == Some(raw_id) || entry_id == Some(normalized) {
        return true;
    }
    if let Some(ent) = entry_entity {
        for prefix in ["user-", "group-", "domain-", "project-"] {
            if let Some(stripped) = ent.strip_prefix(prefix) {
                if stripped.eq_ignore_ascii_case(raw_id)
                    || stripped.eq_ignore_ascii_case(normalized)
                {
                    return true;
                }
            }
        }
    }
    false
}

struct ParsedAclCh {
    changes: Vec<AclChange>,
    url_args: Vec<String>,
    recursive: bool,
    all_versions: bool,
    continue_on_error: bool,
}

fn parse_acl_ch_args(args: &[String]) -> Result<ParsedAclCh> {
    let mut changes = Vec::new();
    let mut url_args = Vec::new();
    let mut recursive = false;
    let mut all_versions = false;
    let mut continue_on_error = false;
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();
        if matches!(arg, "-u" | "-g" | "-p") {
            let flag = arg;
            i += 1;
            let spec = args.get(i).ok_or_else(|| {
                GsutilError::command(format!("Option {flag} requires <entity>:<role>."))
            })?;
            let (id, role_str) = spec.rsplit_once(':').ok_or_else(|| {
                GsutilError::command(format!(
                    "Invalid ACL change \"{spec}\"; expected <entity>:<role>."
                ))
            })?;
            let role = parse_acl_role(role_str)?;
            if matches!(flag, "-u" | "-g")
                && id.contains('@')
                && id
                    .chars()
                    .any(|c| matches!(c, '$' | '!' | '#' | '%' | '^' | '&' | '*' | '(' | ')' | ' '))
            {
                return Err(GsutilError::Service(ServiceError::bad_request(
                    "Invalid entity",
                    Some(400),
                    Some(format!("Invalid entity email: {id}")),
                )));
            }
            changes.push(parse_acl_grant(flag, id, role));
        } else if arg == "-d" {
            i += 1;
            let raw_id = args
                .get(i)
                .ok_or_else(|| GsutilError::command("Option -d requires an entity identifier."))?;
            let entity = normalize_delete_entity(raw_id);
            changes.push(AclChange::Delete {
                raw_id: raw_id.clone(),
                entity,
            });
        } else if arg.starts_with('-')
            && arg.len() > 1
            && arg[1..]
                .bytes()
                .all(|b| matches!(b, b'r' | b'R' | b'a' | b'f'))
        {
            for ch in arg[1..].chars() {
                match ch {
                    'r' | 'R' => recursive = true,
                    'a' => all_versions = true,
                    'f' => continue_on_error = true,
                    _ => {}
                }
            }
        } else {
            url_args.push(arg.to_string());
        }
        i += 1;
    }

    if changes.is_empty() {
        return Err(GsutilError::command(
            "Please specify at least one ACL change (-u, -g, -p, or -d).",
        ));
    }

    Ok(ParsedAclCh {
        changes,
        url_args,
        recursive,
        all_versions,
        continue_on_error,
    })
}

fn apply_bucket_acl_changes(acl: &mut Vec<BucketAccessControl>, changes: &[AclChange]) {
    for ch in changes {
        match ch {
            AclChange::Grant {
                entity,
                entity_id,
                project_team,
                role,
            } => {
                let existing = acl.iter_mut().find(|e| {
                    (entity.is_some() && e.entity == *entity)
                        || (entity_id.is_some() && e.entity_id == *entity_id)
                });
                if let Some(ex) = existing {
                    ex.role = Some(role.clone());
                } else {
                    acl.push(BucketAccessControl {
                        entity: entity.clone(),
                        entity_id: entity_id.clone(),
                        project_team: project_team.clone(),
                        role: Some(role.clone()),
                        ..Default::default()
                    });
                }
            }
            AclChange::Delete { raw_id, entity } => {
                acl.retain(|e| {
                    !matches_delete_target(
                        e.entity.as_deref(),
                        e.email.as_deref(),
                        e.entity_id.as_deref(),
                        raw_id,
                        entity,
                    )
                });
            }
        }
    }
}

fn apply_object_acl_changes(
    acl: &mut Vec<ObjectAccessControl>,
    changes: &[AclChange],
    target_url: &str,
    err: &mut dyn std::io::Write,
) {
    for ch in changes {
        match ch {
            AclChange::Grant {
                entity,
                entity_id,
                project_team,
                role,
            } => {
                if role == "WRITER" {
                    let who = entity
                        .as_deref()
                        .or(entity_id.as_deref())
                        .unwrap_or("entity");
                    let _ = writeln!(
                        err,
                        "Skipping {who}:WRITER on {target_url}, as WRITER does not apply to objects."
                    );
                    continue;
                }
                let existing = acl.iter_mut().find(|e| {
                    (entity.is_some() && e.entity == *entity)
                        || (entity_id.is_some() && e.entity_id == *entity_id)
                });
                if let Some(ex) = existing {
                    ex.role = Some(role.clone());
                } else {
                    acl.push(ObjectAccessControl {
                        entity: entity.clone(),
                        entity_id: entity_id.clone(),
                        project_team: project_team.clone(),
                        role: Some(role.clone()),
                        ..Default::default()
                    });
                }
            }
            AclChange::Delete { raw_id, entity } => {
                acl.retain(|e| {
                    !matches_delete_target(
                        e.entity.as_deref(),
                        e.email.as_deref(),
                        e.entity_id.as_deref(),
                        raw_id,
                        entity,
                    )
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// acl (get | set | ch)
// ---------------------------------------------------------------------------

pub async fn run_acl(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "acl requires a subcommand (get|set|ch) and arguments.",
        ));
    }
    match args[0].as_str() {
        "get" => {
            let urls = expand_cloud_urls(ctx, &args[1..], false, false).await?;
            for u in urls {
                let bname = u.bucket_name.as_deref().unwrap_or("");
                let api = ctx.api.for_provider(u.scheme.as_str())?;
                if let Some(oname) = u.object_name.as_deref() {
                    let meta = api
                        .get_object_metadata(bname, oname, u.generation.as_deref(), None)
                        .await?;
                    let mut acl = meta.acl.unwrap_or_default();
                    for entry in &mut acl {
                        entry.kind = None;
                        entry.id = None;
                        entry.bucket = None;
                        entry.object = None;
                        entry.generation = None;
                        entry.etag = None;
                    }
                    let val = serde_json::to_value(&acl).map_err(|e| {
                        GsutilError::command(format!("Failed to serialize ACL: {e}"))
                    })?;
                    let json = serde_json::to_string_pretty(&val).map_err(|e| {
                        GsutilError::command(format!("Failed to serialize ACL: {e}"))
                    })?;
                    writeln!(ctx.out, "{json}")?;
                } else {
                    let meta = api
                        .get_bucket(
                            bname,
                            Some(&["acl".to_string(), "iamConfiguration".to_string()]),
                        )
                        .await?;
                    let ubla_enabled = meta
                        .iam_configuration
                        .as_ref()
                        .and_then(|ic| {
                            ic.uniform_bucket_level_access
                                .as_ref()
                                .and_then(|u| u.enabled)
                                .or_else(|| ic.bucket_policy_only.as_ref().and_then(|b| b.enabled))
                        })
                        .unwrap_or(false);
                    if ubla_enabled {
                        return Err(gsutil_core::error::ServiceError::bad_request(
                            "Cannot get legacy ACL for a bucket that has uniform bucket-level access. Read more at https://cloud.google.com/storage/docs/uniform-bucket-level-access",
                            Some(400),
                            None,
                        )
                        .into());
                    }
                    let mut acl = meta.acl.unwrap_or_default();
                    for entry in &mut acl {
                        entry.kind = None;
                        entry.id = None;
                        entry.bucket = None;
                        entry.etag = None;
                    }
                    let val = serde_json::to_value(&acl).map_err(|e| {
                        GsutilError::command(format!("Failed to serialize ACL: {e}"))
                    })?;
                    let json = serde_json::to_string_pretty(&val).map_err(|e| {
                        GsutilError::command(format!("Failed to serialize ACL: {e}"))
                    })?;
                    writeln!(ctx.out, "{json}")?;
                }
            }
            Ok(())
        }
        "set" => {
            let mut recursive = false;
            let mut all_versions = false;
            let mut continue_on_error = false;
            let mut positional = Vec::new();
            for arg in &args[1..] {
                let s = arg.as_str();
                if s.starts_with('-')
                    && s.len() > 1
                    && s[1..]
                        .bytes()
                        .all(|b| matches!(b, b'r' | b'R' | b'a' | b'f'))
                {
                    for ch in s[1..].chars() {
                        match ch {
                            'r' | 'R' => recursive = true,
                            'a' => all_versions = true,
                            'f' => continue_on_error = true,
                            _ => {}
                        }
                    }
                } else {
                    positional.push(arg.clone());
                }
            }
            if positional.len() < 2 {
                return Err(GsutilError::command(
                    "acl set requires <file-or-canned-acl> and at least one URL.",
                ));
            }
            let acl_arg = &positional[0];
            let canned = if is_canned_acl(acl_arg) {
                normalize_canned_acl(acl_arg)
            } else {
                None
            };
            let raw_json = if canned.is_none() {
                if acl_arg != "-"
                    && !std::path::Path::new(acl_arg).exists()
                    && !acl_arg.contains('/')
                    && !acl_arg.contains('\\')
                    && !acl_arg.contains('.')
                {
                    return Err(GsutilError::command(format!(
                        "Invalid canned ACL \"{acl_arg}\"."
                    )));
                }
                let raw = read_json_arg(acl_arg)?;
                if raw.trim_start().starts_with('<') {
                    return Err(GsutilError::argument(
                        "XML ACL data provided; please convert to JSON format.",
                    ));
                }
                Some(raw)
            } else {
                None
            };

            let urls = expand_cloud_urls(ctx, &positional[1..], recursive, all_versions).await?;
            ctx.maybe_report_seek_ahead(urls.len())?;
            let mut failed = false;
            for u in urls {
                let bname = u.bucket_name.as_deref().unwrap_or("");
                let res: Result<()> = if let Some(oname) = u.object_name.as_deref() {
                    let patch = if let Some(ref json) = raw_json {
                        let parsed: Vec<ObjectAccessControl> =
                            serde_json::from_str(json).map_err(|e| {
                                GsutilError::argument(format!("Invalid object ACL JSON: {e}"))
                            })?;
                        Object {
                            acl: Some(parsed),
                            ..Default::default()
                        }
                    } else {
                        Object::default()
                    };
                    writeln!(ctx.err, "Setting ACL on {}...", u.url_string())?;
                    ctx.api
                        .patch_object_metadata(
                            bname,
                            oname,
                            &patch,
                            canned,
                            u.generation.as_deref(),
                            None,
                            None,
                        )
                        .await
                        .map(|_| ())
                } else {
                    let patch = if let Some(ref json) = raw_json {
                        let parsed: Vec<BucketAccessControl> =
                            serde_json::from_str(json).map_err(|e| {
                                GsutilError::argument(format!("Invalid bucket ACL JSON: {e}"))
                            })?;
                        Bucket {
                            acl: Some(parsed),
                            ..Default::default()
                        }
                    } else {
                        Bucket::default()
                    };
                    writeln!(ctx.err, "Setting ACL on {}...", u.bucket_url_string())?;
                    ctx.api
                        .patch_bucket(bname, &patch, canned, None, None, None)
                        .await
                        .map(|_| ())
                };
                if let Err(e) = res {
                    if continue_on_error {
                        writeln!(ctx.err, "{e}")?;
                        failed = true;
                    } else {
                        return Err(e);
                    }
                }
            }
            if failed {
                return Err(GsutilError::command(
                    "Some ACL updates failed; see stderr for details.",
                ));
            }
            Ok(())
        }
        "ch" => {
            let ParsedAclCh {
                changes,
                url_args,
                recursive,
                all_versions,
                continue_on_error,
            } = parse_acl_ch_args(&args[1..])?;
            let urls = expand_cloud_urls(ctx, &url_args, recursive, all_versions).await?;
            ctx.maybe_report_seek_ahead(urls.len())?;
            let mut failed = false;
            for u in urls {
                let bname = u.bucket_name.as_deref().unwrap_or("");
                let u_str = u.url_string();
                let res: Result<()> = if let Some(oname) = u.object_name.as_deref() {
                    match ctx
                        .api
                        .for_provider(u.scheme.as_str())?
                        .get_object_metadata(bname, oname, u.generation.as_deref(), None)
                        .await
                    {
                        Ok(existing) => {
                            let mut acl = existing.acl.unwrap_or_default();
                            apply_object_acl_changes(&mut acl, &changes, &u_str, ctx.err);
                            let patch = Object {
                                acl: Some(acl),
                                ..Default::default()
                            };
                            writeln!(ctx.err, "Updated ACL on {u_str}")?;
                            ctx.api
                                .for_provider(u.scheme.as_str())?
                                .patch_object_metadata(
                                    bname,
                                    oname,
                                    &patch,
                                    None,
                                    u.generation.as_deref(),
                                    None,
                                    None,
                                )
                                .await
                                .map(|_| ())
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    match ctx
                        .api
                        .for_provider(u.scheme.as_str())?
                        .get_bucket(bname, None)
                        .await
                    {
                        Ok(existing) => {
                            let mut acl = existing.acl.unwrap_or_default();
                            apply_bucket_acl_changes(&mut acl, &changes);
                            let patch = Bucket {
                                acl: Some(acl),
                                ..Default::default()
                            };
                            writeln!(ctx.err, "Updated ACL on {}", u.bucket_url_string())?;
                            ctx.api
                                .for_provider(u.scheme.as_str())?
                                .patch_bucket(bname, &patch, None, None, None, None)
                                .await
                                .map(|_| ())
                        }
                        Err(e) => Err(e),
                    }
                };
                if let Err(e) = res {
                    if continue_on_error {
                        writeln!(ctx.err, "{e}")?;
                        failed = true;
                    } else {
                        return Err(e);
                    }
                }
            }
            if failed {
                return Err(GsutilError::command(
                    "Some ACL updates failed; see stderr for details.",
                ));
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the acl command."
        ))),
    }
}

// ---------------------------------------------------------------------------
// defacl (get | set | ch)
// ---------------------------------------------------------------------------

pub async fn run_defacl(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "defacl requires a subcommand (get|set|ch) and arguments.",
        ));
    }
    match args[0].as_str() {
        "get" => {
            for raw in &args[1..] {
                match StorageUrl::parse(raw)? {
                    StorageUrl::Cloud(c) if c.is_bucket() => {
                        if c.scheme != CloudScheme::Gs {
                            return Err(GsutilError::command(
                                "The defacl command can only be used with gs:// URLs.",
                            ));
                        }
                    }
                    _ => {
                        return Err(GsutilError::command(format!(
                            "URL must name a bucket for the defacl command: {raw}"
                        )));
                    }
                }
            }
            let buckets = expand_bucket_urls(ctx, &args[1..], "defacl").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let meta = ctx
                    .api
                    .for_provider(b.scheme.as_str())?
                    .get_bucket(name, None)
                    .await?;
                let mut def_acl = meta.default_object_acl.unwrap_or_default();
                for entry in &mut def_acl {
                    entry.kind = None;
                    entry.id = None;
                    entry.bucket = None;
                    entry.object = None;
                    entry.generation = None;
                    entry.etag = None;
                }
                let val = serde_json::to_value(&def_acl).map_err(|e| {
                    GsutilError::command(format!("Failed to serialize default object ACL: {e}"))
                })?;
                let json = serde_json::to_string_pretty(&val).map_err(|e| {
                    GsutilError::command(format!("Failed to serialize default object ACL: {e}"))
                })?;
                writeln!(ctx.out, "{json}")?;
            }
            Ok(())
        }
        "set" => {
            if args.len() < 3 {
                return Err(GsutilError::command(
                    "defacl set requires <file-or-canned-acl> and at least one bucket URL.",
                ));
            }
            let acl_arg = &args[1];
            let canned = if is_canned_acl(acl_arg) {
                normalize_canned_acl(acl_arg)
            } else {
                None
            };
            let parsed_acl = if canned.is_none() {
                if acl_arg != "-"
                    && !std::path::Path::new(acl_arg).exists()
                    && !acl_arg.contains('/')
                    && !acl_arg.contains('\\')
                    && !acl_arg.contains('.')
                {
                    return Err(GsutilError::command(format!(
                        "Invalid canned ACL \"{acl_arg}\"."
                    )));
                }
                let raw = read_json_arg(acl_arg)?;
                if raw.trim_start().starts_with('<') {
                    return Err(GsutilError::argument(
                        "XML ACL data provided; please convert to JSON format.",
                    ));
                }
                let parsed: Vec<ObjectAccessControl> = serde_json::from_str(&raw).map_err(|e| {
                    GsutilError::argument(format!("Invalid default object ACL JSON: {e}"))
                })?;
                Some(parsed)
            } else {
                None
            };
            for raw in &args[2..] {
                match StorageUrl::parse(raw)? {
                    StorageUrl::Cloud(c) if c.is_bucket() => {
                        if c.scheme != CloudScheme::Gs {
                            return Err(GsutilError::command(
                                "The defacl command can only be used with gs:// URLs.",
                            ));
                        }
                    }
                    _ => {
                        return Err(GsutilError::command(format!(
                            "URL must name a bucket for the defacl command: {raw}"
                        )));
                    }
                }
            }
            let buckets = expand_bucket_urls(ctx, &args[2..], "defacl").await?;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                writeln!(
                    ctx.err,
                    "Setting default object ACL on {}...",
                    b.bucket_url_string()
                )?;
                let patch = Bucket {
                    default_object_acl: parsed_acl.clone(),
                    ..Default::default()
                };
                ctx.api
                    .patch_bucket(name, &patch, None, canned, None, None)
                    .await?;
            }
            Ok(())
        }
        "ch" => {
            let ParsedAclCh {
                changes,
                url_args,
                continue_on_error,
                ..
            } = parse_acl_ch_args(&args[1..])?;
            for ch in &changes {
                if let AclChange::Grant { role, .. } = ch {
                    if role == "WRITER" {
                        return Err(GsutilError::command(
                            "WRITER cannot be set as a default object ACL.",
                        ));
                    }
                }
            }
            for raw in &url_args {
                match StorageUrl::parse(raw)? {
                    StorageUrl::Cloud(c) if c.is_bucket() => {
                        if c.scheme != CloudScheme::Gs {
                            return Err(GsutilError::command(
                                "The defacl command can only be used with gs:// URLs.",
                            ));
                        }
                    }
                    _ => {
                        return Err(GsutilError::command(format!(
                            "defacl ch can only be applied to buckets, got: {raw}"
                        )));
                    }
                }
            }
            let buckets = expand_bucket_urls(ctx, &url_args, "defacl").await?;
            let mut failed = false;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let b_str = b.bucket_url_string();
                let res: Result<()> = match ctx
                    .api
                    .for_provider(b.scheme.as_str())?
                    .get_bucket(name, None)
                    .await
                {
                    Ok(existing) => {
                        let mut def_acl = existing.default_object_acl.unwrap_or_default();
                        apply_object_acl_changes(&mut def_acl, &changes, &b_str, ctx.err);
                        let patch = Bucket {
                            default_object_acl: Some(def_acl),
                            ..Default::default()
                        };
                        writeln!(ctx.err, "Updated default ACL on {b_str}")?;
                        ctx.api
                            .for_provider(b.scheme.as_str())?
                            .patch_bucket(name, &patch, None, None, None, None)
                            .await
                            .map(|_| ())
                    }
                    Err(e) => Err(e),
                };
                if let Err(e) = res {
                    if continue_on_error {
                        writeln!(ctx.err, "{e}")?;
                        failed = true;
                    } else {
                        return Err(e);
                    }
                }
            }
            if failed {
                return Err(GsutilError::command(
                    "Some default ACL updates failed; see stderr for details.",
                ));
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the defacl command."
        ))),
    }
}
