//! `acl` (`get|set|ch`) and `defacl` (`get|set|ch`) command handlers.
//!
//! Matches `gslib/commands/acl.py` and `gslib/commands/defacl.py`.

use gsutil_core::api::{Bucket, BucketAccessControl, Object, ObjectAccessControl};
use gsutil_core::error::{GsutilError, Result};

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
    Grant { entity: String, role: String },
    Delete { entity: String },
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

fn normalize_acl_entity(flag: &str, raw_id: &str) -> String {
    let lower = raw_id.to_ascii_lowercase();
    if lower == "allusers" || lower == "all" {
        return "allUsers".to_string();
    }
    if lower == "allauthenticatedusers" || lower == "allauth" {
        return "allAuthenticatedUsers".to_string();
    }
    match flag {
        "-u" => {
            if raw_id.starts_with("user-") {
                raw_id.to_string()
            } else {
                format!("user-{raw_id}")
            }
        }
        "-g" => {
            if raw_id.starts_with("group-") || raw_id.starts_with("domain-") {
                raw_id.to_string()
            } else if raw_id.contains('@') {
                format!("group-{raw_id}")
            } else {
                format!("domain-{raw_id}")
            }
        }
        "-p" => {
            if raw_id.starts_with("project-") {
                raw_id.to_string()
            } else {
                format!("project-{raw_id}")
            }
        }
        _ => raw_id.to_string(),
    }
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
        match args[i].as_str() {
            "-r" | "-R" => recursive = true,
            "-a" => all_versions = true,
            "-f" => continue_on_error = true,
            flag @ ("-u" | "-g" | "-p") => {
                i += 1;
                let spec = args.get(i).ok_or_else(|| {
                    GsutilError::command(format!("Option {flag} requires <entity>:<role>."))
                })?;
                let (id, role_str) = spec.rsplit_once(':').ok_or_else(|| {
                    GsutilError::command(format!(
                        "Invalid ACL change \"{spec}\"; expected <entity>:<role>."
                    ))
                })?;
                let entity = normalize_acl_entity(flag, id);
                let role = parse_acl_role(role_str)?;
                changes.push(AclChange::Grant { entity, role });
            }
            "-d" => {
                i += 1;
                let raw_id = args.get(i).ok_or_else(|| {
                    GsutilError::command("Option -d requires an entity identifier.")
                })?;
                let entity = normalize_acl_entity("-d", raw_id);
                changes.push(AclChange::Delete { entity });
            }
            other => url_args.push(other.to_string()),
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
            AclChange::Grant { entity, role } => {
                if let Some(existing) = acl
                    .iter_mut()
                    .find(|e| e.entity.as_deref() == Some(entity.as_str()))
                {
                    existing.role = Some(role.clone());
                } else {
                    acl.push(BucketAccessControl {
                        entity: Some(entity.clone()),
                        role: Some(role.clone()),
                        ..Default::default()
                    });
                }
            }
            AclChange::Delete { entity } => {
                acl.retain(|e| {
                    let matches_entity = e.entity.as_deref() == Some(entity.as_str());
                    let matches_email = e.email.as_deref() == Some(entity.as_str());
                    !(matches_entity || matches_email)
                });
            }
        }
    }
}

fn apply_object_acl_changes(acl: &mut Vec<ObjectAccessControl>, changes: &[AclChange]) {
    for ch in changes {
        match ch {
            AclChange::Grant { entity, role } => {
                if let Some(existing) = acl
                    .iter_mut()
                    .find(|e| e.entity.as_deref() == Some(entity.as_str()))
                {
                    existing.role = Some(role.clone());
                } else {
                    acl.push(ObjectAccessControl {
                        entity: Some(entity.clone()),
                        role: Some(role.clone()),
                        ..Default::default()
                    });
                }
            }
            AclChange::Delete { entity } => {
                acl.retain(|e| {
                    let matches_entity = e.entity.as_deref() == Some(entity.as_str());
                    let matches_email = e.email.as_deref() == Some(entity.as_str());
                    !(matches_entity || matches_email)
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
                    let meta = api.get_bucket(bname, None).await?;
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
                match arg.as_str() {
                    "-r" | "-R" => recursive = true,
                    "-a" => all_versions = true,
                    "-f" => continue_on_error = true,
                    other => positional.push(other.to_string()),
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
                Some(read_json_arg(acl_arg)?)
            } else {
                None
            };

            let urls = expand_cloud_urls(ctx, &positional[1..], recursive, all_versions).await?;
            let mut failed = false;
            for u in urls {
                let bname = u.bucket_name.as_deref().unwrap_or("");
                let res: Result<()> = if let Some(oname) = u.object_name.as_deref() {
                    let patch = if let Some(ref json) = raw_json {
                        let parsed: Vec<ObjectAccessControl> =
                            serde_json::from_str(json).map_err(|e| {
                                GsutilError::command(format!("Invalid object ACL JSON: {e}"))
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
                                GsutilError::command(format!("Invalid bucket ACL JSON: {e}"))
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
            let mut failed = false;
            for u in urls {
                let bname = u.bucket_name.as_deref().unwrap_or("");
                let res: Result<()> = if let Some(oname) = u.object_name.as_deref() {
                    let existing = ctx
                        .api
                        .get_object_metadata(bname, oname, u.generation.as_deref(), None)
                        .await?;
                    let mut acl = existing.acl.unwrap_or_default();
                    apply_object_acl_changes(&mut acl, &changes);
                    let patch = Object {
                        acl: Some(acl),
                        ..Default::default()
                    };
                    writeln!(ctx.err, "Updated ACL on {}", u.url_string())?;
                    ctx.api
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
                } else {
                    let existing = ctx.api.get_bucket(bname, None).await?;
                    let mut acl = existing.acl.unwrap_or_default();
                    apply_bucket_acl_changes(&mut acl, &changes);
                    let patch = Bucket {
                        acl: Some(acl),
                        ..Default::default()
                    };
                    writeln!(ctx.err, "Updated ACL on {}", u.bucket_url_string())?;
                    ctx.api
                        .patch_bucket(bname, &patch, None, None, None, None)
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
                let raw = read_json_arg(acl_arg)?;
                let parsed: Vec<ObjectAccessControl> = serde_json::from_str(&raw).map_err(|e| {
                    GsutilError::command(format!("Invalid default object ACL JSON: {e}"))
                })?;
                Some(parsed)
            } else {
                None
            };
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
            let buckets = expand_bucket_urls(ctx, &url_args, "defacl").await?;
            let mut failed = false;
            for b in buckets {
                let name = b.bucket_name.as_deref().unwrap_or("");
                let res: Result<()> = async {
                    let existing = ctx.api.get_bucket(name, None).await?;
                    let mut def_acl = existing.default_object_acl.unwrap_or_default();
                    apply_object_acl_changes(&mut def_acl, &changes);
                    let patch = Bucket {
                        default_object_acl: Some(def_acl),
                        ..Default::default()
                    };
                    writeln!(ctx.err, "Updated default ACL on {}", b.bucket_url_string())?;
                    ctx.api
                        .patch_bucket(name, &patch, None, None, None, None)
                        .await
                        .map(|_| ())
                }
                .await;
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
