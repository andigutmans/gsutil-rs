//! `iam` (`get|set|ch`) command handler.
//!
//! Matches `gslib/commands/iam.py` including `IamChOnResourceWithConditionsException`.

use gsutil_core::api::{IamBinding, IamPolicy};
use gsutil_core::error::{GsutilError, Result};

use crate::{expand_cloud_urls, read_json_arg, AdminContext};

#[derive(Debug, Clone)]
struct IamGrantSpec {
    is_delete: bool,
    member: String,
    roles: Vec<String>,
}

fn normalize_role(role: &str) -> String {
    if role.starts_with("roles/")
        || role.starts_with("projects/")
        || role.starts_with("organizations/")
    {
        role.to_string()
    } else {
        format!("roles/storage.{role}")
    }
}

/// Parse an `iam ch` binding spec like `allUsers:objectViewer`, `user:alice@example.com:roles/storage.admin`,
/// or `user:alice@example.com` (for `-d` all roles).
fn parse_iam_spec(spec: &str, is_delete: bool) -> Result<IamGrantSpec> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.is_empty() {
        return Err(GsutilError::command(format!(
            "Invalid IAM binding specification: \"{spec}\""
        )));
    }

    let (member, role_str_opt) = match parts[0] {
        "allUsers" | "allAuthenticatedUsers" => {
            if parts.len() == 1 && is_delete {
                (parts[0].to_string(), None)
            } else if parts.len() >= 2 {
                (parts[0].to_string(), Some(parts[1..].join(":")))
            } else {
                return Err(GsutilError::command(format!(
                    "IAM grant \"{spec}\" must include at least one role."
                )));
            }
        }
        "user" | "serviceAccount" | "group" | "domain" | "projectOwner" | "projectEditor"
        | "projectViewer" => {
            if !is_delete && matches!(parts[0], "projectOwner" | "projectEditor" | "projectViewer")
            {
                return Err(GsutilError::command(format!(
                    "Granting {} bindings is not supported by iam ch.",
                    parts[0]
                )));
            }
            if parts.len() < 2 {
                return Err(GsutilError::command(format!(
                    "Invalid IAM member \"{spec}\": missing identifier."
                )));
            }
            let member = format!("{}:{}", parts[0], parts[1]);
            if parts.len() == 2 {
                if is_delete {
                    (member, None)
                } else {
                    return Err(GsutilError::command(format!(
                        "IAM grant \"{spec}\" must include at least one role."
                    )));
                }
            } else {
                (member, Some(parts[2..].join(":")))
            }
        }
        other => {
            return Err(GsutilError::command(format!(
                "Invalid IAM member type \"{other}\" in \"{spec}\"."
            )));
        }
    };

    let roles = match role_str_opt {
        Some(rs) => rs
            .split(',')
            .filter(|r| !r.is_empty())
            .map(normalize_role)
            .collect(),
        None => Vec::new(),
    };

    Ok(IamGrantSpec {
        is_delete,
        member,
        roles,
    })
}

fn apply_iam_changes(
    policy: &mut IamPolicy,
    specs: &[IamGrantSpec],
    resource_url: &str,
) -> Result<()> {
    // Match gslib/commands/iam.py: refuse `iam ch` on resources with conditional bindings.
    if policy.bindings.iter().any(|b| b.condition.is_some()) {
        return Err(GsutilError::IamChOnResourceWithConditions(format!(
            "Command running on {resource_url} cannot edit IAM policies with conditions. \
             Please use \"gsutil iam get\" and \"gsutil iam set\" instead."
        )));
    }

    for spec in specs {
        if spec.is_delete {
            if spec.roles.is_empty() {
                // Remove member from all bindings.
                for b in &mut policy.bindings {
                    b.members.retain(|m| m != &spec.member);
                }
            } else {
                for role in &spec.roles {
                    for b in &mut policy.bindings {
                        if &b.role == role {
                            b.members.retain(|m| m != &spec.member);
                        }
                    }
                }
            }
            policy.bindings.retain(|b| !b.members.is_empty());
        } else {
            for role in &spec.roles {
                if let Some(binding) = policy.bindings.iter_mut().find(|b| &b.role == role) {
                    if !binding.members.iter().any(|m| m == &spec.member) {
                        binding.members.push(spec.member.clone());
                    }
                } else {
                    policy.bindings.push(IamBinding {
                        role: role.clone(),
                        members: vec![spec.member.clone()],
                        condition: None,
                    });
                }
            }
        }
    }

    Ok(())
}

pub async fn run_iam(ctx: &mut AdminContext<'_>, args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "iam requires a subcommand (get|set|ch) and arguments.",
        ));
    }
    match args[0].as_str() {
        "get" => {
            let urls = expand_cloud_urls(ctx, &args[1..], false, false).await?;
            if urls.len() != 1 {
                return Err(GsutilError::command(
                    "The iam get command must match a single cloud resource.",
                ));
            }
            let iam_fields = ["bindings".to_string(), "etag".to_string()];
            for u in urls {
                let bname = u.bucket_name.as_deref().unwrap_or("");
                let api = ctx.api.for_provider(u.scheme.as_str())?;
                let mut policy = if let Some(oname) = u.object_name.as_deref() {
                    api.get_object_iam_policy(
                        bname,
                        oname,
                        u.generation.as_deref(),
                        Some(&iam_fields),
                    )
                    .await?
                } else {
                    api.get_bucket_iam_policy(bname, Some(&iam_fields)).await?
                };
                // Match Python gslib/commands/iam.py:541 (fields=['bindings', 'etag'],
                // omitting empty `bindings`, and sorting JSON keys alphabetically).
                policy.kind = None;
                policy.resource_id = None;
                policy.version = None;
                let mut val = serde_json::to_value(&policy).map_err(|e| {
                    GsutilError::command(format!("Failed to serialize IAM policy: {e}"))
                })?;
                if policy.bindings.is_empty() {
                    if let Some(map) = val.as_object_mut() {
                        map.remove("bindings");
                    }
                }
                let json = serde_json::to_string_pretty(&val).map_err(|e| {
                    GsutilError::command(format!("Failed to serialize IAM policy: {e}"))
                })?;
                writeln!(ctx.out, "{json}")?;
            }
            Ok(())
        }
        "set" => {
            let mut recursive = false;
            let mut all_versions = false;
            let mut continue_on_error = false;
            let mut etag_override: Option<String> = None;
            let mut positional = Vec::new();
            let mut i = 1;
            while i < args.len() {
                let arg = args[i].as_str();
                if arg == "-e" {
                    i += 1;
                    etag_override = Some(
                        args.get(i)
                            .ok_or_else(|| {
                                GsutilError::command("Option -e requires an etag value.")
                            })?
                            .clone(),
                    );
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
                    positional.push(arg.to_string());
                }
                i += 1;
            }
            if positional.len() < 2 {
                return Err(GsutilError::command(
                    "iam set requires <policy-file> and at least one URL.",
                ));
            }
            let raw =
                read_json_arg(&positional[0]).map_err(|e| GsutilError::argument(e.to_string()))?;
            let mut policy: IamPolicy = serde_json::from_str(&raw).map_err(|e| {
                GsutilError::argument(format!(
                    "Invalid IAM policy JSON in \"{}\": {e}",
                    positional[0]
                ))
            })?;
            if let Some(etag) = etag_override {
                policy.etag = if etag.is_empty() { None } else { Some(etag) };
            }

            let urls = expand_cloud_urls(ctx, &positional[1..], recursive, all_versions).await?;
            let has_bucket = urls.iter().any(|u| u.is_bucket());
            let has_object = urls.iter().any(|u| u.is_object());
            if has_bucket && has_object {
                return Err(GsutilError::command(
                    "Cannot mix bucket and object URLs in iam set.",
                ));
            }
            ctx.maybe_report_seek_ahead(urls.len())?;
            let mut failed = false;
            for u in urls {
                let bname = u.bucket_name.as_deref().unwrap_or("");
                let res = if let Some(oname) = u.object_name.as_deref() {
                    ctx.api
                        .set_object_iam_policy(bname, oname, &policy, u.generation.as_deref())
                        .await
                        .map(|_| ())
                } else {
                    ctx.api
                        .set_bucket_iam_policy(bname, &policy)
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
                    "Some IAM policy updates failed; see stderr for details.",
                ));
            }
            Ok(())
        }
        "ch" => {
            let mut recursive = false;
            let mut continue_on_error = false;
            let mut specs = Vec::new();
            let mut url_args = Vec::new();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "-r" | "-R" => recursive = true,
                    "-f" => continue_on_error = true,
                    "-d" => {
                        i += 1;
                        let s = args.get(i).ok_or_else(|| {
                            GsutilError::command(
                                "A -d flag is missing an argument specifying bindings to remove.",
                            )
                        })?;
                        if s.starts_with("gs://") || s.starts_with("s3://") || s.starts_with('-') {
                            return Err(GsutilError::command(
                                "A -d flag is missing an argument specifying bindings to remove.",
                            ));
                        }
                        specs.push(parse_iam_spec(s, true)?);
                    }
                    other => {
                        if !url_args.is_empty()
                            || other.starts_with("gs://")
                            || other.starts_with("s3://")
                        {
                            url_args.push(other.to_string());
                        } else {
                            specs.push(parse_iam_spec(other, false)?);
                        }
                    }
                }
                i += 1;
            }
            if specs.is_empty() {
                return Err(GsutilError::command(
                    "iam ch requires at least one binding change.",
                ));
            }
            if url_args.is_empty() {
                return Err(GsutilError::command("Expected at least one URL argument."));
            }
            let mut has_bucket = false;
            let mut has_object = false;
            for raw in &url_args {
                if let Ok(gsutil_core::url::StorageUrl::Cloud(c)) =
                    gsutil_core::url::StorageUrl::parse(raw)
                {
                    if c.is_bucket() && !recursive {
                        has_bucket = true;
                    } else if c.is_object() || recursive {
                        has_object = true;
                    }
                }
            }
            if has_bucket && has_object {
                return Err(GsutilError::command(
                    "Cannot mix bucket and object URLs in iam ch.",
                ));
            }
            let mut failed = false;
            for raw in &url_args {
                let urls =
                    expand_cloud_urls(ctx, std::slice::from_ref(raw), recursive, false).await?;
                ctx.maybe_report_seek_ahead(urls.len())?;
                for u in urls {
                    let bname = u.bucket_name.as_deref().unwrap_or("");
                    let res: Result<()> = async {
                        let mut policy = if let Some(oname) = u.object_name.as_deref() {
                            ctx.api
                                .get_object_iam_policy(bname, oname, u.generation.as_deref(), None)
                                .await?
                        } else {
                            ctx.api.get_bucket_iam_policy(bname, None).await?
                        };
                        apply_iam_changes(&mut policy, &specs, &u.url_string())?;
                        if let Some(oname) = u.object_name.as_deref() {
                            ctx.api
                                .set_object_iam_policy(
                                    bname,
                                    oname,
                                    &policy,
                                    u.generation.as_deref(),
                                )
                                .await?;
                        } else {
                            ctx.api.set_bucket_iam_policy(bname, &policy).await?;
                        }
                        Ok(())
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
            }
            if failed {
                return Err(GsutilError::command(
                    "Some IAM policy updates failed; see stderr for details.",
                ));
            }
            Ok(())
        }
        other => Err(GsutilError::command(format!(
            "Invalid subcommand \"{other}\" for the iam command."
        ))),
    }
}
