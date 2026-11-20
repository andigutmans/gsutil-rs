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
            for u in urls {
                let bname = u.bucket_name.as_deref().unwrap_or("");
                let policy = if let Some(oname) = u.object_name.as_deref() {
                    ctx.api
                        .get_object_iam_policy(bname, oname, u.generation.as_deref(), None)
                        .await?
                } else {
                    ctx.api.get_bucket_iam_policy(bname, None).await?
                };
                let json = serde_json::to_string_pretty(&policy).map_err(|e| {
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
                match args[i].as_str() {
                    "-r" | "-R" => recursive = true,
                    "-a" => all_versions = true,
                    "-f" => continue_on_error = true,
                    "-e" => {
                        i += 1;
                        etag_override = Some(
                            args.get(i)
                                .ok_or_else(|| {
                                    GsutilError::command("Option -e requires an etag value.")
                                })?
                                .clone(),
                        );
                    }
                    other => positional.push(other.to_string()),
                }
                i += 1;
            }
            if positional.len() < 2 {
                return Err(GsutilError::command(
                    "iam set requires <policy-file> and at least one URL.",
                ));
            }
            let raw = read_json_arg(&positional[0])?;
            let mut policy: IamPolicy = serde_json::from_str(&raw).map_err(|e| {
                GsutilError::command(format!(
                    "Invalid IAM policy JSON in \"{}\": {e}",
                    positional[0]
                ))
            })?;
            if let Some(etag) = etag_override {
                policy.etag = if etag.is_empty() { None } else { Some(etag) };
            }

            let urls = expand_cloud_urls(ctx, &positional[1..], recursive, all_versions).await?;
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
                            GsutilError::command("Option -d requires an IAM binding spec.")
                        })?;
                        specs.push(parse_iam_spec(s, true)?);
                    }
                    other => {
                        if other.starts_with("gs://") || other.starts_with("s3://") {
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
            let urls = expand_cloud_urls(ctx, &url_args, recursive, false).await?;
            let mut failed = false;
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
                            .set_object_iam_policy(bname, oname, &policy, u.generation.as_deref())
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
