//! Command implementations and static registry.

pub mod cat;
pub mod du;
pub mod hash;
pub mod help;
pub mod ls;
pub mod mb;
pub mod misc;
pub mod rb;
pub mod rm;
pub mod setmeta;
pub mod stat;
pub mod stubs;
pub mod transfer;
pub mod version;

use gsutil_core::error::Result;

use crate::context::CommandContext;
use crate::dispatch::CommandSpec;
use crate::getopt::OptPair;

/// All 41 gsutil commands sorted alphabetically by canonical name (matching `gsutil help`).
pub const ALL_COMMAND_SPECS: [CommandSpec; 41] = [
    stubs::ACL,
    stubs::AUTOCLASS,
    stubs::BUCKETPOLICYONLY,
    cat::SPEC,
    stubs::COMPOSE,
    stubs::CONFIG,
    stubs::CORS,
    stubs::CP,
    stubs::DEFACL,
    stubs::DEFSTORAGECLASS,
    du::SPEC,
    hash::SPEC,
    help::SPEC,
    stubs::HMAC,
    stubs::IAM,
    stubs::KMS,
    stubs::LABEL,
    stubs::LIFECYCLE,
    stubs::LOGGING,
    ls::SPEC,
    mb::SPEC,
    stubs::MV,
    stubs::NOTIFICATION,
    stubs::PAP,
    stubs::PERFDIAG,
    rb::SPEC,
    stubs::REQUESTERPAYS,
    stubs::RETENTION,
    stubs::REWRITE,
    rm::SPEC,
    stubs::RPO,
    stubs::RSYNC,
    setmeta::SPEC,
    stubs::SIGNURL,
    stat::SPEC,
    stubs::TEST,
    stubs::UBLA,
    stubs::UPDATE,
    version::SPEC,
    stubs::VERSIONING,
    stubs::WEB,
];

/// Execute the resolved command.
pub async fn execute(
    ctx: &mut CommandContext,
    spec: &CommandSpec,
    sub_opts: &[OptPair],
    args: &[String],
) -> Result<i32> {
    match spec.name {
        "cat" => cat::run(ctx, sub_opts, args).await,
        "compose" => transfer::run_compose_cmd(ctx, sub_opts, args).await,
        "config" => misc::run_config(ctx, sub_opts, args).await,
        "cp" => transfer::run_cp(ctx, sub_opts, args).await,
        "du" => du::run(ctx, sub_opts, args).await,
        "hash" => hash::run(ctx, sub_opts, args).await,
        "help" => help::run(ctx, sub_opts, args).await,
        "ls" => ls::run(ctx, sub_opts, args).await,
        "mb" => mb::run(ctx, sub_opts, args).await,
        "mv" => transfer::run_mv_cmd(ctx, sub_opts, args).await,
        "perfdiag" => misc::run_perfdiag(ctx, sub_opts, args).await,
        "rb" => rb::run(ctx, sub_opts, args).await,
        "rewrite" => transfer::run_rewrite_cmd(ctx, sub_opts, args).await,
        "rm" => rm::run(ctx, sub_opts, args).await,
        "rsync" => transfer::run_rsync_cmd(ctx, sub_opts, args).await,
        "setmeta" => setmeta::run(ctx, sub_opts, args).await,
        "stat" => stat::run(ctx, sub_opts, args).await,
        "test" => misc::run_test(ctx, sub_opts, args).await,
        "update" => misc::run_update(ctx, sub_opts, args).await,
        "version" => version::run(ctx, sub_opts, args).await,
        cmd if gsutil_admin::is_admin_command(cmd) => {
            let api = ctx.api().await?;
            let kms_api = ctx.kms_api.clone();
            let pubsub_api = ctx.pubsub_api.clone();
            let mut stdout_vec: Vec<u8> = Vec::new();
            let mut stderr_vec: Vec<u8> = Vec::new();
            let capturing = ctx.stdout_capture.is_some();
            let res = if capturing {
                let mut admin_ctx = gsutil_admin::AdminContext {
                    api: api.as_ref(),
                    config: &ctx.config,
                    project_id: ctx.config.default_project_id().map(ToString::to_string),
                    parallel_operations: ctx.global.parallel_operations,
                    quiet: ctx.global.quiet,
                    debug_level: ctx.global.debug_level,
                    headers: ctx.global.headers.clone(),
                    kms_api: kms_api.as_deref(),
                    pubsub_api: pubsub_api.as_deref(),
                    confirm_fn: None,
                    out: &mut stdout_vec,
                    err: &mut stderr_vec,
                };
                gsutil_admin::dispatch_admin_command(cmd, &mut admin_ctx, args).await
            } else {
                let mut stdout = std::io::stdout();
                let mut stderr = std::io::stderr();
                let mut admin_ctx = gsutil_admin::AdminContext {
                    api: api.as_ref(),
                    config: &ctx.config,
                    project_id: ctx.config.default_project_id().map(ToString::to_string),
                    parallel_operations: ctx.global.parallel_operations,
                    quiet: ctx.global.quiet,
                    debug_level: ctx.global.debug_level,
                    headers: ctx.global.headers.clone(),
                    kms_api: kms_api.as_deref(),
                    pubsub_api: pubsub_api.as_deref(),
                    confirm_fn: None,
                    out: &mut stdout,
                    err: &mut stderr,
                };
                gsutil_admin::dispatch_admin_command(cmd, &mut admin_ctx, args).await
            };
            if capturing {
                if !stdout_vec.is_empty() {
                    let _ = ctx.write_stdout(&stdout_vec);
                }
                if !stderr_vec.is_empty() {
                    if let Some(ref buf) = ctx.stderr_capture {
                        if let Ok(mut g) = buf.lock() {
                            g.extend_from_slice(&stderr_vec);
                        }
                    }
                }
            }
            if let Some(r) = res {
                r?;
                Ok(0)
            } else {
                stubs::run_stub(ctx, spec, sub_opts, args).await
            }
        }
        _ => stubs::run_stub(ctx, spec, sub_opts, args).await,
    }
}
