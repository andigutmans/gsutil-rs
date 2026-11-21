//! CLI command adapters for `gsutil-transfer` (`cp`, `mv`, `rsync`, `compose`, `rewrite`).

use std::io::{self, BufRead};
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use gsutil_core::api::{
    Bucket, Channel, CloudApi, ComposeSourceObject, CopyOptions, CreateNotificationOptions,
    CsObjectOrPrefix, DownloadOptions, EncryptionKey, HmacKeyCreateResponse, HmacKeyMetadata,
    IamPolicy, ListObjectsOptions, Notification, Object, Preconditions, ServiceAccount,
    SignUrlOptions, UploadOptions,
};
use gsutil_core::error::{GsutilError, Result};
use gsutil_core::url::is_file_url_string;
use gsutil_transfer::compose::{run_compose, ComposeConfig};
use gsutil_transfer::copy::{run_copy, CopyConfig, GzipMode};
use gsutil_transfer::mv::{run_mv, MvConfig};
use gsutil_transfer::rewrite::{run_rewrite, RewriteConfig};
use gsutil_transfer::rsync::{run_rsync, RsyncConfig};
use gsutil_transfer::ui::UIController;

use crate::commands::stubs;
use crate::context::CommandContext;
use crate::getopt::OptPair;

/// Zero-overhead `CloudApi` placeholder used when all source/destination URLs are
/// local filesystem paths, avoiding unnecessary auth/ECP initialization.
struct LocalOnlyCloudApi;

#[async_trait]
impl CloudApi for LocalOnlyCloudApi {
    async fn get_service_account_id(&self) -> Result<String> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn get_bucket(&self, _: &str, _: Option<&[String]>) -> Result<Bucket> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn list_buckets(&self, _: Option<&str>, _: Option<&[String]>) -> Result<Vec<Bucket>> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn create_bucket(
        &self,
        _: &str,
        _: Option<&str>,
        _: Option<&Bucket>,
        _: Option<&[String]>,
    ) -> Result<Bucket> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn patch_bucket(
        &self,
        _: &str,
        _: &Bucket,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&Preconditions>,
        _: Option<&[String]>,
    ) -> Result<Bucket> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn delete_bucket(&self, _: &str, _: Option<&Preconditions>) -> Result<()> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn lock_retention_policy(&self, _: &str, _: i64) -> Result<Bucket> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn get_bucket_iam_policy(&self, _: &str, _: Option<&[String]>) -> Result<IamPolicy> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn set_bucket_iam_policy(&self, _: &str, _: &IamPolicy) -> Result<IamPolicy> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn list_objects(&self, _: &str, _: &ListObjectsOptions) -> Result<Vec<CsObjectOrPrefix>> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn get_object_metadata(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: Option<&[String]>,
    ) -> Result<Object> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn patch_object_metadata(
        &self,
        _: &str,
        _: &str,
        _: &Object,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&Preconditions>,
        _: Option<&[String]>,
    ) -> Result<Object> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn get_object_iam_policy(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: Option<&[String]>,
    ) -> Result<IamPolicy> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn set_object_iam_policy(
        &self,
        _: &str,
        _: &str,
        _: &IamPolicy,
        _: Option<&str>,
    ) -> Result<IamPolicy> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn get_object_media(&self, _: &str, _: &str, _: &DownloadOptions) -> Result<Bytes> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn upload_object(&self, _: Bytes, _: &Object, _: &UploadOptions) -> Result<Object> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn upload_object_resumable(
        &self,
        _: Bytes,
        _: &Object,
        _: &UploadOptions,
    ) -> Result<Object> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn copy_object(&self, _: &Object, _: &Object, _: &CopyOptions) -> Result<Object> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn compose_object(
        &self,
        _: &[ComposeSourceObject],
        _: &Object,
        _: Option<&Preconditions>,
        _: Option<&EncryptionKey>,
        _: Option<&[String]>,
    ) -> Result<Object> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn delete_object(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: Option<&Preconditions>,
    ) -> Result<()> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn watch_bucket(&self, _: &str, _: &str, _: &str, _: Option<&str>) -> Result<Channel> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn stop_channel(&self, _: &str, _: &str) -> Result<()> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn get_project_service_account(&self, _: &str) -> Result<ServiceAccount> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn create_notification_config(
        &self,
        _: &str,
        _: &CreateNotificationOptions,
    ) -> Result<Notification> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn delete_notification_config(&self, _: &str, _: &str) -> Result<()> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn list_notification_configs(&self, _: &str) -> Result<Vec<Notification>> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn create_hmac_key(&self, _: &str, _: &str) -> Result<HmacKeyCreateResponse> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn delete_hmac_key(&self, _: &str, _: &str) -> Result<()> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn get_hmac_key(&self, _: &str, _: &str) -> Result<HmacKeyMetadata> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn list_hmac_keys(
        &self,
        _: &str,
        _: Option<&str>,
        _: bool,
    ) -> Result<Vec<HmacKeyMetadata>> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn update_hmac_key(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Result<HmacKeyMetadata> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
    async fn sign_url(&self, _: &SignUrlOptions) -> Result<String> {
        Err(GsutilError::command(
            "Cloud API unavailable for local-only transfer",
        ))
    }
}

async fn api_for_urls(
    ctx: &mut CommandContext,
    urls: &[&str],
    read_stdin: bool,
) -> Result<Arc<dyn CloudApi>> {
    if !read_stdin && !urls.is_empty() && urls.iter().all(|u| is_file_url_string(u)) {
        return Ok(Arc::new(LocalOnlyCloudApi));
    }
    ctx.api().await
}

fn build_copy_config(
    ctx: &CommandContext,
    sub_opts: &[OptPair],
    args: &[String],
    is_mv: bool,
) -> Result<CopyConfig> {
    let mut cfg = CopyConfig {
        parallel_operations: ctx.global.parallel_operations,
        headers: ctx.global.headers.clone(),
        preconditions: Some(ctx.preconditions_from_headers()?),
        encryption_key: crate::encryption::configured_encryption_key(&ctx.config)?,
        decryption_key: crate::encryption::primary_decryption_key(&ctx.config)?,
        recursive: is_mv,
        delete_source_after_copy: is_mv,
        ui: Some(UIController::new(ctx.global.quiet)),
        ..Default::default()
    };

    for (o, a) in sub_opts {
        match o.as_str() {
            "-a" => cfg.canned_acl = Some(a.clone()),
            "-c" => cfg.continue_on_error = true,
            "-D" => cfg.daisy_chain = true,
            "-e" => cfg.exclude_symlinks = true,
            "-I" => cfg.read_stdin_urls = true,
            "-L" => cfg.manifest_path = Some(PathBuf::from(a)),
            "-n" => cfg.no_clobber = true,
            "-p" => cfg.preserve_acl = true,
            "-P" => cfg.preserve_posix = true,
            "-r" | "-R" => cfg.recursive = true,
            "-s" => cfg.storage_class = Some(a.clone()),
            "-t" if !a.is_empty() => {
                // Content-type header override if supplied via -t.
                cfg.headers.insert("content-type".to_string(), a.clone());
            }
            "-U" => cfg.skip_unsupported = true,
            "-v" => cfg.print_created_version = true,
            "-Z" => cfg.gzip_mode = GzipMode::All,
            "-z" => {
                let exts: Vec<String> = a
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                cfg.gzip_mode = GzipMode::Extensions(exts);
            }
            "-J" => cfg.gzip_transport = GzipMode::All,
            "-j" => {
                let exts: Vec<String> = a
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                cfg.gzip_transport = GzipMode::Extensions(exts);
            }
            _ => {}
        }
    }

    if cfg.read_stdin_urls {
        if args.len() != 1 {
            return Err(GsutilError::command(
                "With -I, exactly one destination URL argument is required.",
            ));
        }
        cfg.dst_url = args[0].clone();
    } else {
        if args.len() < 2 {
            let spec = if is_mv { &stubs::MV } else { &stubs::CP };
            return Err(spec.raise_wrong_num_args(args.len()));
        }
        cfg.src_urls = args[..args.len() - 1].to_vec();
        cfg.dst_url = args[args.len() - 1].clone();
    }

    Ok(cfg)
}

pub async fn run_cp(
    ctx: &mut CommandContext,
    sub_opts: &[OptPair],
    args: &[String],
) -> Result<i32> {
    let cfg = build_copy_config(ctx, sub_opts, args, false)?;
    let mut url_refs: Vec<&str> = cfg.src_urls.iter().map(String::as_str).collect();
    url_refs.push(&cfg.dst_url);
    let api = api_for_urls(ctx, &url_refs, cfg.read_stdin_urls).await?;
    let summary = run_copy(api, &ctx.config, &cfg).await?;
    for item in &summary.items {
        if cfg.print_created_version {
            if let Some(ref created) = item.created_url {
                ctx.println(&format!("Created: {created}"))?;
            }
        }
    }
    Ok(if summary.failed > 0 { 1 } else { 0 })
}

pub async fn run_mv_cmd(
    ctx: &mut CommandContext,
    sub_opts: &[OptPair],
    args: &[String],
) -> Result<i32> {
    let copy_cfg = build_copy_config(ctx, sub_opts, args, true)?;
    let mut url_refs: Vec<&str> = copy_cfg.src_urls.iter().map(String::as_str).collect();
    url_refs.push(&copy_cfg.dst_url);
    let api = api_for_urls(ctx, &url_refs, copy_cfg.read_stdin_urls).await?;
    let mv_cfg = MvConfig { copy: copy_cfg };
    let summary = run_mv(api, &ctx.config, &mv_cfg).await?;
    Ok(if summary.failed > 0 { 1 } else { 0 })
}

pub async fn run_rsync_cmd(
    ctx: &mut CommandContext,
    sub_opts: &[OptPair],
    args: &[String],
) -> Result<i32> {
    let mut cfg = RsyncConfig {
        src_url: args[0].clone(),
        dst_url: args[1].clone(),
        parallel_operations: ctx.global.parallel_operations,
        ui: Some(UIController::new(ctx.global.quiet)),
        ..Default::default()
    };

    let mut gzip_all_j = false;
    for (o, a) in sub_opts {
        match o.as_str() {
            "-a" => cfg.canned_acl = Some(a.clone()),
            "-c" => cfg.compute_checksums = true,
            "-C" => cfg.continue_on_error = true,
            "-d" => cfg.delete_extras = true,
            "-e" => cfg.ignore_symlinks = true,
            "-i" => cfg.ignore_existing = true,
            "-J" => gzip_all_j = true,
            "-j" => {
                let exts: Vec<String> = a
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                cfg.gzip_extensions = Some(exts);
            }
            "-n" => cfg.dry_run = true,
            "-p" => cfg.preserve_acl = true,
            "-P" => cfg.preserve_posix = true,
            "-r" | "-R" => cfg.recursive = true,
            "-u" => cfg.skip_old_files = true,
            "-U" => cfg.skip_unsupported = true,
            "-x" => {
                if a.is_empty() {
                    return Err(GsutilError::command("Invalid blank exclude filter"));
                }
                if regex::Regex::new(a).is_err() {
                    return Err(GsutilError::command(format!(
                        "Invalid exclude filter ({a})"
                    )));
                }
                cfg.exclude_pattern = Some(a.clone());
            }
            _ => {}
        }
    }

    if cfg.preserve_acl && cfg.canned_acl.is_some() {
        return Err(GsutilError::command(
            "Specifying both the -p and -a options together is invalid.",
        ));
    }
    if gzip_all_j && cfg.gzip_extensions.is_some() {
        return Err(GsutilError::command(
            "Specifying both the -j and -J options together is invalid.",
        ));
    }
    cfg.gzip_all = gzip_all_j;

    let url_refs = [cfg.src_url.as_str(), cfg.dst_url.as_str()];
    let api = api_for_urls(ctx, &url_refs, false).await?;
    let summary = run_rsync(api, &ctx.config, &cfg).await?;
    Ok(if summary.failed > 0 { 1 } else { 0 })
}

pub async fn run_compose_cmd(
    ctx: &mut CommandContext,
    _sub_opts: &[OptPair],
    args: &[String],
) -> Result<i32> {
    if args.len() < 2 {
        return Err(GsutilError::command(
            "\"compose\" requires at least one source object and a destination object.",
        ));
    }
    let cfg = ComposeConfig {
        src_urls: args[..args.len() - 1].to_vec(),
        dst_url: args[args.len() - 1].clone(),
        preconditions: Some(ctx.preconditions_from_headers()?),
        encryption_key: crate::encryption::configured_encryption_key(&ctx.config)?,
    };
    let api = ctx.api().await?;
    ctx.info(&format!("Composing {}...", cfg.dst_url));
    run_compose(api.as_ref(), &cfg).await?;
    Ok(0)
}

pub async fn run_rewrite_cmd(
    ctx: &mut CommandContext,
    sub_opts: &[OptPair],
    args: &[String],
) -> Result<i32> {
    let mut cfg = RewriteConfig {
        parallel_operations: ctx.global.parallel_operations,
        preconditions: Some(ctx.preconditions_from_headers()?),
        encryption_key: crate::encryption::configured_encryption_key(&ctx.config)?,
        decryption_key: crate::encryption::primary_decryption_key(&ctx.config)?,
        ..Default::default()
    };
    let mut read_stdin = false;

    for (o, a) in sub_opts {
        match o.as_str() {
            "-f" => cfg.continue_on_error = true,
            "-I" => read_stdin = true,
            "-k" => cfg.update_encryption_key = true,
            "-O" => cfg.omit_acl = true,
            "-r" | "-R" => cfg.recursive = true,
            "-s" => cfg.storage_class = Some(a.clone()),
            _ => {}
        }
    }

    if read_stdin {
        if !args.is_empty() {
            return Err(GsutilError::command(
                "No arguments allowed with the -I flag.",
            ));
        }
        let stdin = io::stdin();
        cfg.urls = stdin
            .lock()
            .lines()
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
    } else {
        if args.is_empty() {
            return Err(GsutilError::command(
                "The rewrite command (without -I) expects at least one URL.",
            ));
        }
        cfg.urls = args.to_vec();
    }

    let api = ctx.api().await?;
    let summary = run_rewrite(api, &ctx.config, &cfg).await?;
    Ok(if summary.failed > 0 { 1 } else { 0 })
}
