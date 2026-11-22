//! Core copy engine (`gsutil cp`).
//!
//! Matches `gslib/utils/copy_helper.py` and `gslib/commands/cp.py` in Python gsutil v5.38:
//! - Local -> Cloud (simple, resumable, streaming `-`, parallel composite uploads
//!   with temp component cleanup, `-z`/`-Z` gzip, `-c`, `-n`, `-r`/`-R`, `-a`, `-s`,
//!   `-P` POSIX, `-L` manifest CSV, `-I` stdin URL list, `-U` skip unsupported, `-v`)
//! - Cloud -> Local (oneshot, resumable, sliced object downloads with concurrent range
//!   requests & reassembly, gzip decompression, POSIX restore, `_.gstmp` atomic rename)
//! - Cloud -> Cloud (server-side rewrite/copy, `-D` daisy-chain fallback)
//! - Local -> Local
//! - On-the-fly CRC32C & MD5 integrity validation (`check_hashes`)

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use chrono::Utc;
use flate2::write::{GzDecoder as GzWriteDecoder, GzEncoder};
use flate2::Compression;
use futures::StreamExt;
use gsutil_core::api::{
    CloudApi, ComposeSourceObject, CopyOptions, CsObjectOrPrefix, DownloadOptions,
    DownloadStrategy, EncryptionKey, ListObjectsOptions, Object, Preconditions, SessionUriCallback,
    UploadOptions,
};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result, ServiceErrorKind};
use gsutil_core::hash::{
    concat_crc32c, crc32c_from_base64, crc32c_to_base64, hash_reader, Crc32cHasher, Md5Hasher,
};
use gsutil_core::url::{contains_wildcard, strip_one_slash, StorageUrl};
use gsutil_core::wildcard::{build_bucket_filter_strings, WildcardMatcher};
use tempfile::NamedTempFile;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::compose::MAX_COMPOSE_ARITY;
use crate::parallel::{run_parallel_with_results, ParallelConfig};
use crate::posix::{
    apply_posix_to_local_file, deserialize_posix_from_metadata, read_local_posix_attributes,
    serialize_posix_to_metadata,
};
use crate::rewrite::normalize_storage_class;
use crate::tracker::{
    delete_download_tracker_files, delete_tracker_file, get_tracker_file_path,
    read_or_create_download_tracker, read_parallel_upload_tracker, read_upload_tracker,
    write_download_component_tracker, write_parallel_upload_tracker, write_sliced_download_tracker,
    write_upload_tracker, ParallelUploadComponentEntry, ParallelUploadTrackerData,
    SlicedDownloadTrackerData, TrackerFileType,
};
use crate::ui::UIController;

/// Temporary file suffix for atomic local downloads (matches `temporary_file_util.py`).
pub const TEMP_FILE_SUFFIX: &str = "_.gstmp";

/// Namespace prefix for temporary parallel composite upload components.
pub const PARALLEL_UPLOAD_TEMP_NAMESPACE: &str =
    "/gsutil/tmp/parallel_composite_uploads/for_details_see/gsutil_help_cp/";

/// CSV header for `gsutil cp -L <manifest>`.
pub const MANIFEST_CSV_HEADER: &str =
    "Source,Destination,Start,End,Md5,UploadId,Source Size,Bytes Transferred,Result,Description";

/// Gzip compression mode for uploads (`-z` / `-Z`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum GzipMode {
    #[default]
    None,
    /// `-Z`: compress all uploaded files in-flight.
    All,
    /// `-z ext1,ext2`: compress files whose extension matches (case-insensitive).
    Extensions(Vec<String>),
}

impl GzipMode {
    pub fn should_compress(&self, path: &str) -> bool {
        match self {
            Self::None => false,
            Self::All => true,
            Self::Extensions(exts) => {
                let ext = Path::new(path)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                exts.iter().any(|e| e.eq_ignore_ascii_case(ext))
            }
        }
    }
}

/// Hash validation mode from `[GSUtil] check_hashes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckHashesMode {
    IfFastElseFail,
    IfFastElseSkip,
    Always,
    Never,
}

impl CheckHashesMode {
    pub fn from_config(boto: &BotoConfig) -> Self {
        match boto.check_hashes().trim().to_ascii_lowercase().as_str() {
            "never" => Self::Never,
            "always" => Self::Always,
            "if_fast_else_skip" => Self::IfFastElseSkip,
            _ => Self::IfFastElseFail,
        }
    }

    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Never)
    }
}

/// Configuration for `gsutil cp` (and underlying `mv`/`rsync` transfers).
#[derive(Debug, Clone, Default)]
pub struct CopyConfig {
    pub src_urls: Vec<String>,
    pub dst_url: String,
    pub recursive: bool,
    pub no_clobber: bool,
    pub continue_on_error: bool,
    pub preserve_acl: bool,
    pub preserve_posix: bool,
    /// Preserve file mtime (`goog-reserved-file-mtime`) without full `-P` POSIX attrs (used by `rsync`).
    pub preserve_mtime: bool,
    pub canned_acl: Option<String>,
    pub storage_class: Option<String>,
    /// `-z <exts>` / `-Z`: gzip-compress and store with `Content-Encoding: gzip`.
    pub gzip_mode: GzipMode,
    /// `-j <exts>` / `-J`: gzip-compress in transit during upload (stored uncompressed).
    pub gzip_transport: GzipMode,
    /// `-e`: exclude symlinks during recursive local copies.
    pub exclude_symlinks: bool,
    pub daisy_chain: bool,
    pub skip_unsupported: bool,
    pub manifest_path: Option<PathBuf>,
    pub read_stdin_urls: bool,
    pub print_created_version: bool,
    /// Internal flag (`-M`) used by `mv`: delete each source only after its copy succeeds.
    pub delete_source_after_copy: bool,
    pub parallel_operations: bool,
    pub headers: BTreeMap<String, String>,
    pub encryption_key: Option<EncryptionKey>,
    pub decryption_key: Option<EncryptionKey>,
    pub preconditions: Option<Preconditions>,
    /// Suppress informational progress lines (`-q`).
    pub quiet: bool,
    /// Optional interactive TTY progress controller (`UIController`).
    pub ui: Option<Arc<UIController>>,
}

/// Result of copying a single source -> destination pair.
#[derive(Debug, Clone, Default)]
pub struct CopyItemResult {
    pub src_url: String,
    pub dst_url: String,
    pub bytes_transferred: u64,
    pub created_url: Option<String>,
    pub skipped: bool,
}

/// Aggregate summary of a `run_copy` execution.
#[derive(Debug, Default)]
pub struct CopySummary {
    pub items: Vec<CopyItemResult>,
    pub total_bytes: u64,
    pub succeeded: usize,
    pub skipped: usize,
    pub failed: usize,
}

/// Thread-safe CSV manifest writer for `cp -L`.
pub struct ManifestWriter {
    file: Mutex<File>,
}

impl ManifestWriter {
    pub fn open(path: &Path) -> Result<Self> {
        let needs_header =
            !path.exists() || fs::metadata(path).map(|m| m.len() == 0).unwrap_or(true);
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        if needs_header {
            writeln!(file, "{MANIFEST_CSV_HEADER}")?;
        }
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        src: &str,
        dst: &str,
        start: &str,
        end: &str,
        md5: &str,
        upload_id: &str,
        src_size: u64,
        bytes_transferred: u64,
        result: &str,
        description: &str,
    ) {
        let line = format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            csv_escape(src),
            csv_escape(dst),
            csv_escape(start),
            csv_escape(end),
            csv_escape(md5),
            csv_escape(upload_id),
            src_size,
            bytes_transferred,
            csv_escape(result),
            csv_escape(description),
        );
        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Validate CRC32C and/or MD5 hashes against expected object metadata.
pub fn validate_hashes(
    mode: CheckHashesMode,
    src_desc: &str,
    dst_desc: &str,
    local_crc32c: Option<u32>,
    local_md5_b64: Option<&str>,
    cloud_crc32c_b64: Option<&str>,
    cloud_md5_b64: Option<&str>,
) -> Result<()> {
    if !mode.is_enabled() {
        return Ok(());
    }

    if let (Some(l_crc), Some(c_crc_b64)) = (local_crc32c, cloud_crc32c_b64) {
        let l_crc_b64 = crc32c_to_base64(l_crc);
        if l_crc_b64 != c_crc_b64 {
            return Err(GsutilError::HashMismatch(format!(
                "CommandException: crc32c signature computed for {src_desc} ({l_crc_b64}) \
                 doesn't match cloud-supplied digest for {dst_desc} ({c_crc_b64})."
            )));
        }
    }

    if let (Some(l_md5), Some(c_md5)) = (local_md5_b64, cloud_md5_b64) {
        if l_md5 != c_md5 {
            return Err(GsutilError::HashMismatch(format!(
                "CommandException: md5 signature computed for {src_desc} ({l_md5}) \
                 doesn't match cloud-supplied digest for {dst_desc} ({c_md5})."
            )));
        }
    }

    Ok(())
}

/// Read URLs from a `BufRead` (for `cp -I`), trimming blank lines.
pub fn read_urls_from_reader<R: BufRead>(reader: R) -> Result<Vec<String>> {
    let mut urls = Vec::new();
    for line in reader.lines() {
        let l = line?;
        let trimmed = l.trim();
        if !trimmed.is_empty() {
            urls.push(trimmed.to_string());
        }
    }
    Ok(urls)
}

/// Entry point for `gsutil cp`.
pub async fn run_copy(
    api: Arc<dyn CloudApi>,
    boto: &BotoConfig,
    cfg: &CopyConfig,
) -> Result<CopySummary> {
    if cfg.gzip_mode != GzipMode::None && cfg.gzip_transport != GzipMode::None {
        return Err(GsutilError::command(
            "Specifying both the -j/-J and -z/-Z options together is invalid.",
        ));
    }

    let mut src_url_strs = cfg.src_urls.clone();
    if cfg.read_stdin_urls {
        let stdin = std::io::stdin();
        let from_stdin = read_urls_from_reader(stdin.lock())?;
        src_url_strs.extend(from_stdin);
    }

    if src_url_strs.is_empty() {
        return Err(GsutilError::command("cp requires at least one source URL."));
    }

    if src_url_strs.len() > 1 && src_url_strs.iter().any(|s| s == "-" || s == "file://-") {
        return Err(GsutilError::command(
            "Multiple URL strings are not supported with streaming",
        ));
    }

    let dst_base = StorageUrl::parse(&cfg.dst_url)?;
    if cfg.storage_class.is_some() && dst_base.is_file_url() {
        return Err(GsutilError::command(format!(
            "Cannot specify storage class for a non-cloud destination: {}",
            cfg.dst_url
        )));
    }
    let manifest = match &cfg.manifest_path {
        Some(p) => Some(Arc::new(ManifestWriter::open(p)?)),
        None => None,
    };

    let pairs = expand_copy_pairs(
        api.as_ref(),
        &src_url_strs,
        &dst_base,
        cfg,
        manifest.as_deref(),
    )
    .await?;
    if pairs.is_empty() {
        return Err(GsutilError::command_informational(
            gsutil_core::error::NO_URLS_MATCHED_GENERIC,
        ));
    }
    if dst_base.is_fifo() && pairs.len() > 1 {
        return Err(GsutilError::command(
            "Cannot copy multiple files/objects to a single FIFO.",
        ));
    }

    if let Some(ref ui) = cfg.ui {
        let total_local_bytes: u64 = pairs
            .iter()
            .filter_map(|(src, _)| match src {
                StorageUrl::File(f) if !f.is_stream => {
                    fs::metadata(&f.object_name).ok().map(|m| m.len())
                }
                _ => None,
            })
            .sum();
        ui.set_totals(pairs.len() as u64, total_local_bytes);
    }

    let par_cfg = ParallelConfig::from_boto(
        boto,
        cfg.parallel_operations,
        cfg.continue_on_error || cfg.parallel_operations,
    );
    let boto_arc = Arc::new(boto.clone());
    let cfg_arc = Arc::new(cfg.clone());

    let (items, batch) = run_parallel_with_results(pairs, &par_cfg, move |(src_url, dst_url)| {
        let api = Arc::clone(&api);
        let boto = Arc::clone(&boto_arc);
        let cfg = Arc::clone(&cfg_arc);
        let manifest = manifest.clone();
        async move {
            let res =
                copy_single_pair(api, &boto, &cfg, &src_url, &dst_url, manifest.as_deref()).await;
            if res.is_ok() {
                if let Some(ref ui) = cfg.ui {
                    ui.finish_file();
                }
            }
            res
        }
    })
    .await;

    if let Some(ref ui) = cfg.ui {
        ui.finish();
    }

    let mut summary = CopySummary {
        failed: batch.failed,
        ..Default::default()
    };
    for item in items {
        if item.skipped {
            summary.skipped += 1;
        } else {
            summary.succeeded += 1;
            summary.total_bytes += item.bytes_transferred;
        }
        summary.items.push(item);
    }

    if batch.failed > 0 {
        batch.into_result()?;
    }
    Ok(summary)
}

/// Return the configured resumable chunk size (default 100 MiB, matching Python gsutil).
/// File uploads stream each chunk in 1 MiB blocks via `Body::wrap_stream`, so peak RSS
/// stays ~15 MiB regardless of chunk size.
fn effective_resumable_chunk_size(boto: &BotoConfig) -> usize {
    boto.json_resumable_chunk_size() as usize
}

/// Writer wrapper that updates streaming CRC32C and MD5 hashers on every write.
struct HashingWriter<W: Write> {
    inner: W,
    crc: Crc32cHasher,
    md5: Md5Hasher,
    bytes_written: u64,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            crc: Crc32cHasher::new(),
            md5: Md5Hasher::new(),
            bytes_written: 0,
        }
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.crc.update(&buf[..n]);
        self.md5.update(&buf[..n]);
        self.bytes_written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Stream arbitrary bytes from an async reader directly to a cloud object (`gsutil cp - gs://...`)
/// with bounded ~256 KiB pipe memory.
pub async fn copy_async_stream_to_cloud<R>(
    api: &dyn CloudApi,
    boto: &BotoConfig,
    cfg: &CopyConfig,
    mut reader: R,
    dst_url: &StorageUrl,
) -> Result<CopyItemResult>
where
    R: AsyncRead + Send + Unpin + 'static,
{
    let bucket = dst_url.bucket_name().ok_or_else(|| {
        GsutilError::command("Streaming upload destination must be a cloud object URL.")
    })?;
    let object_name = dst_url.object_name().ok_or_else(|| {
        GsutilError::command("Streaming upload destination must specify an object name.")
    })?;

    let gzip_storage = matches!(cfg.gzip_mode, GzipMode::All);
    let meta = build_upload_metadata(bucket, object_name, cfg, gzip_storage, None);

    let opts = UploadOptions {
        canned_acl: cfg.canned_acl.clone(),
        preconditions: effective_upload_preconditions(cfg),
        encryption_key: cfg.encryption_key.clone(),
        fields: None,
        gzip_encoded: false,
        resumable_session_uri: None,
        session_uri_callback: None,
        progress_callback: cfg.ui.as_ref().map(|u| u.progress_callback()),
        total_size: None,
        chunk_size: Some(effective_resumable_chunk_size(boto)),
        streamed_crc32c_out: None,
    };

    let (mut pipe_w, pipe_r) = tokio::io::duplex(256 * 1024);

    let pump = tokio::spawn(async move {
        let mut crc = Crc32cHasher::new();
        let mut md5 = Md5Hasher::new();
        let mut total_bytes = 0u64;
        let mut buf = vec![0u8; 64 * 1024];

        if gzip_storage {
            let mut enc = GzEncoder::new(Vec::new(), Compression::default());
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                enc.write_all(&buf[..n])?;
                let compressed_chunk = std::mem::take(enc.get_mut());
                if !compressed_chunk.is_empty() {
                    crc.update(&compressed_chunk);
                    md5.update(&compressed_chunk);
                    total_bytes += compressed_chunk.len() as u64;
                    pipe_w.write_all(&compressed_chunk).await?;
                }
            }
            let tail = enc.finish()?;
            if !tail.is_empty() {
                crc.update(&tail);
                md5.update(&tail);
                total_bytes += tail.len() as u64;
                pipe_w.write_all(&tail).await?;
            }
        } else {
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                crc.update(&buf[..n]);
                md5.update(&buf[..n]);
                total_bytes += n as u64;
                pipe_w.write_all(&buf[..n]).await?;
            }
        }
        pipe_w.shutdown().await?;
        Ok::<(u32, String, u64), GsutilError>((crc.finalize(), md5.finalize_base64(), total_bytes))
    });

    let dst_api = api.for_provider(dst_url.scheme())?;
    let upload_fut = dst_api.upload_object_streaming(Box::new(pipe_r), &meta, &opts);
    let (pump_join, upload_res) = tokio::join!(pump, upload_fut);

    let (local_crc, local_md5, len) = pump_join
        .map_err(|e| GsutilError::command(format!("Streaming upload pump failed: {e}")))??;
    let uploaded = upload_res?;

    let check_mode = CheckHashesMode::from_config(boto);
    if let Err(err) = validate_hashes(
        check_mode,
        "stdin",
        &dst_url.url_string(),
        Some(local_crc),
        Some(&local_md5),
        uploaded.crc32c.as_deref(),
        uploaded.md5_hash.as_deref(),
    ) {
        let _ = dst_api
            .delete_object(bucket, object_name, uploaded.generation.as_deref(), None)
            .await;
        return Err(err);
    }

    let created_url = uploaded
        .generation
        .as_deref()
        .map(|g| format!("{}#{g}", dst_url.versionless_url_string()));

    Ok(CopyItemResult {
        src_url: "file://-".to_string(),
        dst_url: dst_url.url_string(),
        bytes_transferred: len,
        created_url,
        skipped: false,
    })
}

/// Stream arbitrary bytes from a synchronous `Read` directly to a cloud object.
pub async fn copy_stream_to_cloud<R: Read>(
    api: &dyn CloudApi,
    boto: &BotoConfig,
    cfg: &CopyConfig,
    mut reader: R,
    dst_url: &StorageUrl,
) -> Result<CopyItemResult> {
    let mut raw = Vec::new();
    reader.read_to_end(&mut raw)?;
    copy_async_stream_to_cloud(api, boto, cfg, std::io::Cursor::new(raw), dst_url).await
}

/// Stream a cloud object directly to a writer (`gsutil cp gs://... -`) with O(1) RAM.
pub async fn copy_cloud_to_stream<W: Write>(
    api: &dyn CloudApi,
    boto: &BotoConfig,
    cfg: &CopyConfig,
    src_url: &StorageUrl,
    mut writer: W,
) -> Result<CopyItemResult> {
    let bucket = src_url
        .bucket_name()
        .ok_or_else(|| GsutilError::command("Source URL must specify a bucket."))?;
    let object_name = src_url
        .object_name()
        .ok_or_else(|| GsutilError::command("Source URL must specify an object."))?;

    let src_api = api.for_provider(src_url.scheme())?;
    let meta = src_api
        .get_object_metadata(bucket, object_name, src_url.generation(), None)
        .await?;
    let gzip_encoded = is_gzip_encoded(&meta);

    let mut stream = src_api
        .get_object_media_stream(
            bucket,
            object_name,
            &DownloadOptions {
                generation: src_url.generation().map(ToString::to_string),
                start_byte: None,
                end_byte: None,
                compressed_encoding: gzip_encoded,
                strategy: DownloadStrategy::OneShot,
                decryption_key: cfg.decryption_key.clone(),
                progress_callback: cfg.ui.as_ref().map(|u| u.progress_callback()),
            },
        )
        .await?;

    let mut crc = Crc32cHasher::new();
    let mut md5 = Md5Hasher::new();
    let mut written_bytes = 0u64;

    if gzip_encoded {
        let mut dec = GzWriteDecoder::new(writer);
        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res?;
            crc.update(&chunk);
            md5.update(&chunk);
            dec.write_all(&chunk)?;
            written_bytes += chunk.len() as u64;
        }
        let mut inner = dec.finish()?;
        inner.flush()?;
    } else {
        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res?;
            crc.update(&chunk);
            md5.update(&chunk);
            writer.write_all(&chunk)?;
            written_bytes += chunk.len() as u64;
        }
        writer.flush()?;
    }

    let check_mode = CheckHashesMode::from_config(boto);
    validate_hashes(
        check_mode,
        "downloaded stream",
        &src_url.url_string(),
        Some(crc.finalize()),
        Some(&md5.finalize_base64()),
        meta.crc32c.as_deref(),
        meta.md5_hash.as_deref(),
    )?;

    Ok(CopyItemResult {
        src_url: src_url.url_string(),
        dst_url: "file://-".to_string(),
        bytes_transferred: written_bytes,
        created_url: None,
        skipped: false,
    })
}

/// Copy a single resolved `(src_url, dst_url)` pair, recording manifest & deleting source if `-M`.
pub async fn copy_single_pair(
    api: Arc<dyn CloudApi>,
    boto: &BotoConfig,
    cfg: &CopyConfig,
    src_url: &StorageUrl,
    dst_url: &StorageUrl,
    manifest: Option<&ManifestWriter>,
) -> Result<CopyItemResult> {
    let start_ts = Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
    if !cfg.quiet {
        if src_url.is_stream() {
            eprintln!("Copying from <STDIN>...");
        } else {
            eprintln!("Copying {}...", src_url);
        }
    }
    let res = match (src_url, dst_url) {
        (StorageUrl::File(f), StorageUrl::Cloud(_)) if f.is_stream => {
            copy_async_stream_to_cloud(api.as_ref(), boto, cfg, tokio::io::stdin(), dst_url).await
        }
        (StorageUrl::File(f), StorageUrl::Cloud(_)) if f.is_fifo => {
            let fifo_file = tokio::fs::File::open(&f.object_name).await?;
            copy_async_stream_to_cloud(api.as_ref(), boto, cfg, fifo_file, dst_url).await
        }
        (StorageUrl::Cloud(_), StorageUrl::File(f)) if f.is_stream => {
            copy_cloud_to_stream(api.as_ref(), boto, cfg, src_url, std::io::stdout()).await
        }
        (StorageUrl::File(_), StorageUrl::Cloud(_)) => {
            copy_local_to_cloud(api.clone(), boto, cfg, src_url, dst_url).await
        }
        (StorageUrl::Cloud(_), StorageUrl::File(_)) => {
            copy_cloud_to_local(api.clone(), boto, cfg, src_url, dst_url).await
        }
        (StorageUrl::Cloud(_), StorageUrl::Cloud(_)) => {
            copy_cloud_to_cloud(api.as_ref(), boto, cfg, src_url, dst_url).await
        }
        (StorageUrl::File(src_f), StorageUrl::File(dst_f)) if dst_f.is_stream => {
            let mut src_file = File::open(&src_f.object_name)?;
            let mut stdout = std::io::stdout();
            let bytes = std::io::copy(&mut src_file, &mut stdout)?;
            stdout.flush()?;
            Ok(CopyItemResult {
                src_url: src_url.url_string(),
                dst_url: dst_url.url_string(),
                bytes_transferred: bytes,
                created_url: None,
                skipped: false,
            })
        }
        (StorageUrl::File(src_f), StorageUrl::File(dst_f)) if src_f.is_stream => {
            let mut stdin = std::io::stdin();
            let mut dst_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&dst_f.object_name)?;
            let bytes = std::io::copy(&mut stdin, &mut dst_file)?;
            dst_file.flush()?;
            Ok(CopyItemResult {
                src_url: src_url.url_string(),
                dst_url: dst_url.url_string(),
                bytes_transferred: bytes,
                created_url: None,
                skipped: false,
            })
        }
        (StorageUrl::File(_), StorageUrl::File(_)) => copy_local_to_local(cfg, src_url, dst_url),
    };

    let end_ts = Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
    match res {
        Ok(item) => {
            if let Some(m) = manifest {
                let status = if item.skipped { "skip" } else { "OK" };
                m.record(
                    &item.src_url,
                    &item.dst_url,
                    &start_ts,
                    &end_ts,
                    "",
                    "",
                    item.bytes_transferred,
                    item.bytes_transferred,
                    status,
                    "",
                );
            }
            // For `mv` (-M), delete the source ONLY if copy succeeded and was not skipped.
            if item.skipped && !cfg.quiet {
                eprintln!("Skipping existing item: {}", item.dst_url);
            } else if cfg.print_created_version && !cfg.quiet {
                if let Some(ref created) = item.created_url {
                    eprintln!("Created: {created}");
                }
            }
            if cfg.delete_source_after_copy && !item.skipped {
                if !cfg.quiet {
                    eprintln!("Removing {}...", src_url);
                }
                delete_source_after_copy(api.as_ref(), src_url).await?;
            }
            Ok(item)
        }
        Err(err) => {
            if let Some(m) = manifest {
                m.record(
                    &src_url.url_string(),
                    &dst_url.url_string(),
                    &start_ts,
                    &end_ts,
                    "",
                    "",
                    0,
                    0,
                    "error",
                    &err.to_string(),
                );
            }
            Err(err)
        }
    }
}

async fn delete_source_after_copy(api: &dyn CloudApi, src_url: &StorageUrl) -> Result<()> {
    match src_url {
        StorageUrl::Cloud(c) => {
            if let (Some(b), Some(o)) = (c.bucket_name.as_deref(), c.object_name.as_deref()) {
                let src_api = api.for_provider(c.scheme.as_str())?;
                src_api
                    .delete_object(b, o, c.generation.as_deref(), None)
                    .await?;
            }
        }
        StorageUrl::File(f) => {
            if !f.is_stream && Path::new(&f.object_name).exists() {
                fs::remove_file(&f.object_name)?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Local -> Cloud
// ---------------------------------------------------------------------------

async fn copy_local_to_cloud(
    api: Arc<dyn CloudApi>,
    boto: &BotoConfig,
    cfg: &CopyConfig,
    src_url: &StorageUrl,
    dst_url: &StorageUrl,
) -> Result<CopyItemResult> {
    let src_path = Path::new(src_url.object_name().unwrap_or(""));
    let bucket = dst_url
        .bucket_name()
        .ok_or_else(|| GsutilError::command("Destination cloud URL missing bucket."))?;
    let object_name = dst_url
        .object_name()
        .ok_or_else(|| GsutilError::command("Destination cloud URL missing object name."))?;

    let dst_api = api.for_provider(dst_url.scheme())?;
    if cfg.no_clobber
        && dst_api
            .get_object_metadata(bucket, object_name, None, Some(&["name".to_string()]))
            .await
            .is_ok()
    {
        return Ok(CopyItemResult {
            src_url: src_url.url_string(),
            dst_url: dst_url.url_string(),
            bytes_transferred: 0,
            created_url: None,
            skipped: true,
        });
    }

    let file_meta = fs::metadata(src_path)?;
    let file_size = file_meta.len();
    let posix_attrs = if cfg.preserve_posix {
        Some(read_local_posix_attributes(src_path)?)
    } else if cfg.preserve_mtime {
        let local = read_local_posix_attributes(src_path)?;
        Some(crate::posix::PosixAttributes {
            mtime: local.mtime,
            ..Default::default()
        })
    } else {
        None
    };

    let src_path_str = src_path.to_string_lossy();
    let should_gzip_storage = cfg.gzip_mode.should_compress(&src_path_str);
    let should_gzip_transport =
        !should_gzip_storage && cfg.gzip_transport.should_compress(&src_path_str);
    if should_gzip_transport && !cfg.quiet {
        eprintln!("Using compressed transport encoding for {src_url}.");
    }
    let pc_threshold = boto.parallel_composite_upload_threshold();
    let use_parallel_composite = !should_gzip_storage
        && !should_gzip_transport
        && dst_url.scheme() == "gs"
        && pc_threshold > 0
        && file_size >= pc_threshold
        && file_size > 0;

    if use_parallel_composite {
        return upload_parallel_composite(
            api,
            boto,
            cfg,
            src_url,
            src_path,
            file_size,
            dst_url,
            bucket,
            object_name,
            posix_attrs.as_ref(),
        )
        .await;
    }

    // Stream-hash / stream-compress into a temp file (O(1) RAM) according to `-z`/`-Z` vs `-j`/`-J`:
    // - `-z`/`-Z`: stream-compress into temp file, hash compressed bytes, `meta.content_encoding = Some("gzip")`,
    //   `UploadOptions.gzip_encoded = false` (store as-is).
    // - `-j`/`-J`: stream-compress into temp file, hash uncompressed bytes, `meta.content_encoding = None`,
    //   `UploadOptions.gzip_encoded = true` (server decompresses).
    // - normal: stream-hash source file directly on disk without buffering the file in RAM!
    let check_mode = CheckHashesMode::from_config(boto);
    let mut temp_gz: Option<NamedTempFile> = None;
    let will_stream_resumable_raw =
        !should_gzip_storage && !should_gzip_transport && file_size >= boto.resumable_threshold();
    let (upload_path, transfer_len, mut local_crc_opt, local_md5_opt): (
        PathBuf,
        u64,
        Option<u32>,
        Option<String>,
    ) = if should_gzip_storage {
        let tmp = NamedTempFile::new()?;
        let mut src_f = File::open(src_path)?;
        let hw = HashingWriter::new(BufWriter::new(tmp.as_file().try_clone()?));
        let mut enc = GzEncoder::new(hw, Compression::default());
        std::io::copy(&mut src_f, &mut enc)?;
        let mut hw = enc.finish()?;
        hw.flush()?;
        let path = tmp.path().to_path_buf();
        let len = hw.bytes_written;
        let crc = hw.crc.finalize();
        let md5 = hw.md5.finalize_base64();
        temp_gz = Some(tmp);
        (path, len, Some(crc), Some(md5))
    } else if should_gzip_transport {
        let mut src_f = File::open(src_path)?;
        let hashes = hash_reader(&mut src_f, true, true)?;
        let local_crc = hashes.crc32c.unwrap_or(0);
        let local_md5 = hashes.md5_base64().unwrap_or_default();
        src_f.seek(SeekFrom::Start(0))?;
        let tmp = NamedTempFile::new()?;
        let mut enc = GzEncoder::new(
            BufWriter::new(tmp.as_file().try_clone()?),
            Compression::default(),
        );
        std::io::copy(&mut src_f, &mut enc)?;
        let mut bw = enc.finish()?;
        bw.flush()?;
        let len = tmp.as_file().metadata()?.len();
        let path = tmp.path().to_path_buf();
        temp_gz = Some(tmp);
        (path, len, Some(local_crc), Some(local_md5))
    } else if will_stream_resumable_raw {
        // Large resumable upload: skip full pre-read + software MD5 pass;
        // compute hardware CRC32C on-the-fly while streaming chunks to GCS.
        (src_path.to_path_buf(), file_size, None, None)
    } else {
        let mut src_f = File::open(src_path)?;
        let hashes = hash_reader(&mut src_f, true, true)?;
        let local_crc = hashes.crc32c.unwrap_or(0);
        let local_md5 = hashes.md5_base64().unwrap_or_default();
        (
            src_path.to_path_buf(),
            file_size,
            Some(local_crc),
            Some(local_md5),
        )
    };

    let mut meta = build_upload_metadata(
        bucket,
        object_name,
        cfg,
        should_gzip_storage,
        posix_attrs.as_ref(),
    );
    if let Some(crc) = local_crc_opt {
        meta.crc32c = Some(crc32c_to_base64(crc));
    }
    if let Some(ref md5) = local_md5_opt {
        meta.md5_hash = Some(md5.clone());
    }

    let use_resumable = transfer_len >= boto.resumable_threshold();
    let streamed_crc_slot = if use_resumable && local_crc_opt.is_none() {
        Some(Arc::new(std::sync::Mutex::new(None)))
    } else {
        None
    };
    let enc_sha = encryption_key_sha256(cfg.encryption_key.as_ref());
    let (tracker_path, existing_session, session_cb): (
        Option<PathBuf>,
        Option<String>,
        Option<SessionUriCallback>,
    ) = if use_resumable {
        let p = get_tracker_file_path(boto, dst_url, TrackerFileType::Upload, "JSON", None, None)?;
        let existing = read_upload_tracker(&p, enc_sha);
        let tp_clone = p.clone();
        let enc_owned = enc_sha.map(ToString::to_string);
        let cb: SessionUriCallback = Arc::new(move |real_session_uri: &str| {
            let _ =
                write_upload_tracker(&tp_clone, enc_owned.clone(), real_session_uri.to_string());
        });
        (Some(p), existing, Some(cb))
    } else {
        (None, None, None)
    };

    let opts = UploadOptions {
        canned_acl: cfg.canned_acl.clone(),
        preconditions: effective_upload_preconditions(cfg),
        encryption_key: cfg.encryption_key.clone(),
        fields: None,
        // Only set HTTP transport `Content-Encoding: gzip` for `-j`/`-J`, NOT `-z`/`-Z`!
        gzip_encoded: should_gzip_transport,
        resumable_session_uri: existing_session,
        session_uri_callback: session_cb,
        progress_callback: cfg.ui.as_ref().map(|u| u.progress_callback()),
        total_size: Some(transfer_len),
        chunk_size: Some(effective_resumable_chunk_size(boto)),
        streamed_crc32c_out: streamed_crc_slot.clone(),
    };

    let dst_api = api.for_provider(dst_url.scheme())?;
    let upload_res = if use_resumable {
        // Constant-memory chunked resumable upload directly from disk!
        dst_api
            .upload_object_resumable_file(&upload_path, 0, transfer_len, &meta, &opts)
            .await
    } else {
        // Small file (< resumable_threshold): single-RTT multipart upload.
        let mut f = File::open(&upload_path)?;
        let mut buf = Vec::with_capacity(transfer_len as usize);
        f.read_to_end(&mut buf)?;
        let res = dst_api.upload_object(Bytes::from(buf), &meta, &opts).await;
        if res.is_ok() {
            if let Some(ref ui) = cfg.ui {
                ui.add_bytes(transfer_len);
            }
        }
        res
    };

    drop(temp_gz);

    let uploaded = match upload_res {
        Ok(obj) => {
            if let Some(ref tp) = tracker_path {
                delete_tracker_file(tp);
            }
            obj
        }
        Err(GsutilError::Service(se))
            if cfg.no_clobber && se.kind == ServiceErrorKind::Precondition =>
        {
            if let Some(ref tp) = tracker_path {
                delete_tracker_file(tp);
            }
            return Ok(CopyItemResult {
                src_url: src_url.url_string(),
                dst_url: dst_url.url_string(),
                bytes_transferred: 0,
                created_url: None,
                skipped: true,
            });
        }
        Err(e) => return Err(e),
    };

    if local_crc_opt.is_none() {
        local_crc_opt = streamed_crc_slot
            .as_ref()
            .and_then(|s| s.lock().ok().and_then(|mut g| g.take()));
        if local_crc_opt.is_none() && check_mode != CheckHashesMode::Never {
            let mut src_f = File::open(src_path)?;
            let hashes = hash_reader(&mut src_f, true, false)?;
            local_crc_opt = hashes.crc32c;
        }
    }

    if let Err(err) = validate_hashes(
        check_mode,
        &src_url.url_string(),
        &dst_url.url_string(),
        local_crc_opt,
        local_md5_opt.as_deref(),
        uploaded.crc32c.as_deref(),
        uploaded.md5_hash.as_deref(),
    ) {
        let _ = dst_api
            .delete_object(bucket, object_name, uploaded.generation.as_deref(), None)
            .await;
        return Err(err);
    }

    let created_url = uploaded
        .generation
        .as_deref()
        .map(|g| format!("{}#{g}", dst_url.versionless_url_string()));

    Ok(CopyItemResult {
        src_url: src_url.url_string(),
        dst_url: dst_url.url_string(),
        bytes_transferred: transfer_len,
        created_url,
        skipped: false,
    })
}

#[allow(clippy::too_many_arguments)]
async fn upload_parallel_composite(
    api: Arc<dyn CloudApi>,
    boto: &BotoConfig,
    cfg: &CopyConfig,
    src_url: &StorageUrl,
    src_path: &Path,
    file_size: u64,
    dst_url: &StorageUrl,
    bucket: &str,
    object_name: &str,
    posix_attrs: Option<&crate::posix::PosixAttributes>,
) -> Result<CopyItemResult> {
    let comp_size_cfg = boto.parallel_composite_upload_component_size().max(1);
    let num_components = (file_size.div_ceil(comp_size_cfg) as usize).clamp(2, MAX_COMPOSE_ARITY);
    let chunk_size = file_size.div_ceil(num_components as u64);

    let tracker_path = get_tracker_file_path(
        boto,
        dst_url,
        TrackerFileType::ParallelUpload,
        "JSON",
        Some(src_url),
        None,
    )?;

    let desired_enc_sha = encryption_key_sha256(cfg.encryption_key.as_ref());
    let raw_existing_tracker = read_parallel_upload_tracker(&tracker_path);
    let existing_tracker = match raw_existing_tracker {
        Some(prev) if prev.encryption_key_sha256.as_deref() == desired_enc_sha => Some(prev),
        Some(prev) => {
            if !cfg.quiet {
                eprintln!(
                    "Parallel upload tracker file does not match current encryption key. \
                     Deleting old components and restarting upload"
                );
            }
            let cleanup_api = api.for_provider(dst_url.scheme())?;
            for c in &prev.components {
                let _ = cleanup_api
                    .delete_object(bucket, &c.object_name, c.generation.as_deref(), None)
                    .await;
            }
            delete_tracker_file(&tracker_path);
            None
        }
        None => None,
    };

    // Reuse random_prefix from matching tracker if resuming an interrupted composite upload.
    let random_prefix = if let Some(ref prev) = existing_tracker {
        prev.random_prefix.clone()
    } else {
        let mut salt_hash = Md5Hasher::new();
        salt_hash.update(bucket.as_bytes());
        salt_hash.update(b"/");
        salt_hash.update(object_name.as_bytes());
        salt_hash.update(b"/");
        salt_hash.update(src_path.to_string_lossy().as_bytes());
        salt_hash.finalize_hex()
    };

    let prev_components: BTreeMap<usize, ParallelUploadComponentEntry> = existing_tracker
        .map(|t| {
            t.components
                .into_iter()
                .map(|c| (c.component_num, c))
                .collect()
        })
        .unwrap_or_default();

    let mut ranges_to_upload: Vec<(usize, u64, u64, String)> = Vec::new();
    let mut reused_parts: Vec<(usize, String, Object, u32, u64)> = Vec::new();
    let dst_api = api.for_provider(dst_url.scheme())?;

    let mut offset = 0u64;
    let mut idx = 0usize;
    while offset < file_size {
        let len = (file_size - offset).min(chunk_size);
        let temp_name = format!("{PARALLEL_UPLOAD_TEMP_NAMESPACE}{random_prefix}_{idx}");

        // Check if this component was already uploaded in an earlier interrupted run.
        let mut reused = false;
        if let Some(prev) = prev_components.get(&idx) {
            if prev.object_name == temp_name && prev.size == len {
                if let Ok(existing_obj) = dst_api
                    .get_object_metadata(bucket, &temp_name, prev.generation.as_deref(), None)
                    .await
                {
                    if existing_obj.size_bytes() == len {
                        if let Some(crc) = existing_obj
                            .crc32c
                            .as_deref()
                            .and_then(|c| crc32c_from_base64(c).ok())
                        {
                            reused_parts.push((idx, temp_name.clone(), existing_obj, crc, len));
                            reused = true;
                        }
                    }
                }
            }
        }
        if !reused {
            ranges_to_upload.push((idx, offset, len, temp_name));
        }
        offset += len;
        idx += 1;
    }

    if !reused_parts.is_empty() && !cfg.quiet {
        eprintln!(
            "Found {} existing temporary components to reuse.",
            reused_parts.len()
        );
    }

    let par_cfg = ParallelConfig {
        parallel_operations: true,
        process_count: boto.parallel_process_count().max(1),
        thread_count: boto.parallel_thread_count().max(1),
        continue_on_error: false,
    };

    let src_path_buf = src_path.to_path_buf();
    let bucket_str = bucket.to_string();
    let dst_scheme = dst_url.scheme().to_string();
    let cfg_cloned = cfg.clone();
    let api_for_parts = Arc::clone(&api);
    let comp_chunk_size = effective_resumable_chunk_size(boto);

    let (mut uploaded_parts, batch) = run_parallel_with_results(
        ranges_to_upload,
        &par_cfg,
        move |(part_idx, start, len, temp_name)| {
            let api = Arc::clone(&api_for_parts);
            let path = src_path_buf.clone();
            let bkt = bucket_str.clone();
            let scheme = dst_scheme.clone();
            let cfg = cfg_cloned.clone();
            async move {
                // Stream-hash component slice directly from disk (64 KiB buffer, O(1) RAM).
                let mut f = File::open(&path)?;
                f.seek(SeekFrom::Start(start))?;
                let mut limited = f.take(len);
                let hashes = hash_reader(&mut limited, true, false)?;
                let part_crc = hashes.crc32c.unwrap_or(0);

                let meta = Object {
                    bucket: Some(bkt),
                    name: Some(temp_name.clone()),
                    storage_class: cfg.storage_class.as_deref().map(normalize_storage_class),
                    crc32c: Some(crc32c_to_base64(part_crc)),
                    ..Default::default()
                };
                let opts = UploadOptions {
                    canned_acl: cfg.canned_acl.clone(),
                    preconditions: None,
                    encryption_key: cfg.encryption_key.clone(),
                    fields: None,
                    gzip_encoded: false,
                    resumable_session_uri: None,
                    session_uri_callback: None,
                    progress_callback: cfg.ui.as_ref().map(|u| u.progress_callback()),
                    total_size: Some(len),
                    chunk_size: Some(comp_chunk_size),
                    streamed_crc32c_out: None,
                };
                let part_api = api.for_provider(&scheme)?;
                let obj = part_api
                    .upload_object_resumable_file(&path, start, len, &meta, &opts)
                    .await?;
                Ok((part_idx, temp_name, obj, part_crc, len))
            }
        },
    )
    .await;

    uploaded_parts.extend(reused_parts);
    uploaded_parts.sort_by_key(|(i, _, _, _, _)| *i);

    // Always persist uploaded components to tracker so an interrupted upload can resume.
    let tracker_data = ParallelUploadTrackerData {
        encryption_key_sha256: desired_enc_sha.map(ToString::to_string),
        random_prefix,
        components: uploaded_parts
            .iter()
            .map(|(i, name, obj, _, len)| ParallelUploadComponentEntry {
                component_num: *i,
                object_name: name.clone(),
                generation: obj.generation.clone(),
                crc32c: obj.crc32c.clone(),
                size: *len,
            })
            .collect(),
    };
    let _ = write_parallel_upload_tracker(&tracker_path, &tracker_data);

    if batch.failed > 0 {
        return Err(batch.into_result().unwrap_err());
    }

    // Compute expected composite CRC32C via concat_crc32c.
    let mut expected_crc = 0u32;
    let mut compose_sources = Vec::with_capacity(uploaded_parts.len());
    for (_, name, obj, part_crc, len) in &uploaded_parts {
        expected_crc = concat_crc32c(expected_crc, *part_crc, *len);
        compose_sources.push(ComposeSourceObject {
            name: name.clone(),
            generation: obj.generation.clone(),
            object_preconditions: None,
        });
    }

    let dst_meta = build_upload_metadata(bucket, object_name, cfg, false, posix_attrs);
    let compose_res = dst_api
        .compose_object(
            &compose_sources,
            &dst_meta,
            effective_upload_preconditions(cfg).as_ref(),
            cfg.encryption_key.as_ref(),
            None,
        )
        .await;

    // Always clean up temporary component objects after compose attempt.
    for (_, temp_name, obj, _, _) in &uploaded_parts {
        let _ = dst_api
            .delete_object(bucket, temp_name, obj.generation.as_deref(), None)
            .await;
    }

    let composed = match compose_res {
        Ok(obj) => {
            delete_tracker_file(&tracker_path);
            obj
        }
        Err(GsutilError::Service(se))
            if cfg.no_clobber && se.kind == ServiceErrorKind::Precondition =>
        {
            delete_tracker_file(&tracker_path);
            return Ok(CopyItemResult {
                src_url: src_url.url_string(),
                dst_url: dst_url.url_string(),
                bytes_transferred: 0,
                created_url: None,
                skipped: true,
            });
        }
        Err(e) => return Err(e),
    };

    let check_mode = CheckHashesMode::from_config(boto);
    if let Err(err) = validate_hashes(
        check_mode,
        &src_url.url_string(),
        &dst_url.url_string(),
        Some(expected_crc),
        None,
        composed.crc32c.as_deref(),
        None,
    ) {
        let _ = dst_api
            .delete_object(bucket, object_name, composed.generation.as_deref(), None)
            .await;
        return Err(err);
    }

    let created_url = composed
        .generation
        .as_deref()
        .map(|g| format!("{}#{g}", dst_url.versionless_url_string()));

    Ok(CopyItemResult {
        src_url: src_url.url_string(),
        dst_url: dst_url.url_string(),
        bytes_transferred: file_size,
        created_url,
        skipped: false,
    })
}

// ---------------------------------------------------------------------------
// Cloud -> Local
// ---------------------------------------------------------------------------

async fn copy_cloud_to_local(
    api: Arc<dyn CloudApi>,
    boto: &BotoConfig,
    cfg: &CopyConfig,
    src_url: &StorageUrl,
    dst_url: &StorageUrl,
) -> Result<CopyItemResult> {
    let bucket = src_url
        .bucket_name()
        .ok_or_else(|| GsutilError::command("Source cloud URL missing bucket."))?;
    let object_name = src_url
        .object_name()
        .ok_or_else(|| GsutilError::command("Source cloud URL missing object name."))?;
    let dst_path_str = dst_url.object_name().unwrap_or("");
    let dst_path = Path::new(dst_path_str);

    // Copying a cloud object into an existing FIFO: stream directly into the FIFO
    // instead of writing to `_.gstmp` + `rename` (which would replace/break the FIFO).
    if dst_url.is_fifo() {
        let fifo_writer = OpenOptions::new().write(true).open(dst_path)?;
        return copy_cloud_to_stream(api.as_ref(), boto, cfg, src_url, fifo_writer).await;
    }

    if cfg.no_clobber && dst_path.exists() {
        return Ok(CopyItemResult {
            src_url: src_url.url_string(),
            dst_url: dst_url.url_string(),
            bytes_transferred: 0,
            created_url: None,
            skipped: true,
        });
    }

    if let Some(parent) = dst_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let src_api = api.for_provider(src_url.scheme())?;
    let src_meta = src_api
        .get_object_metadata(bucket, object_name, src_url.generation(), None)
        .await?;

    if cfg.delete_source_after_copy && !cfg.quiet {
        maybe_warn_early_deletion(src_url, &src_meta);
    }
    let obj_size = src_meta.size_bytes();
    let gzip_encoded = is_gzip_encoded(&src_meta);

    let temp_path = PathBuf::from(format!("{dst_path_str}{TEMP_FILE_SUFFIX}"));
    let sliced_threshold = boto.sliced_object_download_threshold();
    let use_sliced = !gzip_encoded
        && sliced_threshold > 0
        && obj_size >= sliced_threshold
        && obj_size > 0
        && boto.sliced_object_download_max_components() > 1;

    let bytes_written = if use_sliced {
        download_sliced(
            api.clone(),
            boto,
            cfg,
            src_url,
            &src_meta,
            dst_url,
            &temp_path,
            bucket,
            object_name,
            obj_size,
        )
        .await?
    } else {
        download_single(
            api.as_ref(),
            boto,
            cfg,
            src_url,
            &src_meta,
            dst_url,
            &temp_path,
            bucket,
            object_name,
            obj_size,
            gzip_encoded,
        )
        .await?
    };

    // Atomic rename from _.gstmp to final destination.
    fs::rename(&temp_path, dst_path)?;
    delete_download_tracker_files(boto, dst_url, "JSON");

    if cfg.preserve_posix {
        if let Some(ref custom_meta) = src_meta.metadata {
            let attrs = deserialize_posix_from_metadata(custom_meta);
            if !attrs.is_empty() {
                apply_posix_to_local_file(dst_path, &attrs)?;
            }
        }
    } else if cfg.preserve_mtime {
        if let Some(ref custom_meta) = src_meta.metadata {
            let attrs = deserialize_posix_from_metadata(custom_meta);
            if attrs.mtime.is_some() {
                apply_posix_to_local_file(
                    dst_path,
                    &crate::posix::PosixAttributes {
                        mtime: attrs.mtime,
                        ..Default::default()
                    },
                )?;
            }
        }
    }

    Ok(CopyItemResult {
        src_url: src_url.url_string(),
        dst_url: dst_url.url_string(),
        bytes_transferred: bytes_written,
        created_url: None,
        skipped: false,
    })
}

#[allow(clippy::too_many_arguments)]
async fn download_single(
    api: &dyn CloudApi,
    boto: &BotoConfig,
    cfg: &CopyConfig,
    src_url: &StorageUrl,
    src_meta: &Object,
    dst_url: &StorageUrl,
    temp_path: &Path,
    bucket: &str,
    object_name: &str,
    obj_size: u64,
    gzip_encoded: bool,
) -> Result<u64> {
    let src_api = api.for_provider(src_url.scheme())?;
    let existing_size = fs::metadata(temp_path).map(|m| m.len()).unwrap_or(0);
    let (_tracker, start_byte) =
        read_or_create_download_tracker(boto, src_meta, dst_url, "JSON", 0, existing_size, None)?;

    let strategy = if obj_size >= boto.resumable_threshold() {
        DownloadStrategy::Resumable
    } else {
        DownloadStrategy::OneShot
    };

    let progress_cb = cfg.ui.as_ref().map(|u| u.progress_callback());

    // Real streaming resumable download: when a matching tracker file exists and partial bytes
    // are already present in `_.gstmp` (non-gzip), stream-hash existing bytes, request only
    // `[start_byte..]`, append chunks streamingly, and validate hashes in O(1) RAM.
    if !gzip_encoded && start_byte > 0 && start_byte <= obj_size && temp_path.exists() {
        let mut crc = Crc32cHasher::new();
        let mut md5 = Md5Hasher::new();
        {
            let mut rf = File::open(temp_path)?;
            let mut buf = vec![0u8; 64 * 1024];
            let mut remaining_prefix = start_byte;
            while remaining_prefix > 0 {
                let to_read = (remaining_prefix as usize).min(buf.len());
                let n = rf.read(&mut buf[..to_read])?;
                if n == 0 {
                    break;
                }
                crc.update(&buf[..n]);
                md5.update(&buf[..n]);
                remaining_prefix -= n as u64;
            }
        }

        if start_byte == obj_size && !cfg.quiet {
            eprintln!(
                "Download already complete for file://{dst}, skipping download but will run integrity checks.",
                dst = temp_path.display()
            );
        }

        if start_byte < obj_size {
            let mut stream = src_api
                .get_object_media_stream(
                    bucket,
                    object_name,
                    &DownloadOptions {
                        generation: src_url.generation().map(ToString::to_string),
                        start_byte: Some(start_byte as i64),
                        end_byte: None,
                        compressed_encoding: false,
                        strategy,
                        decryption_key: cfg.decryption_key.clone(),
                        progress_callback: progress_cb.clone(),
                    },
                )
                .await?;

            let mut f = OpenOptions::new().write(true).open(temp_path)?;
            f.seek(SeekFrom::Start(start_byte))?;
            let mut bw = BufWriter::with_capacity(256 * 1024, f);
            while let Some(chunk_res) = stream.next().await {
                let chunk = chunk_res?;
                crc.update(&chunk);
                md5.update(&chunk);
                bw.write_all(&chunk)?;
            }
            bw.flush()?;
        }

        let check_mode = CheckHashesMode::from_config(boto);
        if validate_hashes(
            check_mode,
            &dst_url.url_string(),
            &src_url.url_string(),
            Some(crc.finalize()),
            Some(&md5.finalize_base64()),
            src_meta.crc32c.as_deref(),
            src_meta.md5_hash.as_deref(),
        )
        .is_ok()
        {
            let final_len = fs::metadata(temp_path)?.len();
            return Ok(final_len);
        }
        // Existing partial/complete temp file failed hash check: delete and restart fresh below.
        let _ = fs::remove_file(temp_path);
        delete_download_tracker_files(boto, dst_url, "JSON");
    }

    // Fresh streaming download (constant O(1) RAM for both plain and gzip-encoded objects).
    let mut stream = src_api
        .get_object_media_stream(
            bucket,
            object_name,
            &DownloadOptions {
                generation: src_url.generation().map(ToString::to_string),
                start_byte: None,
                end_byte: None,
                compressed_encoding: gzip_encoded,
                strategy,
                decryption_key: cfg.decryption_key.clone(),
                progress_callback: progress_cb,
            },
        )
        .await?;

    let mut crc = Crc32cHasher::new();
    let mut md5 = Md5Hasher::new();

    if gzip_encoded {
        // Stream compressed wire bytes into GzWriteDecoder -> BufWriter<File> while
        // validating CRC32C/MD5 against the compressed wire bytes!
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(temp_path)?;
        let mut dec = GzWriteDecoder::new(BufWriter::with_capacity(256 * 1024, f));
        let mut stream_err: Option<GsutilError> = None;
        while let Some(chunk_res) = stream.next().await {
            let chunk = match chunk_res {
                Ok(c) => c,
                Err(e) => {
                    stream_err = Some(e.into());
                    break;
                }
            };
            crc.update(&chunk);
            md5.update(&chunk);
            if let Err(e) = dec.write_all(&chunk) {
                // Keep hashing remaining bytes or surface decode error after hash check.
                stream_err = Some(e.into());
                break;
            }
        }
        if let Some(e) = stream_err {
            let _ = fs::remove_file(temp_path);
            return Err(e);
        }
        let mut bw = match dec.finish() {
            Ok(w) => w,
            Err(e) => {
                // Check if hash mismatch caused corrupt gzip stream!
                let check_mode = CheckHashesMode::from_config(boto);
                validate_hashes(
                    check_mode,
                    &dst_url.url_string(),
                    &src_url.url_string(),
                    Some(crc.finalize()),
                    Some(&md5.finalize_base64()),
                    src_meta.crc32c.as_deref(),
                    src_meta.md5_hash.as_deref(),
                )?;
                let _ = fs::remove_file(temp_path);
                return Err(e.into());
            }
        };
        bw.flush()?;
    } else {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(temp_path)?;
        let mut bw = BufWriter::with_capacity(256 * 1024, f);
        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res?;
            crc.update(&chunk);
            md5.update(&chunk);
            bw.write_all(&chunk)?;
        }
        bw.flush()?;
    }

    let check_mode = CheckHashesMode::from_config(boto);
    if let Err(err) = validate_hashes(
        check_mode,
        &dst_url.url_string(),
        &src_url.url_string(),
        Some(crc.finalize()),
        Some(&md5.finalize_base64()),
        src_meta.crc32c.as_deref(),
        src_meta.md5_hash.as_deref(),
    ) {
        let _ = fs::remove_file(temp_path);
        return Err(err);
    }

    let final_len = fs::metadata(temp_path)?.len();
    Ok(final_len)
}

#[allow(clippy::too_many_arguments)]
async fn download_sliced(
    api: Arc<dyn CloudApi>,
    boto: &BotoConfig,
    cfg: &CopyConfig,
    src_url: &StorageUrl,
    src_meta: &Object,
    dst_url: &StorageUrl,
    temp_path: &Path,
    bucket: &str,
    object_name: &str,
    obj_size: u64,
) -> Result<u64> {
    let max_components = boto.sliced_object_download_max_components().max(2);
    let comp_size_cfg = boto.sliced_object_download_component_size().max(1);
    let num_components = (obj_size.div_ceil(comp_size_cfg) as usize).clamp(2, max_components);
    let slice_size = obj_size.div_ceil(num_components as u64);

    // Check if an existing matching sliced-download tracker + temp file can be resumed.
    let parent_tracker = get_tracker_file_path(
        boto,
        dst_url,
        TrackerFileType::SlicedDownload,
        "JSON",
        None,
        None,
    )
    .ok();
    let can_resume_sliced = parent_tracker
        .as_ref()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<SlicedDownloadTrackerData>(&s).ok())
        .is_some_and(|t| {
            t.etag == src_meta.etag.as_deref().unwrap_or("")
                && t.generation == src_meta.generation
                && t.num_components == num_components
                && temp_path.exists()
                && fs::metadata(temp_path).map(|m| m.len()).unwrap_or(0) == obj_size
        });

    if !can_resume_sliced {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(temp_path)?;
        f.set_len(obj_size)?;
        if let Some(ref pt) = parent_tracker {
            let _ = write_sliced_download_tracker(pt, src_meta, num_components);
        }
    }

    let mut slices: Vec<(usize, u64, u64)> = Vec::new();
    let mut start = 0u64;
    let mut idx = 0usize;
    while start < obj_size {
        let end = (start + slice_size - 1).min(obj_size - 1);
        slices.push((idx, start, end));
        start = end + 1;
        idx += 1;
    }

    let par_cfg = ParallelConfig {
        parallel_operations: true,
        process_count: boto.parallel_process_count().max(1),
        thread_count: boto.parallel_thread_count().max(1),
        continue_on_error: false,
    };

    let temp_path_buf = temp_path.to_path_buf();
    let bucket_str = bucket.to_string();
    let obj_str = object_name.to_string();
    let src_scheme = src_url.scheme().to_string();
    let gen = src_url.generation().map(ToString::to_string);
    let dec_key = cfg.decryption_key.clone();
    let boto_cloned = boto.clone();
    let dst_url_cloned = dst_url.clone();
    let src_meta_cloned = src_meta.clone();

    let (mut slice_results, batch) =
        run_parallel_with_results(slices, &par_cfg, move |(comp_idx, start_byte, end_byte)| {
            let api = Arc::clone(&api);
            let temp_path = temp_path_buf.clone();
            let bkt = bucket_str.clone();
            let obj = obj_str.clone();
            let scheme = src_scheme.clone();
            let gen = gen.clone();
            let dec_key = dec_key.clone();
            let boto = boto_cloned.clone();
            let dst_url = dst_url_cloned.clone();
            let src_meta = src_meta_cloned.clone();
            async move {
                let expected_len = end_byte - start_byte + 1;
                let (comp_tracker, saved_pos) = if can_resume_sliced {
                    read_or_create_download_tracker(
                        &boto,
                        &src_meta,
                        &dst_url,
                        "JSON",
                        start_byte,
                        0,
                        Some(comp_idx),
                    )?
                } else {
                    let ct = get_tracker_file_path(
                        &boto,
                        &dst_url,
                        TrackerFileType::DownloadComponent,
                        "JSON",
                        None,
                        Some(comp_idx),
                    )
                    .ok();
                    if let Some(ref p) = ct {
                        let _ = write_download_component_tracker(p, &src_meta, start_byte);
                    }
                    (ct, start_byte)
                };

                // If this slice was already completely downloaded in an earlier run, skip GET!
                let resume_from = saved_pos.clamp(start_byte, end_byte + 1);
                if resume_from <= end_byte {
                    let src_api = api.for_provider(&scheme)?;
                    let mut stream = src_api
                        .get_object_media_stream(
                            &bkt,
                            &obj,
                            &DownloadOptions {
                                generation: gen,
                                start_byte: Some(resume_from as i64),
                                end_byte: Some(end_byte),
                                compressed_encoding: false,
                                strategy: DownloadStrategy::Resumable,
                                decryption_key: dec_key,
                                progress_callback: None,
                            },
                        )
                        .await?;

                    let mut f = OpenOptions::new().write(true).open(&temp_path)?;
                    f.seek(SeekFrom::Start(resume_from))?;
                    let mut bw = BufWriter::with_capacity(256 * 1024, f);
                    let mut written = 0u64;
                    while let Some(chunk_res) = stream.next().await {
                        let chunk = chunk_res?;
                        bw.write_all(&chunk)?;
                        written += chunk.len() as u64;
                    }
                    bw.flush()?;

                    if let Some(ref ct) = comp_tracker {
                        let _ =
                            write_download_component_tracker(ct, &src_meta, resume_from + written);
                    }
                }

                // Compute CRC32C of this slice from disk (handles both fresh and resumed slices).
                let mut rf = File::open(&temp_path)?;
                rf.seek(SeekFrom::Start(start_byte))?;
                let mut limited = rf.take(expected_len);
                let hashes = hash_reader(&mut limited, true, false)?;
                let slice_crc = hashes.crc32c.unwrap_or(0);

                Ok((comp_idx, slice_crc, expected_len))
            }
        })
        .await;

    if batch.failed > 0 {
        return Err(batch.into_result().unwrap_err());
    }

    slice_results.sort_by_key(|(idx, _, _)| *idx);
    let mut combined_crc = 0u32;
    let mut total_len = 0u64;
    for (_, scrc, len) in slice_results {
        combined_crc = concat_crc32c(combined_crc, scrc, len);
        total_len += len;
    }

    let check_mode = CheckHashesMode::from_config(boto);
    if let Err(err) = validate_hashes(
        check_mode,
        &dst_url.url_string(),
        &src_url.url_string(),
        Some(combined_crc),
        None,
        src_meta.crc32c.as_deref(),
        None,
    ) {
        let _ = fs::remove_file(temp_path);
        return Err(err);
    }

    Ok(total_len)
}

// ---------------------------------------------------------------------------
// Cloud -> Cloud (Server-Side Copy & Daisy-Chain)
// ---------------------------------------------------------------------------

async fn copy_cloud_to_cloud(
    api: &dyn CloudApi,
    boto: &BotoConfig,
    cfg: &CopyConfig,
    src_url: &StorageUrl,
    dst_url: &StorageUrl,
) -> Result<CopyItemResult> {
    let src_bucket = src_url
        .bucket_name()
        .ok_or_else(|| GsutilError::command("Source cloud URL missing bucket."))?;
    let src_obj = src_url
        .object_name()
        .ok_or_else(|| GsutilError::command("Source cloud URL missing object name."))?;
    let dst_bucket = dst_url
        .bucket_name()
        .ok_or_else(|| GsutilError::command("Destination cloud URL missing bucket."))?;
    let dst_obj = dst_url
        .object_name()
        .ok_or_else(|| GsutilError::command("Destination cloud URL missing object name."))?;

    let src_api = api.for_provider(src_url.scheme())?;
    let src_meta = src_api
        .get_object_metadata(src_bucket, src_obj, src_url.generation(), None)
        .await?;

    if cfg.delete_source_after_copy && !cfg.quiet {
        maybe_warn_early_deletion(src_url, &src_meta);
    }

    let cross_provider = src_url.scheme() != dst_url.scheme();
    if cfg.daisy_chain || cross_provider {
        return copy_cloud_daisy_chain(
            api, boto, cfg, src_url, &src_meta, dst_url, dst_bucket, dst_obj,
        )
        .await;
    }

    let mut dst_meta = src_meta.clone();
    dst_meta.bucket = Some(dst_bucket.to_string());
    dst_meta.name = Some(dst_obj.to_string());
    if let Some(ref sc) = cfg.storage_class {
        dst_meta.storage_class = Some(normalize_storage_class(sc));
    }
    if !cfg.preserve_acl {
        dst_meta.acl = None;
    }
    apply_custom_headers(&mut dst_meta, &cfg.headers);

    let copy_opts = CopyOptions {
        src_generation: src_url.generation().map(ToString::to_string),
        canned_acl: cfg.canned_acl.clone(),
        preconditions: effective_upload_preconditions(cfg),
        max_bytes_per_call: None,
        encryption_key: cfg.encryption_key.clone(),
        decryption_key: cfg.decryption_key.clone(),
        fields: None,
    };

    let dst_api = api.for_provider(dst_url.scheme())?;
    if cfg.no_clobber
        && dst_api
            .get_object_metadata(dst_bucket, dst_obj, None, Some(&["name".to_string()]))
            .await
            .is_ok()
    {
        return Ok(CopyItemResult {
            src_url: src_url.url_string(),
            dst_url: dst_url.url_string(),
            bytes_transferred: 0,
            created_url: None,
            skipped: true,
        });
    }

    let copied = match dst_api.copy_object(&src_meta, &dst_meta, &copy_opts).await {
        Ok(obj) => obj,
        Err(GsutilError::Service(se))
            if cfg.no_clobber && se.kind == ServiceErrorKind::Precondition =>
        {
            return Ok(CopyItemResult {
                src_url: src_url.url_string(),
                dst_url: dst_url.url_string(),
                bytes_transferred: 0,
                created_url: None,
                skipped: true,
            });
        }
        Err(e) => return Err(e),
    };

    let created_url = copied
        .generation
        .as_deref()
        .map(|g| format!("{}#{g}", dst_url.versionless_url_string()));

    Ok(CopyItemResult {
        src_url: src_url.url_string(),
        dst_url: dst_url.url_string(),
        bytes_transferred: copied.size_bytes(),
        created_url,
        skipped: false,
    })
}

#[allow(clippy::too_many_arguments)]
async fn copy_cloud_daisy_chain(
    api: &dyn CloudApi,
    boto: &BotoConfig,
    cfg: &CopyConfig,
    src_url: &StorageUrl,
    src_meta: &Object,
    dst_url: &StorageUrl,
    dst_bucket: &str,
    dst_obj: &str,
) -> Result<CopyItemResult> {
    let src_bucket = src_url.bucket_name().unwrap_or("");
    let src_obj = src_url.object_name().unwrap_or("");
    let src_api = api.for_provider(src_url.scheme())?;
    let dst_api = api.for_provider(dst_url.scheme())?;
    let gzip_encoded = is_gzip_encoded(src_meta);

    let mut stream = src_api
        .get_object_media_stream(
            src_bucket,
            src_obj,
            &DownloadOptions {
                generation: src_url.generation().map(ToString::to_string),
                start_byte: None,
                end_byte: None,
                compressed_encoding: gzip_encoded,
                strategy: DownloadStrategy::OneShot,
                decryption_key: cfg.decryption_key.clone(),
                progress_callback: None,
            },
        )
        .await?;

    let mut dst_meta = src_meta.clone();
    dst_meta.bucket = Some(dst_bucket.to_string());
    dst_meta.name = Some(dst_obj.to_string());
    dst_meta.generation = None;
    dst_meta.metageneration = None;
    if let Some(ref sc) = cfg.storage_class {
        dst_meta.storage_class = Some(normalize_storage_class(sc));
    }
    if !cfg.preserve_acl {
        dst_meta.acl = None;
    }
    apply_custom_headers(&mut dst_meta, &cfg.headers);

    let opts = UploadOptions {
        canned_acl: cfg.canned_acl.clone(),
        preconditions: effective_upload_preconditions(cfg),
        encryption_key: cfg.encryption_key.clone(),
        fields: None,
        // Daisy-chain preserves the source object's wire bytes & `contentEncoding` as-is.
        gzip_encoded: false,
        resumable_session_uri: None,
        session_uri_callback: None,
        progress_callback: cfg.ui.as_ref().map(|u| u.progress_callback()),
        total_size: Some(src_meta.size_bytes()),
        chunk_size: Some(effective_resumable_chunk_size(boto)),
        streamed_crc32c_out: None,
    };

    // Constant ~256 KiB RAM streaming pipe from source download stream into destination upload.
    let (mut pipe_w, pipe_r) = tokio::io::duplex(256 * 1024);
    let pump = tokio::spawn(async move {
        let mut crc = Crc32cHasher::new();
        let mut md5 = Md5Hasher::new();
        let mut len = 0u64;
        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res?;
            crc.update(&chunk);
            md5.update(&chunk);
            len += chunk.len() as u64;
            pipe_w.write_all(&chunk).await?;
        }
        pipe_w.shutdown().await?;
        Ok::<(u32, String, u64), GsutilError>((crc.finalize(), md5.finalize_base64(), len))
    });

    let upload_fut = dst_api.upload_object_streaming(Box::new(pipe_r), &dst_meta, &opts);
    let (pump_join, upload_res) = tokio::join!(pump, upload_fut);

    let uploaded = match upload_res {
        Ok(obj) => obj,
        Err(GsutilError::Service(se))
            if cfg.no_clobber && se.kind == ServiceErrorKind::Precondition =>
        {
            return Ok(CopyItemResult {
                src_url: src_url.url_string(),
                dst_url: dst_url.url_string(),
                bytes_transferred: 0,
                created_url: None,
                skipped: true,
            });
        }
        Err(e) => return Err(e),
    };

    let (local_crc, local_md5, len) = pump_join
        .map_err(|e| GsutilError::command(format!("Daisy-chain stream pump failed: {e}")))??;

    let check_mode = CheckHashesMode::from_config(boto);
    if let Err(err) = validate_hashes(
        check_mode,
        "daisy-chain stream",
        &src_url.url_string(),
        Some(local_crc),
        Some(&local_md5),
        src_meta.crc32c.as_deref(),
        src_meta.md5_hash.as_deref(),
    ) {
        let _ = dst_api
            .delete_object(dst_bucket, dst_obj, uploaded.generation.as_deref(), None)
            .await;
        return Err(err);
    }

    if let Err(err) = validate_hashes(
        check_mode,
        &src_url.url_string(),
        &dst_url.url_string(),
        Some(local_crc),
        Some(&local_md5),
        uploaded.crc32c.as_deref(),
        uploaded.md5_hash.as_deref(),
    ) {
        let _ = dst_api
            .delete_object(dst_bucket, dst_obj, uploaded.generation.as_deref(), None)
            .await;
        return Err(err);
    }

    let created_url = uploaded
        .generation
        .as_deref()
        .map(|g| format!("{}#{g}", dst_url.versionless_url_string()));

    Ok(CopyItemResult {
        src_url: src_url.url_string(),
        dst_url: dst_url.url_string(),
        bytes_transferred: len,
        created_url,
        skipped: false,
    })
}

// ---------------------------------------------------------------------------
// Local -> Local
// ---------------------------------------------------------------------------

fn copy_local_to_local(
    cfg: &CopyConfig,
    src_url: &StorageUrl,
    dst_url: &StorageUrl,
) -> Result<CopyItemResult> {
    let src_path = Path::new(src_url.object_name().unwrap_or(""));
    let dst_path_str = dst_url.object_name().unwrap_or("");
    let dst_path = Path::new(dst_path_str);

    // Copying a local file into an existing FIFO: open FIFO for writing directly.
    if dst_url.is_fifo() {
        let mut src_f = File::open(src_path)?;
        let mut dst_f = OpenOptions::new().write(true).open(dst_path)?;
        let bytes = std::io::copy(&mut src_f, &mut dst_f)?;
        dst_f.flush()?;
        return Ok(CopyItemResult {
            src_url: src_url.url_string(),
            dst_url: dst_url.url_string(),
            bytes_transferred: bytes,
            created_url: None,
            skipped: false,
        });
    }

    if cfg.no_clobber && dst_path.exists() {
        return Ok(CopyItemResult {
            src_url: src_url.url_string(),
            dst_url: dst_url.url_string(),
            bytes_transferred: 0,
            created_url: None,
            skipped: true,
        });
    }

    if let Some(parent) = dst_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let temp_path = PathBuf::from(format!("{dst_path_str}{TEMP_FILE_SUFFIX}"));
    let bytes = fs::copy(src_path, &temp_path)?;
    fs::rename(&temp_path, dst_path)?;

    if cfg.preserve_posix {
        let attrs = read_local_posix_attributes(src_path)?;
        apply_posix_to_local_file(dst_path, &attrs)?;
    } else if cfg.preserve_mtime {
        let attrs = read_local_posix_attributes(src_path)?;
        if attrs.mtime.is_some() {
            apply_posix_to_local_file(
                dst_path,
                &crate::posix::PosixAttributes {
                    mtime: attrs.mtime,
                    ..Default::default()
                },
            )?;
        }
    }

    Ok(CopyItemResult {
        src_url: src_url.url_string(),
        dst_url: dst_url.url_string(),
        bytes_transferred: bytes,
        created_url: None,
        skipped: false,
    })
}

// ---------------------------------------------------------------------------
// URL Expansion & Destination Path Construction
// ---------------------------------------------------------------------------

async fn expand_copy_pairs(
    api: &dyn CloudApi,
    src_url_strs: &[String],
    dst_base: &StorageUrl,
    cfg: &CopyConfig,
    manifest: Option<&ManifestWriter>,
) -> Result<Vec<(StorageUrl, StorageUrl)>> {
    let multi_src_arg = src_url_strs.len() > 1 || src_url_strs.iter().any(|s| contains_wildcard(s));

    let dst_is_container = match dst_base {
        StorageUrl::File(f) => f.is_directory() || f.object_name.ends_with('/'),
        StorageUrl::Cloud(c) => {
            c.is_bucket() || c.object_name.as_deref().is_some_and(|o| o.ends_with('/'))
        }
    };

    let mut pairs = Vec::new();
    for raw_src in src_url_strs {
        let parsed = StorageUrl::parse(raw_src)?;
        match &parsed {
            StorageUrl::File(f) if f.is_stream => {
                pairs.push((parsed.clone(), dst_base.clone()));
            }
            StorageUrl::File(f) => {
                let src_is_dir = Path::new(&f.object_name).is_dir();
                let expanded = expand_local_source(
                    &f.object_name,
                    cfg.recursive,
                    cfg.skip_unsupported,
                    cfg.exclude_symlinks,
                )?;
                let treat_dst_as_container =
                    dst_is_container || multi_src_arg || src_is_dir || expanded.len() > 1;
                for (local_path, rel_path) in expanded {
                    let s_url = StorageUrl::parse(&local_path.to_string_lossy())?;
                    let d_url =
                        resolve_destination_url(dst_base, &rel_path, treat_dst_as_container)?;
                    pairs.push((s_url, d_url));
                }
            }
            StorageUrl::Cloud(_) => {
                let expanded =
                    expand_cloud_source(api, &parsed, cfg.recursive, cfg.skip_unsupported).await?;
                let src_is_prefix =
                    parsed.is_bucket() || parsed.object_name().is_some_and(|o| o.ends_with('/'));
                let treat_dst_as_container =
                    dst_is_container || multi_src_arg || src_is_prefix || expanded.len() > 1;
                for (c_url, rel_path) in expanded {
                    if dst_base.is_file_url() && has_parent_dir_traversal(&rel_path) {
                        let msg = format!(
                            "Skipping copy of source URL {c_url} because it would be copied \
                             outside the expected destination directory: {}.",
                            dst_base.object_name().unwrap_or("")
                        );
                        if !cfg.quiet {
                            eprintln!("{msg}");
                        }
                        if let Some(m) = manifest {
                            let ts = Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
                            m.record(
                                &c_url.url_string(),
                                "",
                                &ts,
                                &ts,
                                "",
                                "",
                                0,
                                0,
                                "skip",
                                &msg,
                            );
                        }
                        continue;
                    }
                    let d_url =
                        resolve_destination_url(dst_base, &rel_path, treat_dst_as_container)?;
                    pairs.push((c_url, d_url));
                }
            }
        }
    }

    Ok(pairs)
}

fn has_parent_dir_traversal(rel_path: &str) -> bool {
    let mut depth: i32 = 0;
    for comp in Path::new(rel_path).components() {
        match comp {
            std::path::Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            std::path::Component::Normal(_) => depth += 1,
            _ => {}
        }
    }
    false
}

fn expand_local_source(
    raw_path: &str,
    recursive: bool,
    skip_unsupported: bool,
    exclude_symlinks: bool,
) -> Result<Vec<(PathBuf, String)>> {
    if contains_wildcard(raw_path) {
        // Compute longest static (non-wildcard) directory prefix as base_dir.
        let mut static_parts = Vec::new();
        for comp in Path::new(raw_path).components() {
            let s = comp.as_os_str().to_string_lossy();
            if contains_wildcard(&s) {
                break;
            }
            static_parts.push(comp);
        }
        let base_dir: PathBuf = if static_parts.is_empty() {
            PathBuf::from(".")
        } else {
            static_parts.into_iter().collect()
        };
        let has_double_star = raw_path.contains("**");
        let normalized_pat = raw_path.replace('\\', "/");
        let matcher = WildcardMatcher::compile(&normalized_pat)?;
        let mut results = Vec::new();
        let mut visited = HashSet::new();

        // Match Python gsutil wildcard expansion semantics:
        // - If a wildcard directly matches a FILE (e.g. `/*.txt`, `/**/*.dat`),
        //   it is treated as a top-level file source (flattened to `file_name()`).
        // - If a wildcard directly matches a DIRECTORY (e.g. `/*`, `/sub*`) and `-r`
        //   is set, recurse into that directory preserving `<dir_name>/<rel_path>`.
        #[allow(clippy::too_many_arguments)]
        fn walk_wildcard_local(
            dir: &Path,
            matcher: &WildcardMatcher,
            recursive: bool,
            has_double_star: bool,
            skip_unsupported: bool,
            exclude_symlinks: bool,
            visited: &mut HashSet<PathBuf>,
            results: &mut Vec<(PathBuf, String)>,
        ) -> Result<()> {
            let mut entries: Vec<_> = fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
            entries.sort_by_key(|e| e.file_name());
            for entry in entries {
                let path = entry.path();
                let sym_meta = match fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(_) if skip_unsupported => continue,
                    Err(e) => return Err(e.into()),
                };
                if sym_meta.file_type().is_symlink() && (exclude_symlinks || skip_unsupported) {
                    if exclude_symlinks {
                        eprintln!("Skipping symbolic link {}...", path.display());
                    }
                    continue;
                }
                let meta = match fs::metadata(&path) {
                    Ok(m) => m,
                    Err(_) if skip_unsupported || exclude_symlinks => continue,
                    Err(e) => return Err(e.into()),
                };
                let p_str = path.to_string_lossy().replace('\\', "/");
                let matched = matcher.is_match(&p_str);
                if meta.is_dir() {
                    if matched && !has_double_star {
                        if recursive {
                            let dir_name = path
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            if let Ok(canon) = fs::canonicalize(&path) {
                                if !visited.insert(canon) {
                                    continue;
                                }
                            }
                            walk_local_dir(
                                &path,
                                true,
                                skip_unsupported,
                                exclude_symlinks,
                                visited,
                                &mut |file_path| {
                                    if let Ok(rel) = file_path.strip_prefix(&path) {
                                        let rel_unix = rel.to_string_lossy().replace('\\', "/");
                                        let rel_with_root = if dir_name.is_empty() {
                                            rel_unix
                                        } else {
                                            format!("{dir_name}/{rel_unix}")
                                        };
                                        results.push((file_path.to_path_buf(), rel_with_root));
                                    }
                                },
                            )?;
                        }
                        // Without `-r`, matching a directory is omitted (just like Python gsutil).
                    } else if has_double_star {
                        if let Ok(canon) = fs::canonicalize(&path) {
                            if !visited.insert(canon) {
                                continue;
                            }
                        }
                        walk_wildcard_local(
                            &path,
                            matcher,
                            recursive,
                            has_double_star,
                            skip_unsupported,
                            exclude_symlinks,
                            visited,
                            results,
                        )?;
                    }
                } else if meta.is_file() {
                    if matched {
                        let fname = path
                            .file_name()
                            .map(|f| f.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        results.push((path, fname));
                    }
                } else if !skip_unsupported {
                    return Err(GsutilError::command(format!(
                        "Unsupported file type: {}",
                        path.display()
                    )));
                }
            }
            Ok(())
        }

        walk_wildcard_local(
            &base_dir,
            &matcher,
            recursive,
            has_double_star,
            skip_unsupported,
            exclude_symlinks,
            &mut visited,
            &mut results,
        )?;
        return Ok(results);
    }

    let path = Path::new(raw_path);
    if !path.exists() {
        return Err(GsutilError::command_informational(
            gsutil_core::error::no_urls_matched_target(raw_path),
        ));
    }

    if path.is_dir() {
        if !recursive {
            return Err(GsutilError::command(format!(
                "Omitting directory \"file://{raw_path}\". (Did you mean to do cp -r?)"
            )));
        }
        let dir_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut results = Vec::new();
        let mut visited = HashSet::new();
        if let Ok(canon) = fs::canonicalize(path) {
            visited.insert(canon);
        }
        walk_local_dir(
            path,
            true,
            skip_unsupported,
            exclude_symlinks,
            &mut visited,
            &mut |file_path| {
                if let Ok(rel) = file_path.strip_prefix(path) {
                    let rel_unix = rel.to_string_lossy().replace('\\', "/");
                    let rel_with_root = if dir_name.is_empty() {
                        rel_unix
                    } else {
                        format!("{dir_name}/{rel_unix}")
                    };
                    results.push((file_path.to_path_buf(), rel_with_root));
                }
            },
        )?;
        return Ok(results);
    }

    let fname = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| raw_path.to_string());
    Ok(vec![(path.to_path_buf(), fname)])
}

fn walk_local_dir<F>(
    dir: &Path,
    recursive: bool,
    skip_unsupported: bool,
    exclude_symlinks: bool,
    visited_dirs: &mut HashSet<PathBuf>,
    cb: &mut F,
) -> Result<()>
where
    F: FnMut(&Path),
{
    let mut entries: Vec<_> = fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let sym_meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) if skip_unsupported => continue,
            Err(e) => return Err(e.into()),
        };
        if sym_meta.file_type().is_symlink() && (exclude_symlinks || skip_unsupported) {
            if exclude_symlinks {
                eprintln!("Skipping symbolic link {}...", path.display());
            }
            continue;
        }
        // Follow symlinks by default (matching Python gsutil cp -r).
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) if skip_unsupported || exclude_symlinks => continue,
            Err(e) => return Err(e.into()),
        };
        if meta.is_dir() {
            if recursive {
                if let Ok(canon) = fs::canonicalize(&path) {
                    if !visited_dirs.insert(canon) {
                        continue;
                    }
                }
                walk_local_dir(
                    &path,
                    recursive,
                    skip_unsupported,
                    exclude_symlinks,
                    visited_dirs,
                    cb,
                )?;
            }
        } else if meta.is_file() {
            cb(&path);
        } else if !skip_unsupported {
            return Err(GsutilError::command(format!(
                "Unsupported file type: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

async fn expand_cloud_source(
    api: &dyn CloudApi,
    src_url: &StorageUrl,
    recursive: bool,
    skip_unsupported: bool,
) -> Result<Vec<(StorageUrl, String)>> {
    let bucket = src_url
        .bucket_name()
        .ok_or_else(|| GsutilError::command("Cloud source URL must specify a bucket."))?;
    let scheme = src_url.scheme();
    let src_api = api.for_provider(scheme)?;

    if src_url.is_bucket() {
        if !recursive {
            return Err(GsutilError::command(format!(
                "Omitting bucket \"{src_url}\". (Did you mean to do cp -r?)"
            )));
        }
        let listed = src_api
            .list_objects(
                bucket,
                &ListObjectsOptions {
                    prefix: None,
                    delimiter: None,
                    all_versions: false,
                    fields: None,
                },
            )
            .await?;
        let mut results = Vec::new();
        for item in listed {
            if let CsObjectOrPrefix::Object(obj) = item {
                let Some(name) = obj.name.as_deref() else {
                    continue;
                };
                let u = StorageUrl::parse(&format!("{scheme}://{bucket}/{name}"))?;
                if skip_unsupported && u.is_cloud_subdir_placeholder(Some(obj.size_bytes())) {
                    continue;
                }
                // `cp -r gs://b1 gs://b2` or `cp -r gs://b1 /dir` nests under `<bucket>/<name>`.
                results.push((u, format!("{bucket}/{name}")));
            }
        }
        return Ok(results);
    }

    let obj_name = src_url.object_name().unwrap_or("");
    if contains_wildcard(obj_name) {
        let filter = build_bucket_filter_strings(obj_name);
        let matcher = WildcardMatcher::compile(obj_name)?;
        // Static directory prefix before the first wildcard component (e.g. "a/b/" for "a/b/*").
        let static_prefix_dir = filter
            .prefix
            .as_deref()
            .and_then(|p| p.rfind('/').map(|i| p[..=i].to_string()))
            .unwrap_or_default();
        let listed = src_api
            .list_objects(
                bucket,
                &ListObjectsOptions {
                    prefix: filter.prefix,
                    delimiter: if recursive { None } else { filter.delimiter },
                    all_versions: false,
                    fields: None,
                },
            )
            .await?;
        let mut results = Vec::new();
        for item in listed {
            if let CsObjectOrPrefix::Object(obj) = item {
                let Some(name) = obj.name.as_deref() else {
                    continue;
                };
                if !matcher.is_match(name) {
                    continue;
                }
                let u = StorageUrl::parse(&format!("{scheme}://{bucket}/{name}"))?;
                if skip_unsupported && u.is_cloud_subdir_placeholder(Some(obj.size_bytes())) {
                    continue;
                }
                let rel = if recursive {
                    name.strip_prefix(&static_prefix_dir)
                        .unwrap_or(name)
                        .to_string()
                } else {
                    name.rsplit('/').next().unwrap_or(name).to_string()
                };
                results.push((u, rel));
            }
        }
        return Ok(results);
    }

    if recursive {
        let prefix = if obj_name.ends_with('/') {
            obj_name.to_string()
        } else {
            format!("{obj_name}/")
        };
        let listed = src_api
            .list_objects(
                bucket,
                &ListObjectsOptions {
                    prefix: Some(prefix.clone()),
                    delimiter: None,
                    all_versions: false,
                    fields: None,
                },
            )
            .await?;
        let mut results = Vec::new();
        let base_leaf = strip_one_slash(obj_name).rsplit('/').next().unwrap_or("");
        for item in listed {
            if let CsObjectOrPrefix::Object(obj) = item {
                let Some(name) = obj.name.as_deref() else {
                    continue;
                };
                let u = StorageUrl::parse(&format!("{scheme}://{bucket}/{name}"))?;
                if skip_unsupported && u.is_cloud_subdir_placeholder(Some(obj.size_bytes())) {
                    continue;
                }
                let suffix = name.strip_prefix(&prefix).unwrap_or(name);
                let rel = if base_leaf.is_empty() {
                    suffix.to_string()
                } else {
                    format!("{base_leaf}/{suffix}")
                };
                results.push((u, rel));
            }
        }
        if !results.is_empty() {
            return Ok(results);
        }
    }

    let rel = obj_name.rsplit('/').next().unwrap_or(obj_name).to_string();
    Ok(vec![(src_url.clone(), rel)])
}

fn resolve_destination_url(
    dst_base: &StorageUrl,
    rel_path: &str,
    dst_is_container: bool,
) -> Result<StorageUrl> {
    if !dst_is_container {
        return Ok(dst_base.clone());
    }
    match dst_base {
        StorageUrl::File(f) => {
            let joined = Path::new(&f.object_name).join(rel_path);
            StorageUrl::parse(&joined.to_string_lossy())
        }
        StorageUrl::Cloud(c) => {
            let bucket = c.bucket_name.as_deref().unwrap_or("");
            let base_prefix = c.object_name.as_deref().unwrap_or("");
            let trimmed_base = strip_one_slash(base_prefix);
            let trimmed_rel = rel_path.trim_start_matches('/');
            let full_obj = if trimmed_base.is_empty() {
                trimmed_rel.to_string()
            } else {
                format!("{trimmed_base}/{trimmed_rel}")
            };
            StorageUrl::parse(&format!("{}://{bucket}/{full_obj}", c.scheme))
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_upload_metadata(
    bucket: &str,
    object_name: &str,
    cfg: &CopyConfig,
    gzip_encoded: bool,
    posix: Option<&crate::posix::PosixAttributes>,
) -> Object {
    let mut meta = Object {
        bucket: Some(bucket.to_string()),
        name: Some(object_name.to_string()),
        storage_class: cfg.storage_class.as_deref().map(normalize_storage_class),
        content_encoding: if gzip_encoded {
            Some("gzip".to_string())
        } else {
            None
        },
        ..Default::default()
    };
    if let Some(attrs) = posix {
        if !attrs.is_empty() {
            let map = meta.metadata.get_or_insert_with(BTreeMap::new);
            serialize_posix_to_metadata(attrs, map);
        }
    }
    apply_custom_headers(&mut meta, &cfg.headers);
    if meta.content_type.is_none() {
        meta.content_type = Some(infer_content_type(object_name).to_string());
    } else if meta.content_type.as_deref() == Some("") {
        meta.content_type = Some("application/octet-stream".to_string());
    }
    meta
}

fn infer_content_type(path: &str) -> &'static str {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "txt" | "log" | "md" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "csv" => "text/csv",
        "gif" => "image/gif",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "py" => "text/x-python",
        _ => "application/octet-stream",
    }
}

fn apply_custom_headers(meta: &mut Object, headers: &BTreeMap<String, String>) {
    for (k, v) in headers {
        let lower = k.to_ascii_lowercase();
        match lower.as_str() {
            "content-type" => meta.content_type = Some(v.clone()),
            "cache-control" => meta.cache_control = Some(v.clone()),
            "content-disposition" => meta.content_disposition = Some(v.clone()),
            "content-encoding" => meta.content_encoding = Some(v.clone()),
            "content-language" => meta.content_language = Some(v.clone()),
            "custom-time" => meta.custom_time = Some(v.clone()),
            _ if lower.starts_with("x-goog-meta-") => {
                let key = k[12..].to_string();
                meta.metadata
                    .get_or_insert_with(BTreeMap::new)
                    .insert(key, v.clone());
            }
            _ => {}
        }
    }
}

fn effective_upload_preconditions(cfg: &CopyConfig) -> Option<Preconditions> {
    if cfg.no_clobber {
        let mut pre = cfg.preconditions.clone().unwrap_or_default();
        pre.gen_match = Some(0);
        Some(pre)
    } else {
        cfg.preconditions.clone()
    }
}

fn encryption_key_sha256(key: Option<&EncryptionKey>) -> Option<&str> {
    match key {
        Some(EncryptionKey::Csek { key_sha256_b64, .. }) => Some(key_sha256_b64.as_str()),
        Some(EncryptionKey::Cmek { kms_key_name }) => Some(kms_key_name.as_str()),
        None => None,
    }
}

fn is_gzip_encoded(obj: &Object) -> bool {
    obj.content_encoding
        .as_deref()
        .is_some_and(|e| e.eq_ignore_ascii_case("gzip"))
}

fn maybe_warn_early_deletion(src_url: &StorageUrl, src_meta: &Object) {
    let sc = src_meta
        .storage_class
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let min_days: Option<i64> = match sc.as_str() {
        "nearline" => Some(30),
        "coldline" => Some(90),
        "archive" => Some(365),
        _ => None,
    };
    let Some(days) = min_days else { return };
    let created_secs = src_meta
        .time_created
        .as_deref()
        .and_then(crate::posix::parse_rfc3339_to_epoch_secs);
    let too_young = match created_secs {
        Some(ts) => (Utc::now().timestamp() - ts) < days * 86_400,
        None => true,
    };
    if too_young {
        eprintln!(
            "Warning: moving {sc} object {src_url} may incur an early deletion charge, \
             because the original object is less than {days} days old according to the \
             local system time."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_api::MockCloudApi;
    use std::io::Cursor;
    use std::sync::atomic::Ordering;

    fn test_boto(dir: &Path) -> BotoConfig {
        let mut cfg = BotoConfig::new();
        cfg.set(
            "GSUtil",
            "resumable_tracker_dir",
            dir.join("trackers").to_string_lossy().into_owned(),
        );
        cfg
    }

    #[tokio::test]
    async fn test_local_to_cloud_simple_resumable_and_gzip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut boto = test_boto(tmp.path());
        boto.set("GSUtil", "resumable_threshold", "100");
        boto.set("GSUtil", "parallel_composite_upload_threshold", "0");

        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");

        let small_path = tmp.path().join("small.txt");
        fs::write(&small_path, b"tiny").unwrap();

        let big_path = tmp.path().join("big.txt");
        let big_data = vec![b'A'; 256];
        fs::write(&big_path, &big_data).unwrap();

        // Simple upload with -Z gzip and -P POSIX and -L manifest
        let manifest_path = tmp.path().join("manifest.csv");
        let res = run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec![small_path.to_string_lossy().into_owned()],
                dst_url: "gs://bkt/small.txt".into(),
                gzip_mode: GzipMode::All,
                preserve_posix: true,
                manifest_path: Some(manifest_path.clone()),
                print_created_version: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(res.succeeded, 1);
        assert!(res.items[0].created_url.as_deref().unwrap().contains('#'));
        assert_eq!(api.upload_calls.load(Ordering::SeqCst), 1);

        let stored = api.get_stored("bkt", "small.txt").unwrap();
        assert_eq!(stored.metadata.content_encoding.as_deref(), Some("gzip"));
        assert!(stored
            .metadata
            .metadata
            .as_ref()
            .unwrap()
            .contains_key(crate::posix::MTIME_ATTR));
        // Manifest written
        let manifest_text = fs::read_to_string(&manifest_path).unwrap();
        assert!(manifest_text.contains(MANIFEST_CSV_HEADER));
        assert!(manifest_text.contains(",OK,"));

        // Resumable upload (> 100 bytes)
        run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec![big_path.to_string_lossy().into_owned()],
                dst_url: "gs://bkt/big.txt".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(api.resumable_upload_calls.load(Ordering::SeqCst), 1);

        // Download gzipped object -> automatically decompressed!
        let dl_path = tmp.path().join("small_dl.txt");
        run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec!["gs://bkt/small.txt".into()],
                dst_url: dl_path.to_string_lossy().into_owned(),
                preserve_posix: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(fs::read(&dl_path).unwrap(), b"tiny");
    }

    #[tokio::test]
    async fn test_parallel_composite_upload_and_temp_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let mut boto = test_boto(tmp.path());
        boto.set("GSUtil", "parallel_composite_upload_threshold", "500");
        boto.set("GSUtil", "parallel_composite_upload_component_size", "200");

        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");

        let src_path = tmp.path().join("large.bin");
        let payload: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
        fs::write(&src_path, &payload).unwrap();

        let res = run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec![src_path.to_string_lossy().into_owned()],
                dst_url: "gs://bkt/large.bin".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(res.succeeded, 1);
        assert_eq!(api.compose_calls.load(Ordering::SeqCst), 1);
        // All temporary component objects must have been deleted!
        let remaining = api.list_all_object_names("bkt");
        assert_eq!(remaining, vec!["large.bin".to_string()]);
        let stored = api.get_stored("bkt", "large.bin").unwrap();
        assert_eq!(stored.data.as_ref(), payload.as_slice());
    }

    #[tokio::test]
    async fn test_sliced_object_download() {
        let tmp = tempfile::tempdir().unwrap();
        let mut boto = test_boto(tmp.path());
        boto.set("GSUtil", "sliced_object_download_threshold", "500");
        boto.set("GSUtil", "sliced_object_download_component_size", "200");
        boto.set("GSUtil", "sliced_object_download_max_components", "4");

        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");
        let payload: Vec<u8> = (0..1000).map(|i| (i % 199) as u8).collect();
        api.put_object("bkt", "sliced.bin", &payload);

        let dst_path = tmp.path().join("sliced_out.bin");
        run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec!["gs://bkt/sliced.bin".into()],
                dst_url: dst_path.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert!(api.range_download_calls.load(Ordering::SeqCst) >= 2);
        assert_eq!(fs::read(&dst_path).unwrap(), payload);
        // Temp _.gstmp file must not linger.
        assert!(!PathBuf::from(format!("{}{TEMP_FILE_SUFFIX}", dst_path.display())).exists());
    }

    #[tokio::test]
    async fn test_hash_mismatch_upload_and_download() {
        let tmp = tempfile::tempdir().unwrap();
        let mut boto = test_boto(tmp.path());
        boto.set("GSUtil", "parallel_composite_upload_threshold", "0");
        boto.set("GSUtil", "sliced_object_download_threshold", "0");

        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");

        // Upload hash mismatch
        api.set_corrupt_upload_crc(true);
        let src_path = tmp.path().join("a.txt");
        fs::write(&src_path, b"integrity-check").unwrap();
        let err = run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec![src_path.to_string_lossy().into_owned()],
                dst_url: "gs://bkt/a.txt".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, GsutilError::HashMismatch(_)));
        // Corrupt object should have been deleted.
        assert!(api.get_stored("bkt", "a.txt").is_none());

        // Download hash mismatch
        api.set_corrupt_upload_crc(false);
        api.put_object("bkt", "good.txt", b"valid-data");
        api.set_corrupt_download_bytes(true);
        let dl_path = tmp.path().join("corrupt.txt");
        let err2 = run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec!["gs://bkt/good.txt".into()],
                dst_url: dl_path.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err2, GsutilError::HashMismatch(_)));
        assert!(!dl_path.exists());
    }

    #[tokio::test]
    async fn test_daisy_chain_and_no_clobber() {
        let tmp = tempfile::tempdir().unwrap();
        let boto = test_boto(tmp.path());
        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("src-b");
        api.create_bucket_sync("dst-b");
        api.put_object("src-b", "item.bin", b"daisy-payload");

        // Daisy-chain copy (-D)
        let res = run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec!["gs://src-b/item.bin".into()],
                dst_url: "gs://dst-b/item.bin".into(),
                daisy_chain: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(res.succeeded, 1);
        assert_eq!(api.copy_calls.load(Ordering::SeqCst), 0);
        assert_eq!(api.download_calls.load(Ordering::SeqCst), 1);
        assert_eq!(api.streaming_upload_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            api.get_stored("dst-b", "item.bin").unwrap().data,
            Bytes::from_static(b"daisy-payload")
        );

        // No-clobber (-n) skips existing destination object
        let res2 = run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec!["gs://src-b/item.bin".into()],
                dst_url: "gs://dst-b/item.bin".into(),
                no_clobber: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(res2.skipped, 1);
        assert_eq!(res2.succeeded, 0);
    }

    #[tokio::test]
    async fn test_streaming_upload_and_download_and_local_to_local() {
        let tmp = tempfile::tempdir().unwrap();
        let boto = test_boto(tmp.path());
        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");

        let dst = StorageUrl::parse("gs://bkt/streamed.txt").unwrap();
        let cfg = CopyConfig::default();
        let up = copy_stream_to_cloud(
            api.as_ref(),
            &boto,
            &cfg,
            Cursor::new(b"hello from stdin"),
            &dst,
        )
        .await
        .unwrap();
        assert_eq!(up.bytes_transferred, 16);

        let mut sink = Vec::new();
        copy_cloud_to_stream(api.as_ref(), &boto, &cfg, &dst, &mut sink)
            .await
            .unwrap();
        assert_eq!(sink, b"hello from stdin");

        // Local -> Local
        let f1 = tmp.path().join("f1.txt");
        let f2 = tmp.path().join("f2.txt");
        fs::write(&f1, b"local copy").unwrap();
        run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec![f1.to_string_lossy().into_owned()],
                dst_url: f2.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(fs::read(&f2).unwrap(), b"local copy");
    }

    #[tokio::test]
    async fn test_resumable_download_resumes_from_partial_gstmp() {
        let tmp = tempfile::tempdir().unwrap();
        let mut boto = test_boto(tmp.path());
        boto.set("GSUtil", "resumable_threshold", "100");
        boto.set("GSUtil", "sliced_object_download_threshold", "0");

        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");
        let payload: Vec<u8> = (0..500).map(|i| (i % 251) as u8).collect();
        let obj = api.put_object("bkt", "resume.bin", &payload);

        let dst_path = tmp.path().join("resume_out.bin");
        let temp_path = PathBuf::from(format!("{}{TEMP_FILE_SUFFIX}", dst_path.display()));
        // Simulate an interrupted download: first 200 bytes already on disk + matching tracker.
        fs::write(&temp_path, &payload[..200]).unwrap();
        let dst_url = StorageUrl::parse(&dst_path.to_string_lossy()).unwrap();
        let tracker = get_tracker_file_path(
            &boto,
            &dst_url,
            TrackerFileType::Download,
            "JSON",
            None,
            None,
        )
        .unwrap();
        crate::tracker::write_tracker_file(&tracker, &format!("{}\n", obj.etag.unwrap())).unwrap();

        run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec!["gs://bkt/resume.bin".into()],
                dst_url: dst_path.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Must have used a ranged download starting at byte 200 rather than full re-download.
        assert_eq!(api.range_download_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read(&dst_path).unwrap(), payload);
        assert!(!tracker.exists());
    }

    #[tokio::test]
    async fn test_sliced_download_resumes_completed_components() {
        let tmp = tempfile::tempdir().unwrap();
        let mut boto = test_boto(tmp.path());
        boto.set("GSUtil", "resumable_threshold", "100");
        boto.set("GSUtil", "sliced_object_download_threshold", "500");
        boto.set("GSUtil", "sliced_object_download_component_size", "250");
        boto.set("GSUtil", "sliced_object_download_max_components", "4");

        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");
        let payload: Vec<u8> = (0..1000).map(|i| (i % 199) as u8).collect();
        let obj = api.put_object("bkt", "sliced_resume.bin", &payload);

        let dst_path = tmp.path().join("sliced_resume_out.bin");
        let temp_path = PathBuf::from(format!("{}{TEMP_FILE_SUFFIX}", dst_path.display()));
        // Pre-populate full-size temp file where components 0 and 1 (bytes 0..500) are complete.
        let mut partial = vec![0u8; 1000];
        partial[..500].copy_from_slice(&payload[..500]);
        fs::write(&temp_path, &partial).unwrap();

        let dst_url = StorageUrl::parse(&dst_path.to_string_lossy()).unwrap();
        let parent_tracker = get_tracker_file_path(
            &boto,
            &dst_url,
            TrackerFileType::SlicedDownload,
            "JSON",
            None,
            None,
        )
        .unwrap();
        write_sliced_download_tracker(&parent_tracker, &obj, 4).unwrap();
        for (idx, pos) in [(0usize, 250u64), (1, 500), (2, 500), (3, 750)] {
            let ct = get_tracker_file_path(
                &boto,
                &dst_url,
                TrackerFileType::DownloadComponent,
                "JSON",
                None,
                Some(idx),
            )
            .unwrap();
            write_download_component_tracker(&ct, &obj, pos).unwrap();
        }

        run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec!["gs://bkt/sliced_resume.bin".into()],
                dst_url: dst_path.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Only components 2 and 3 should have been downloaded!
        assert_eq!(api.range_download_calls.load(Ordering::SeqCst), 2);
        assert_eq!(fs::read(&dst_path).unwrap(), payload);
    }

    #[tokio::test]
    async fn test_parallel_composite_upload_resumes_existing_components() {
        let tmp = tempfile::tempdir().unwrap();
        let mut boto = test_boto(tmp.path());
        boto.set("GSUtil", "parallel_composite_upload_threshold", "500");
        boto.set("GSUtil", "parallel_composite_upload_component_size", "250");

        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");

        let src_path = tmp.path().join("comp_resume.bin");
        let payload: Vec<u8> = (0..1000).map(|i| (i % 233) as u8).collect();
        fs::write(&src_path, &payload).unwrap();

        let src_url = StorageUrl::parse(&src_path.to_string_lossy()).unwrap();
        let dst_url = StorageUrl::parse("gs://bkt/comp_resume.bin").unwrap();
        let tracker_path = get_tracker_file_path(
            &boto,
            &dst_url,
            TrackerFileType::ParallelUpload,
            "JSON",
            Some(&src_url),
            None,
        )
        .unwrap();

        // Pre-upload component 0 and record it in the parallel upload tracker.
        let prefix = "resumedprefix";
        let comp0_name = format!("{PARALLEL_UPLOAD_TEMP_NAMESPACE}{prefix}_0");
        let comp0_meta = api.put_object("bkt", &comp0_name, &payload[..250]);
        write_parallel_upload_tracker(
            &tracker_path,
            &ParallelUploadTrackerData {
                encryption_key_sha256: None,
                random_prefix: prefix.to_string(),
                components: vec![ParallelUploadComponentEntry {
                    component_num: 0,
                    object_name: comp0_name,
                    generation: comp0_meta.generation,
                    crc32c: comp0_meta.crc32c,
                    size: 250,
                }],
            },
        )
        .unwrap();

        run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec![src_path.to_string_lossy().into_owned()],
                dst_url: "gs://bkt/comp_resume.bin".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Only 3 of 4 components should have been uploaded via resumable file streaming (component 0 was reused!).
        assert_eq!(api.resumable_upload_calls.load(Ordering::SeqCst), 3);
        assert_eq!(api.compose_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            api.get_stored("bkt", "comp_resume.bin")
                .unwrap()
                .data
                .as_ref(),
            payload.as_slice()
        );
        assert_eq!(
            api.list_all_object_names("bkt"),
            vec!["comp_resume.bin".to_string()]
        );
    }

    #[test]
    fn test_default_parallel_composite_threshold_is_disabled() {
        let boto = BotoConfig::new();
        assert_eq!(boto.parallel_composite_upload_threshold(), 0);
    }

    #[cfg(unix)]
    #[cfg(unix)]
    #[tokio::test]
    async fn test_cp_recursive_follows_and_excludes_symlinks() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let boto = test_boto(tmp.path());
        let src_dir = tmp.path().join("src_tree");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("real.txt"), b"real").unwrap();
        let target_file = tmp.path().join("outside.txt");
        fs::write(&target_file, b"linked-content").unwrap();
        symlink(&target_file, src_dir.join("link.txt")).unwrap();

        // Default: follow symlinks
        let api1 = Arc::new(MockCloudApi::new());
        api1.create_bucket_sync("b1");
        let res1 = run_copy(
            api1.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec![src_dir.to_string_lossy().into_owned()],
                dst_url: "gs://b1/".into(),
                recursive: true,
                exclude_symlinks: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(res1.succeeded, 2);
        assert_eq!(
            api1.get_stored("b1", "src_tree/link.txt")
                .unwrap()
                .data
                .as_ref(),
            b"linked-content"
        );

        // With `-e` (`exclude_symlinks: true`): skip symlink cleanly
        let api2 = Arc::new(MockCloudApi::new());
        api2.create_bucket_sync("b2");
        let res2 = run_copy(
            api2.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec![src_dir.to_string_lossy().into_owned()],
                dst_url: "gs://b2/".into(),
                recursive: true,
                exclude_symlinks: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(res2.succeeded, 1);
        assert!(api2.get_stored("b2", "src_tree/link.txt").is_none());
        assert!(api2.get_stored("b2", "src_tree/real.txt").is_some());
    }

    #[tokio::test]
    async fn test_gzip_transport_vs_storage_encoding() {
        let tmp = tempfile::tempdir().unwrap();
        let boto = test_boto(tmp.path());
        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");

        let src_path = tmp.path().join("doc.txt");
        let payload = b"repeated text for gzip compression test repeated text repeated text";
        fs::write(&src_path, payload).unwrap();

        // `-J` gzip transport: stored UNCOMPRESSED with `content_encoding == None`
        run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec![src_path.to_string_lossy().into_owned()],
                dst_url: "gs://bkt/transport.txt".into(),
                gzip_transport: GzipMode::All,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let stored_t = api.get_stored("bkt", "transport.txt").unwrap();
        assert_eq!(stored_t.metadata.content_encoding, None);
        assert_eq!(stored_t.data.as_ref(), payload.as_slice());

        // `-Z` gzip storage: stored COMPRESSED with `content_encoding == Some("gzip")`
        run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec![src_path.to_string_lossy().into_owned()],
                dst_url: "gs://bkt/stored.txt".into(),
                gzip_mode: GzipMode::All,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let stored_z = api.get_stored("bkt", "stored.txt").unwrap();
        assert_eq!(stored_z.metadata.content_encoding.as_deref(), Some("gzip"));
        assert_ne!(stored_z.data.as_ref(), payload.as_slice());
    }

    #[tokio::test]
    async fn test_resumable_upload_crash_persists_real_session_uri_and_resumes_offset() {
        let tmp = tempfile::tempdir().unwrap();
        let mut boto = test_boto(tmp.path());
        boto.set("GSUtil", "resumable_threshold", "100");
        boto.set("GSUtil", "parallel_composite_upload_threshold", "0");

        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("bkt");
        // Simulate crash after committing first 150 bytes of a 512-byte upload.
        api.set_fail_resumable_once_after(Some(150));

        let src_path = tmp.path().join("crash_resume.bin");
        let payload: Vec<u8> = (0..512).map(|i| (i % 241) as u8).collect();
        fs::write(&src_path, &payload).unwrap();

        let dst_url = StorageUrl::parse("gs://bkt/crash_resume.bin").unwrap();
        let tracker_path =
            get_tracker_file_path(&boto, &dst_url, TrackerFileType::Upload, "JSON", None, None)
                .unwrap();

        // Attempt 1: fails mid-upload, must leave real session URI in tracker file!
        let err = run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec![src_path.to_string_lossy().into_owned()],
                dst_url: "gs://bkt/crash_resume.bin".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("ResumableUploadException"));
        assert!(tracker_path.exists());
        let saved_uri = read_upload_tracker(&tracker_path, None).unwrap();
        assert!(
            saved_uri.starts_with("https://mock-gcs.local/upload/session-"),
            "Expected real session URI, got: {saved_uri}"
        );

        // Attempt 2: resumes from exact committed offset (150), completes, and deletes tracker!
        let ui = UIController::with_tty(false, false);
        let res = run_copy(
            api.clone(),
            &boto,
            &CopyConfig {
                src_urls: vec![src_path.to_string_lossy().into_owned()],
                dst_url: "gs://bkt/crash_resume.bin".into(),
                ui: Some(ui.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(res.succeeded, 1);
        assert_eq!(api.last_resumed_offset.load(Ordering::SeqCst), 150);
        assert!(!tracker_path.exists());
        assert_eq!(
            api.get_stored("bkt", "crash_resume.bin")
                .unwrap()
                .data
                .as_ref(),
            payload.as_slice()
        );
        assert_eq!(
            ui.format_final_summary(),
            "Operation completed over 1 objects/512 B."
        );
    }

    #[test]
    fn test_expand_local_wildcard_recursive_preserves_hierarchy() {
        let dir = tempfile::tempdir().unwrap();
        let root_txt = dir.path().join("root.txt");
        let nested_a = dir.path().join("l0_00/l1_00/obj_000.dat");
        let nested_b = dir.path().join("l0_01/l1_00/obj_000.dat");
        fs::create_dir_all(nested_a.parent().unwrap()).unwrap();
        fs::create_dir_all(nested_b.parent().unwrap()).unwrap();
        fs::write(&root_txt, b"r").unwrap();
        fs::write(&nested_a, b"a").unwrap();
        fs::write(&nested_b, b"b").unwrap();

        // `*` with `-r`: files at top level flatten to basename, matched dirs preserve hierarchy.
        let pattern = format!("{}/*", dir.path().display());
        let keys: Vec<String> = expand_local_source(&pattern, true, false, false)
            .unwrap()
            .into_iter()
            .map(|(_, k)| k)
            .collect();
        assert_eq!(
            keys,
            vec![
                "l0_00/l1_00/obj_000.dat",
                "l0_01/l1_00/obj_000.dat",
                "root.txt"
            ]
        );

        // `**/*.dat` with `-r`: directly matched files flatten to basename (matching Python gsutil).
        let dstar = format!("{}/**/*.dat", dir.path().display());
        let dstar_keys: Vec<String> = expand_local_source(&dstar, true, false, false)
            .unwrap()
            .into_iter()
            .map(|(_, k)| k)
            .collect();
        assert_eq!(dstar_keys, vec!["obj_000.dat", "obj_000.dat"]);

        // `*.txt` without `-r`: only top-level file matched.
        let non_rec = format!("{}/*.txt", dir.path().display());
        let non_rec_keys: Vec<String> = expand_local_source(&non_rec, false, false, false)
            .unwrap()
            .into_iter()
            .map(|(_, k)| k)
            .collect();
        assert_eq!(non_rec_keys, vec!["root.txt"]);
    }
}
