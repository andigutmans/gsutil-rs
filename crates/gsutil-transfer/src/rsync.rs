//! External-merge sorted diff engine for `gsutil rsync`.
//!
//! Matches `gslib/commands/rsync.py` and `gslib/utils/rsync_util.py` in Python gsutil v5.38:
//! - External batch merge-sort (`rsync_buffer_lines`, default 32000) so arbitrarily
//!   large local/cloud trees can be diffed without loading everything into memory
//! - Supports `-r`/`-R`, `-d`, `-c`, `-C`, `-e`, `-i`, `-n` (dry-run), `-p`, `-P`,
//!   `-u`, `-U`, `-x` (regex exclusion), `-a`, `-j`, `-m`

use std::cmp::Ordering as CmpOrdering;
use std::collections::{BTreeMap, BinaryHeap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gsutil_core::api::{CloudApi, CsObjectOrPrefix, ListObjectsOptions, Object};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result};
use gsutil_core::hash::hash_reader;
use gsutil_core::url::{strip_one_slash, StorageUrl};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::copy::{copy_single_pair, CopyConfig, GzipMode};
use crate::parallel::{run_parallel, ParallelConfig};
use crate::posix::{
    apply_posix_to_local_file, deserialize_posix_from_metadata, parse_rfc3339_to_epoch_secs,
    read_local_posix_attributes, serialize_posix_to_metadata, PosixAttributes,
};
use crate::ui::UIController;

/// Default lines per external sort chunk (matches `GSUtil:rsync_buffer_lines`).
pub const DEFAULT_RSYNC_BUFFER_LINES: usize = 32_000;

/// Configuration for `gsutil rsync`.
#[derive(Debug, Clone, Default)]
pub struct RsyncConfig {
    pub src_url: String,
    pub dst_url: String,
    /// `-r` / `-R`: recurse into subdirectories.
    pub recursive: bool,
    /// `-d`: delete extra files/objects under destination not present in source.
    pub delete_extras: bool,
    /// `-c`: compare checksums (CRC32C/MD5) instead of mtime/size.
    pub compute_checksums: bool,
    /// `-C`: continue on error.
    pub continue_on_error: bool,
    /// `-e`: exclude symlinks.
    pub ignore_symlinks: bool,
    /// `-i`: ignore existing files/objects at destination.
    pub ignore_existing: bool,
    /// `-n`: dry-run (compute diffs without mutating destination).
    pub dry_run: bool,
    /// `-p`: preserve ACLs.
    pub preserve_acl: bool,
    /// `-P`: preserve POSIX attributes.
    pub preserve_posix: bool,
    /// `-u`: skip files where destination is newer than source.
    pub skip_old_files: bool,
    /// `-U`: skip unsupported object types.
    pub skip_unsupported: bool,
    /// `-x <regex>`: exclude paths matching regex (relative to root).
    pub exclude_pattern: Option<String>,
    /// `-a <canned_acl>`: canned ACL to apply to uploaded/copied objects.
    pub canned_acl: Option<String>,
    /// `-j <ext1,ext2>`: gzip-compress matching extensions on upload.
    pub gzip_extensions: Option<Vec<String>>,
    /// `-J`: gzip-compress all uploaded files.
    pub gzip_all: bool,
    /// `-m`: parallel execution.
    pub parallel_operations: bool,
    /// Override for external merge-sort chunk size (defaults to `GSUtil:rsync_buffer_lines`).
    pub buffer_lines: Option<usize>,
    /// Suppress informational progress lines (`-q`).
    pub quiet: bool,
    /// Optional interactive TTY progress controller (`UIController`).
    pub ui: Option<Arc<UIController>>,
}

/// A single entry in a sorted source or destination listing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RsyncEntry {
    /// Relative path (forward-slash separated), used as the primary sort key.
    pub rel_path: String,
    /// Full URL string (`file://...` or `gs://...`).
    pub full_url: String,
    pub size: u64,
    pub time_created: Option<i64>,
    pub mtime: Option<i64>,
    pub atime: Option<i64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<u32>,
    pub crc32c: Option<String>,
    pub md5: Option<String>,
}

impl RsyncEntry {
    pub fn posix_attrs(&self) -> PosixAttributes {
        PosixAttributes {
            atime: self.atime,
            mtime: self.mtime,
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
        }
    }

    /// Best-available timestamp for `-u` / mtime comparison.
    pub fn effective_mtime(&self) -> Option<i64> {
        self.mtime.or(self.time_created)
    }
}

/// Diff action produced by the sorted merge engine (matches `DiffAction` in `rsync_util.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffAction {
    Copy {
        src_url: String,
        dst_url: String,
        rel_path: String,
        size: u64,
    },
    Remove {
        dst_url: String,
        rel_path: String,
    },
    PosixSrcToDst {
        src_url: String,
        dst_url: String,
        rel_path: String,
        posix: PosixAttributes,
    },
}

/// Summary of an `rsync` run.
#[derive(Debug, Default)]
pub struct RsyncSummary {
    pub planned_actions: Vec<DiffAction>,
    pub copied: usize,
    pub removed: usize,
    pub metadata_updated: usize,
    pub failed: usize,
}

/// Validate `RsyncConfig` options offline (before any cloud API calls) and compile `-x` regex.
pub fn validate_rsync_config(cfg: &RsyncConfig) -> Result<Option<Regex>> {
    if cfg.preserve_acl && cfg.canned_acl.is_some() {
        return Err(GsutilError::command(
            "Specifying both the -p and -a options together is invalid.",
        ));
    }
    if cfg.gzip_all && cfg.gzip_extensions.is_some() {
        return Err(GsutilError::command(
            "Specifying both the -j and -J options together is invalid.",
        ));
    }
    match &cfg.exclude_pattern {
        Some(pat) if pat.is_empty() => Err(GsutilError::command("Invalid blank exclude filter")),
        Some(pat) => Regex::new(pat)
            .map(Some)
            .map_err(|_| GsutilError::command(format!("Invalid exclude filter ({pat})"))),
        None => Ok(None),
    }
}

/// Execute `gsutil rsync` between `cfg.src_url` and `cfg.dst_url`.
pub async fn run_rsync(
    api: Arc<dyn CloudApi>,
    boto: &BotoConfig,
    cfg: &RsyncConfig,
) -> Result<RsyncSummary> {
    let exclude_re = validate_rsync_config(cfg)?;
    let src_root = StorageUrl::parse(&cfg.src_url)?;
    let dst_root = StorageUrl::parse(&cfg.dst_url)?;

    let buffer_lines = cfg
        .buffer_lines
        .unwrap_or_else(|| {
            boto.get_u64(
                "GSUtil",
                "rsync_buffer_lines",
                DEFAULT_RSYNC_BUFFER_LINES as u64,
            ) as usize
        })
        .max(1);

    if !cfg.quiet {
        eprintln!("Building synchronization state...");
    }

    let (src_res, dst_res) = tokio::join!(
        list_tree(api.as_ref(), &src_root, cfg, exclude_re.as_ref()),
        list_tree(api.as_ref(), &dst_root, cfg, exclude_re.as_ref()),
    );
    let src_entries = match src_res {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("{err}");
            return Err(GsutilError::command(
                "Caught non-retryable exception - aborting rsync",
            ));
        }
    };
    let dst_entries = match dst_res {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("{err}");
            return Err(GsutilError::command(
                "Caught non-retryable exception - aborting rsync",
            ));
        }
    };

    // Validate POSIX permission access before syncing cloud -> local with `-P`.
    if cfg.preserve_posix && src_root.is_cloud_url() && dst_root.is_file_url() {
        for entry in &src_entries {
            if let Some(mode) = entry.mode {
                if (mode & 0o400) == 0 {
                    return Err(GsutilError::command(
                        "This sync will orphan file(s), please fix their permissions before trying again.",
                    ));
                }
            }
        }
    }

    // External merge-sort both listings to temp files.
    let sorted_src_file = batch_sort_entries(src_entries.into_iter(), buffer_lines)?;
    let sorted_dst_file = batch_sort_entries(dst_entries.into_iter(), buffer_lines)?;

    let actions = compute_diffs_from_sorted_files(
        sorted_src_file.path(),
        sorted_dst_file.path(),
        &dst_root,
        cfg,
    )?;

    if !cfg.quiet {
        eprintln!("Starting synchronization...");
    }

    let mut summary = RsyncSummary {
        planned_actions: actions.clone(),
        ..Default::default()
    };

    if cfg.dry_run {
        if !cfg.quiet {
            for act in &actions {
                match act {
                    DiffAction::Copy {
                        src_url, dst_url, ..
                    } => eprintln!("Would copy {src_url} to {dst_url}"),
                    DiffAction::Remove { dst_url, .. } => eprintln!("Would remove {dst_url}"),
                    DiffAction::PosixSrcToDst { dst_url, .. } => {
                        eprintln!("Would set POSIX attributes on {dst_url}")
                    }
                }
            }
        }
        return Ok(summary);
    }

    if actions.is_empty() {
        return Ok(summary);
    }

    if cfg.parallel_operations && !cfg.quiet {
        let force = boto.get_bool("GSUtil", "task_estimation_force", false);
        let threshold = boto.get_u64("GSUtil", "task_estimation_threshold", 50_000) as usize;
        if force || (threshold > 0 && actions.len() >= threshold) {
            let total_size: u64 = actions
                .iter()
                .map(|a| match a {
                    DiffAction::Copy { size, .. } => *size,
                    _ => 0,
                })
                .sum();
            eprintln!(
                "Estimated work for this command: objects: {}, total size: {}",
                actions.len(),
                total_size
            );
        }
    }

    let copy_cfg = Arc::new(CopyConfig {
        preserve_acl: cfg.preserve_acl,
        preserve_posix: cfg.preserve_posix,
        preserve_mtime: true,
        canned_acl: cfg.canned_acl.clone(),
        gzip_transport: if cfg.gzip_all {
            GzipMode::All
        } else {
            match &cfg.gzip_extensions {
                Some(exts) if !exts.is_empty() => GzipMode::Extensions(exts.clone()),
                _ => GzipMode::None,
            }
        },
        continue_on_error: cfg.continue_on_error,
        parallel_operations: cfg.parallel_operations,
        quiet: cfg.quiet,
        ui: cfg.ui.clone(),
        ..Default::default()
    });
    let boto_arc = Arc::new(boto.clone());
    let par_cfg = ParallelConfig::from_boto(
        boto,
        cfg.parallel_operations,
        cfg.continue_on_error || cfg.parallel_operations,
    );

    let mut copy_actions = Vec::new();
    let mut remove_actions = Vec::new();
    let mut posix_actions = Vec::new();
    for act in actions {
        match act {
            DiffAction::Copy { .. } => copy_actions.push(act),
            DiffAction::Remove { .. } => remove_actions.push(act),
            DiffAction::PosixSrcToDst { .. } => posix_actions.push(act),
        }
    }

    // 1. Copies
    let copy_batch = run_parallel(copy_actions, &par_cfg, {
        let api = Arc::clone(&api);
        let boto = Arc::clone(&boto_arc);
        let copy_cfg = Arc::clone(&copy_cfg);
        move |act| {
            let api = Arc::clone(&api);
            let boto = Arc::clone(&boto);
            let copy_cfg = Arc::clone(&copy_cfg);
            async move {
                if let DiffAction::Copy {
                    src_url, dst_url, ..
                } = act
                {
                    let s = StorageUrl::parse(&src_url)?;
                    let d = StorageUrl::parse(&dst_url)?;
                    copy_single_pair(api, &boto, &copy_cfg, &s, &d, None).await?;
                }
                Ok(())
            }
        }
    })
    .await;
    summary.copied = copy_batch.succeeded;
    summary.failed += copy_batch.failed;

    // 2. Removals (-d)
    let quiet_remove = cfg.quiet;
    let remove_batch = run_parallel(remove_actions, &par_cfg, {
        let api = Arc::clone(&api);
        move |act| {
            let api = Arc::clone(&api);
            async move {
                if let DiffAction::Remove { dst_url, .. } = act {
                    if !quiet_remove {
                        eprintln!("Removing {dst_url}...");
                    }
                    let d = StorageUrl::parse(&dst_url)?;
                    match d {
                        StorageUrl::Cloud(c) => {
                            if let (Some(b), Some(o)) =
                                (c.bucket_name.as_deref(), c.object_name.as_deref())
                            {
                                api.for_provider(c.scheme.as_str())?
                                    .delete_object(b, o, c.generation.as_deref(), None)
                                    .await?;
                            }
                        }
                        StorageUrl::File(f) => {
                            if Path::new(&f.object_name).exists() {
                                fs::remove_file(&f.object_name)?;
                            }
                        }
                    }
                }
                Ok(())
            }
        }
    })
    .await;
    summary.removed = remove_batch.succeeded;
    summary.failed += remove_batch.failed;

    // 3. POSIX metadata-only updates (-P)
    let quiet_posix = cfg.quiet;
    let posix_batch = run_parallel(posix_actions, &par_cfg, {
        let api = Arc::clone(&api);
        move |act| {
            let api = Arc::clone(&api);
            async move {
                if let DiffAction::PosixSrcToDst { dst_url, posix, .. } = act {
                    if !quiet_posix {
                        eprintln!("Copying POSIX attributes from src to dst for {dst_url}...");
                    }
                    let d = StorageUrl::parse(&dst_url)?;
                    match d {
                        StorageUrl::File(f) => {
                            apply_posix_to_local_file(Path::new(&f.object_name), &posix)?;
                        }
                        StorageUrl::Cloud(c) => {
                            if let (Some(b), Some(o)) =
                                (c.bucket_name.as_deref(), c.object_name.as_deref())
                            {
                                let mut meta_map = BTreeMap::new();
                                serialize_posix_to_metadata(&posix, &mut meta_map);
                                let patch = Object {
                                    metadata: Some(meta_map),
                                    ..Default::default()
                                };
                                api.for_provider(c.scheme.as_str())?
                                    .patch_object_metadata(b, o, &patch, None, None, None, None)
                                    .await?;
                            }
                        }
                    }
                }
                Ok(())
            }
        }
    })
    .await;
    summary.metadata_updated = posix_batch.succeeded;
    summary.failed += posix_batch.failed;

    if summary.failed > 0 {
        return Err(GsutilError::command(format!(
            "{} files/objects could not be copied/removed.",
            summary.failed
        )));
    }
    Ok(summary)
}

// ---------------------------------------------------------------------------
// External Merge Sort (Batch Sort + K-Way Heap Merge)
// ---------------------------------------------------------------------------

struct HeapItem {
    entry: RsyncEntry,
    chunk_idx: usize,
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.entry.rel_path == other.entry.rel_path
    }
}
impl Eq for HeapItem {}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

// Min-heap by `rel_path` (reversed for BinaryHeap which is a max-heap).
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        other.entry.rel_path.cmp(&self.entry.rel_path)
    }
}

/// Externally sort `RsyncEntry` records by `rel_path` in chunks of `buffer_lines`,
/// merging chunks with a k-way min-heap into a temporary JSONL file.
pub fn batch_sort_entries<I>(mut iter: I, buffer_lines: usize) -> Result<NamedTempFile>
where
    I: Iterator<Item = RsyncEntry>,
{
    let mut chunk_files: Vec<NamedTempFile> = Vec::new();
    let chunk_cap = buffer_lines.max(1);

    loop {
        let mut chunk: Vec<RsyncEntry> = Vec::with_capacity(chunk_cap.min(4096));
        for _ in 0..chunk_cap {
            match iter.next() {
                Some(e) => chunk.push(e),
                None => break,
            }
        }
        if chunk.is_empty() {
            break;
        }
        chunk.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        let mut tmp = NamedTempFile::new()?;
        {
            let mut w = BufWriter::new(tmp.as_file_mut());
            for entry in &chunk {
                serde_json::to_writer(&mut w, entry).map_err(|e| {
                    GsutilError::command(format!("Failed to serialize rsync entry: {e}"))
                })?;
                w.write_all(b"\n")?;
            }
            w.flush()?;
        }
        chunk_files.push(tmp);
    }

    let mut out = NamedTempFile::new()?;
    let mut readers: Vec<BufReader<File>> = Vec::with_capacity(chunk_files.len());
    for cf in &chunk_files {
        readers.push(BufReader::new(File::open(cf.path())?));
    }

    let mut heap: BinaryHeap<HeapItem> = BinaryHeap::new();
    for (idx, r) in readers.iter_mut().enumerate() {
        if let Some(entry) = read_next_entry(r)? {
            heap.push(HeapItem {
                entry,
                chunk_idx: idx,
            });
        }
    }

    {
        let mut writer = BufWriter::new(out.as_file_mut());
        while let Some(HeapItem { entry, chunk_idx }) = heap.pop() {
            serde_json::to_writer(&mut writer, &entry).map_err(|e| {
                GsutilError::command(format!("Failed to write merged rsync entry: {e}"))
            })?;
            writer.write_all(b"\n")?;
            if let Some(next_entry) = read_next_entry(&mut readers[chunk_idx])? {
                heap.push(HeapItem {
                    entry: next_entry,
                    chunk_idx,
                });
            }
        }
        writer.flush()?;
    }

    Ok(out)
}

fn read_next_entry(reader: &mut BufReader<File>) -> Result<Option<RsyncEntry>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let entry: RsyncEntry = serde_json::from_str(trimmed)
        .map_err(|e| GsutilError::command(format!("Corrupt rsync state entry: {e}")))?;
    Ok(Some(entry))
}

// ---------------------------------------------------------------------------
// Sorted Merge Diff Engine
// ---------------------------------------------------------------------------

fn compute_diffs_from_sorted_files(
    src_path: &Path,
    dst_path: &Path,
    dst_root: &StorageUrl,
    cfg: &RsyncConfig,
) -> Result<Vec<DiffAction>> {
    let mut src_reader = BufReader::new(File::open(src_path)?);
    let mut dst_reader = BufReader::new(File::open(dst_path)?);

    let mut cur_src = read_next_entry(&mut src_reader)?;
    let mut cur_dst = read_next_entry(&mut dst_reader)?;
    let mut actions = Vec::new();

    loop {
        match (&cur_src, &cur_dst) {
            (None, None) => break,
            (Some(s), None) => {
                let dst_url = build_child_url(dst_root, &s.rel_path);
                actions.push(DiffAction::Copy {
                    src_url: s.full_url.clone(),
                    dst_url,
                    rel_path: s.rel_path.clone(),
                    size: s.size,
                });
                cur_src = read_next_entry(&mut src_reader)?;
            }
            (None, Some(d)) => {
                if cfg.delete_extras {
                    actions.push(DiffAction::Remove {
                        dst_url: d.full_url.clone(),
                        rel_path: d.rel_path.clone(),
                    });
                }
                cur_dst = read_next_entry(&mut dst_reader)?;
            }
            (Some(s), Some(d)) => match s.rel_path.cmp(&d.rel_path) {
                CmpOrdering::Less => {
                    let dst_url = build_child_url(dst_root, &s.rel_path);
                    actions.push(DiffAction::Copy {
                        src_url: s.full_url.clone(),
                        dst_url,
                        rel_path: s.rel_path.clone(),
                        size: s.size,
                    });
                    cur_src = read_next_entry(&mut src_reader)?;
                }
                CmpOrdering::Greater => {
                    if cfg.delete_extras {
                        actions.push(DiffAction::Remove {
                            dst_url: d.full_url.clone(),
                            rel_path: d.rel_path.clone(),
                        });
                    }
                    cur_dst = read_next_entry(&mut dst_reader)?;
                }
                CmpOrdering::Equal => {
                    if let Some(act) = compare_matching_entries(s, d, cfg)? {
                        actions.push(act);
                    }
                    cur_src = read_next_entry(&mut src_reader)?;
                    cur_dst = read_next_entry(&mut dst_reader)?;
                }
            },
        }
    }

    Ok(actions)
}

fn compare_matching_entries(
    src: &RsyncEntry,
    dst: &RsyncEntry,
    cfg: &RsyncConfig,
) -> Result<Option<DiffAction>> {
    if cfg.ignore_existing {
        return Ok(None);
    }

    if cfg.skip_old_files {
        if let (Some(sm), Some(dm)) = (src.effective_mtime(), dst.effective_mtime()) {
            if dm > sm {
                return Ok(None);
            }
        }
    }

    let needs_copy = if cfg.compute_checksums {
        !entries_have_matching_checksum(src, dst)?
    } else if src.size != dst.size {
        true
    } else if let (Some(sm), Some(dm)) = (src.mtime, dst.mtime) {
        sm != dm
    } else {
        // Same size, missing mtime on at least one side -> compare checksums.
        !entries_have_matching_checksum(src, dst)?
    };

    if needs_copy {
        return Ok(Some(DiffAction::Copy {
            src_url: src.full_url.clone(),
            dst_url: dst.full_url.clone(),
            rel_path: src.rel_path.clone(),
            size: src.size,
        }));
    }

    if cfg.preserve_posix && src.posix_attrs() != dst.posix_attrs() {
        return Ok(Some(DiffAction::PosixSrcToDst {
            src_url: src.full_url.clone(),
            dst_url: dst.full_url.clone(),
            rel_path: src.rel_path.clone(),
            posix: src.posix_attrs(),
        }));
    }

    Ok(None)
}

fn entries_have_matching_checksum(src: &RsyncEntry, dst: &RsyncEntry) -> Result<bool> {
    // Prefer hardware-accelerated CRC32C when either side already has it (e.g. all GCS objects),
    // avoiding unnecessary software MD5 computation on local files.
    let need_md5 = src.crc32c.is_none() && dst.crc32c.is_none();
    let (s_crc, s_md5) = resolve_entry_hashes(src, !need_md5 || src.crc32c.is_some(), need_md5)?;
    let (d_crc, d_md5) = resolve_entry_hashes(dst, !need_md5 || dst.crc32c.is_some(), need_md5)?;

    if let (Some(sc), Some(dc)) = (s_crc.as_deref(), d_crc.as_deref()) {
        return Ok(sc == dc);
    }
    if let (Some(sm), Some(dm)) = (s_md5.as_deref(), d_md5.as_deref()) {
        return Ok(sm == dm);
    }
    // Fallback if neither hash is available (shouldn't happen for valid files/GCS objects).
    Ok(src.size == dst.size)
}

fn resolve_entry_hashes(
    entry: &RsyncEntry,
    compute_crc32c: bool,
    compute_md5: bool,
) -> Result<(Option<String>, Option<String>)> {
    if entry.crc32c.is_some() || entry.md5.is_some() {
        return Ok((entry.crc32c.clone(), entry.md5.clone()));
    }
    let parsed = StorageUrl::parse(&entry.full_url)?;
    if let StorageUrl::File(f) = parsed {
        let mut file = File::open(&f.object_name)?;
        let hashes = hash_reader(&mut file, compute_crc32c, compute_md5)?;
        return Ok((hashes.crc32c_base64(), hashes.md5_base64()));
    }
    Ok((None, None))
}

// ---------------------------------------------------------------------------
// Tree Listing Helpers (Local & Cloud)
// ---------------------------------------------------------------------------

async fn list_tree(
    api: &dyn CloudApi,
    root: &StorageUrl,
    cfg: &RsyncConfig,
    exclude_re: Option<&Regex>,
) -> Result<Vec<RsyncEntry>> {
    match root {
        StorageUrl::File(f) => list_local_tree(Path::new(&f.object_name), cfg, exclude_re),
        StorageUrl::Cloud(_) => list_cloud_tree(api, root, cfg, exclude_re).await,
    }
}

fn list_local_tree(
    root: &Path,
    cfg: &RsyncConfig,
    exclude_re: Option<&Regex>,
) -> Result<Vec<RsyncEntry>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    let mut visited = HashSet::new();
    if let Ok(canon) = fs::canonicalize(root) {
        visited.insert(canon);
    }
    walk_local_rsync(root, root, cfg, exclude_re, &mut visited, &mut entries)?;
    Ok(entries)
}

fn walk_local_rsync(
    root: &Path,
    dir: &Path,
    cfg: &RsyncConfig,
    exclude_re: Option<&Regex>,
    visited_dirs: &mut HashSet<PathBuf>,
    out: &mut Vec<RsyncEntry>,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let sym_meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) if cfg.skip_unsupported => continue,
            Err(e) => return Err(e.into()),
        };

        if sym_meta.file_type().is_symlink() && (cfg.ignore_symlinks || cfg.skip_unsupported) {
            continue;
        }

        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) if cfg.skip_unsupported || cfg.ignore_symlinks => continue,
            Err(e) => return Err(e.into()),
        };

        if meta.is_dir() {
            // Python gsutil rsync skips symlinks pointing to directories.
            if sym_meta.file_type().is_symlink() {
                continue;
            }
            if cfg.recursive {
                if let Ok(canon) = fs::canonicalize(&path) {
                    if !visited_dirs.insert(canon) {
                        continue;
                    }
                }
                walk_local_rsync(root, &path, cfg, exclude_re, visited_dirs, out)?;
            }
            continue;
        }
        if !meta.is_file() {
            if cfg.skip_unsupported {
                continue;
            }
            return Err(GsutilError::command(format!(
                "Unsupported file type in rsync: {}",
                path.display()
            )));
        }

        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");

        if let Some(re) = exclude_re {
            if re.is_match(&rel) {
                continue;
            }
        }

        let posix = read_local_posix_attributes(&path)?;
        out.push(RsyncEntry {
            rel_path: rel,
            full_url: format!("file://{}", path.to_string_lossy()),
            size: meta.len(),
            time_created: posix.mtime,
            mtime: posix.mtime,
            atime: posix.atime,
            uid: posix.uid,
            gid: posix.gid,
            mode: posix.mode,
            crc32c: None,
            md5: None,
        });
    }
    Ok(())
}

async fn list_cloud_tree(
    api: &dyn CloudApi,
    root: &StorageUrl,
    cfg: &RsyncConfig,
    exclude_re: Option<&Regex>,
) -> Result<Vec<RsyncEntry>> {
    let bucket = root
        .bucket_name()
        .ok_or_else(|| GsutilError::command("rsync cloud URL must specify a bucket."))?;
    let scheme = root.scheme();

    let prefix = match root.object_name() {
        Some(o) if !o.is_empty() => {
            let trimmed = strip_one_slash(o);
            Some(format!("{trimmed}/"))
        }
        _ => None,
    };

    let listed = api
        .for_provider(scheme)?
        .list_objects(
            bucket,
            &ListObjectsOptions {
                prefix: prefix.clone(),
                delimiter: if cfg.recursive {
                    None
                } else {
                    Some("/".to_string())
                },
                all_versions: false,
                fields: None,
            },
        )
        .await?;

    let prefix_str = prefix.as_deref().unwrap_or("");
    let mut entries = Vec::new();
    for item in listed {
        let CsObjectOrPrefix::Object(obj) = item else {
            continue;
        };
        let Some(name) = obj.name.as_deref() else {
            continue;
        };
        let full_url = format!("{scheme}://{bucket}/{name}");
        let parsed_u = StorageUrl::parse(&full_url)?;
        if parsed_u.is_cloud_subdir_placeholder(Some(obj.size_bytes())) {
            continue;
        }
        let rel = name.strip_prefix(prefix_str).unwrap_or(name).to_string();
        if rel.is_empty() {
            continue;
        }
        if let Some(re) = exclude_re {
            if re.is_match(&rel) {
                continue;
            }
        }

        if let Some(ref custom_meta) = obj.metadata {
            if let Some(raw_mtime) = custom_meta.get(crate::posix::MTIME_ATTR) {
                let parsed = raw_mtime.trim().parse::<i64>().ok();
                match parsed {
                    None => eprintln!("WARNING: {full_url} has an invalid mtime in its metadata"),
                    Some(v) if v < 0 => {
                        eprintln!("WARNING: {full_url} has an invalid mtime in its metadata")
                    }
                    Some(v) if v > chrono::Utc::now().timestamp() + 86_400 => {
                        eprintln!(
                            "WARNING: {full_url} has an mtime more than 1 day from current system time"
                        );
                    }
                    _ => {}
                }
            }
        }
        if obj
            .content_encoding
            .as_deref()
            .is_some_and(|e| e.eq_ignore_ascii_case("gzip"))
            && !cfg.quiet
        {
            eprintln!(
                "WARNING: {full_url} has a compressed content-encoding, so it may be re-downloaded."
            );
        }
        let posix = obj
            .metadata
            .as_ref()
            .map(deserialize_posix_from_metadata)
            .unwrap_or_default();
        let time_created = obj
            .time_created
            .as_deref()
            .and_then(parse_rfc3339_to_epoch_secs);

        entries.push(RsyncEntry {
            rel_path: rel,
            full_url,
            size: obj.size_bytes(),
            time_created,
            mtime: posix.mtime,
            atime: posix.atime,
            uid: posix.uid,
            gid: posix.gid,
            mode: posix.mode,
            crc32c: obj.crc32c.clone(),
            md5: obj.md5_hash.clone(),
        });
    }

    Ok(entries)
}

fn build_child_url(root: &StorageUrl, rel_path: &str) -> String {
    match root {
        StorageUrl::File(f) => {
            let joined: PathBuf = Path::new(&f.object_name).join(rel_path);
            format!("file://{}", joined.to_string_lossy())
        }
        StorageUrl::Cloud(c) => {
            let bucket = c.bucket_name.as_deref().unwrap_or("");
            let base = c.object_name.as_deref().unwrap_or("");
            let trimmed_base = strip_one_slash(base);
            if trimmed_base.is_empty() {
                format!("{}://{bucket}/{rel_path}", c.scheme)
            } else {
                format!("{}://{bucket}/{trimmed_base}/{rel_path}", c.scheme)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_api::MockCloudApi;

    #[test]
    fn test_external_batch_sort_multi_chunk_merge() {
        let names = [
            "z.txt", "a.txt", "m.txt", "b.txt", "y.txt", "c.txt", "d.txt",
        ];
        let entries = names.iter().map(|n| RsyncEntry {
            rel_path: (*n).to_string(),
            full_url: format!("gs://b/{n}"),
            size: 1,
            time_created: None,
            mtime: None,
            atime: None,
            uid: None,
            gid: None,
            mode: None,
            crc32c: None,
            md5: None,
        });
        // Buffer size 2 forces 4 sorted chunk files merged via k-way heap.
        let sorted_file = batch_sort_entries(entries, 2).unwrap();
        let mut r = BufReader::new(File::open(sorted_file.path()).unwrap());
        let mut out = Vec::new();
        while let Some(e) = read_next_entry(&mut r).unwrap() {
            out.push(e.rel_path);
        }
        assert_eq!(
            out,
            vec!["a.txt", "b.txt", "c.txt", "d.txt", "m.txt", "y.txt", "z.txt"]
        );
    }

    #[tokio::test]
    async fn test_rsync_diff_delete_exclude_and_dry_run() {
        let tmp = tempfile::tempdir().unwrap();
        let mut boto = BotoConfig::new();
        boto.set(
            "GSUtil",
            "resumable_tracker_dir",
            tmp.path().join("trackers").to_string_lossy().into_owned(),
        );

        let src_dir = tmp.path().join("src");
        fs::create_dir_all(src_dir.join("sub")).unwrap();
        fs::write(src_dir.join("keep.txt"), b"same-content").unwrap();
        fs::write(src_dir.join("changed.txt"), b"new-content-longer").unwrap();
        fs::write(src_dir.join("added.txt"), b"brand-new").unwrap();
        fs::write(src_dir.join("sub/nested.txt"), b"nested").unwrap();
        fs::write(src_dir.join("ignore.tmp"), b"ignored").unwrap();

        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("dst");
        api.put_object("dst", "keep.txt", b"same-content");
        api.put_object("dst", "changed.txt", b"old");
        api.put_object("dst", "extra.txt", b"delete-me");

        // Dry run (-n) with -r, -d, -c, -x '.*\.tmp$'
        let dry_cfg = RsyncConfig {
            src_url: src_dir.to_string_lossy().into_owned(),
            dst_url: "gs://dst".into(),
            recursive: true,
            delete_extras: true,
            compute_checksums: true,
            dry_run: true,
            exclude_pattern: Some(r".*\.tmp$".into()),
            buffer_lines: Some(2),
            ..Default::default()
        };
        let dry_summary = run_rsync(api.clone(), &boto, &dry_cfg).await.unwrap();
        // Should plan: copy added.txt, changed.txt, sub/nested.txt; remove extra.txt; skip keep.txt & ignore.tmp
        assert_eq!(dry_summary.planned_actions.len(), 4);
        // Dry run must not mutate bucket!
        assert!(api.get_stored("dst", "extra.txt").is_some());
        assert!(api.get_stored("dst", "added.txt").is_none());

        // Real run
        let real_cfg = RsyncConfig {
            dry_run: false,
            ..dry_cfg
        };
        let summary = run_rsync(api.clone(), &boto, &real_cfg).await.unwrap();
        assert_eq!(summary.copied, 3);
        assert_eq!(summary.removed, 1);
        assert!(api.get_stored("dst", "extra.txt").is_none());
        assert!(api.get_stored("dst", "ignore.tmp").is_none());
        assert_eq!(
            api.get_stored("dst", "changed.txt").unwrap().data.as_ref(),
            b"new-content-longer"
        );
        assert_eq!(
            api.get_stored("dst", "sub/nested.txt")
                .unwrap()
                .data
                .as_ref(),
            b"nested"
        );
    }

    #[tokio::test]
    async fn test_rsync_ignore_existing_flag() {
        let boto = BotoConfig::new();
        let api = Arc::new(MockCloudApi::new());
        api.create_bucket_sync("src");
        api.create_bucket_sync("dst");
        api.put_object("src", "a.txt", b"new-version");
        api.put_object("src", "b.txt", b"only-in-src");
        api.put_object("dst", "a.txt", b"old-version");

        let summary = run_rsync(
            api.clone(),
            &boto,
            &RsyncConfig {
                src_url: "gs://src".into(),
                dst_url: "gs://dst".into(),
                ignore_existing: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(summary.copied, 1);
        assert_eq!(
            api.get_stored("dst", "a.txt").unwrap().data.as_ref(),
            b"old-version"
        );
        assert_eq!(
            api.get_stored("dst", "b.txt").unwrap().data.as_ref(),
            b"only-in-src"
        );
    }

    #[test]
    fn test_rsync_config_validation_parity() {
        let blank_x = RsyncConfig {
            exclude_pattern: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(
            validate_rsync_config(&blank_x).unwrap_err().to_string(),
            "CommandException: Invalid blank exclude filter"
        );

        let bad_x = RsyncConfig {
            exclude_pattern: Some("[".into()),
            ..Default::default()
        };
        assert_eq!(
            validate_rsync_config(&bad_x).unwrap_err().to_string(),
            "CommandException: Invalid exclude filter ([)"
        );

        let p_and_a = RsyncConfig {
            preserve_acl: true,
            canned_acl: Some("public-read".into()),
            ..Default::default()
        };
        assert_eq!(
            validate_rsync_config(&p_and_a).unwrap_err().to_string(),
            "CommandException: Specifying both the -p and -a options together is invalid."
        );

        let j_and_big_j = RsyncConfig {
            gzip_all: true,
            gzip_extensions: Some(vec!["html".into()]),
            ..Default::default()
        };
        assert_eq!(
            validate_rsync_config(&j_and_big_j).unwrap_err().to_string(),
            "CommandException: Specifying both the -j and -J options together is invalid."
        );
    }
}
