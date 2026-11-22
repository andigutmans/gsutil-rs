//! Resumable transfer tracker files under `~/.gsutil/tracker-files/`.
//!
//! Matches `gslib/tracker_file.py` and `gslib/parallel_tracker_file.py` in
//! Python gsutil v5.38, including SHA-1 hashed filenames (`TRACKER_<sha1>.<last16>`).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use gsutil_core::api::Object;
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result};
use gsutil_core::hash::Md5Hasher;
use gsutil_core::url::StorageUrl;
use serde::{Deserialize, Serialize};

/// Maximum tracker filename length (matches `MAX_TRACKER_FILE_NAME_LENGTH`).
pub const MAX_TRACKER_FILE_NAME_LENGTH: usize = 100;

/// Tracker file types matching `TrackerFileType` in `gslib/tracker_file.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackerFileType {
    Upload,
    Download,
    DownloadComponent,
    ParallelUpload,
    SlicedDownload,
    Rewrite,
}

impl TrackerFileType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
            Self::DownloadComponent => "download_component",
            Self::ParallelUpload => "parallel_upload",
            Self::SlicedDownload => "sliced_download",
            Self::Rewrite => "rewrite",
        }
    }
}

/// JSON payload stored in upload tracker files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UploadTrackerData {
    pub encryption_key_sha256: Option<String>,
    pub serialization_data: String,
}

/// JSON payload stored in download component tracker files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DownloadComponentTrackerData {
    pub etag: String,
    pub generation: Option<String>,
    pub download_start_byte: u64,
}

/// JSON payload stored in sliced download parent tracker files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlicedDownloadTrackerData {
    pub etag: String,
    pub generation: Option<String>,
    pub num_components: usize,
}

/// Single component entry in a parallel composite upload tracker file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParallelUploadComponentEntry {
    pub component_num: usize,
    pub object_name: String,
    pub generation: Option<String>,
    pub crc32c: Option<String>,
    pub size: u64,
}

/// JSON payload stored in parallel composite upload tracker files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParallelUploadTrackerData {
    pub encryption_key_sha256: Option<String>,
    pub random_prefix: String,
    pub components: Vec<ParallelUploadComponentEntry>,
}

/// Compute lowercase hex SHA-1 digest (RFC 3174) for tracker filename hashing.
pub fn sha1_hex(data: &[u8]) -> String {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    format!("{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}")
}

/// Shorten a raw tracker filename using SHA-1, matching `_HashFilename` in `tracker_file.py`:
/// `TRACKER_<sha1_hex>.<last_16_chars>`
pub fn hash_filename(filename: &str) -> String {
    let digest = sha1_hex(filename.as_bytes());
    let char_count = filename.chars().count();
    let trailing: String = if char_count > 16 {
        filename.chars().skip(char_count - 16).collect()
    } else {
        filename.to_string()
    };
    format!("TRACKER_{digest}.{trailing}")
}

/// Look up or create the tracker files directory (`~/.gsutil/tracker-files` by default).
pub fn create_tracker_dir_if_needed(config: &BotoConfig) -> Result<PathBuf> {
    let dir = if let Some(custom) = config.get("GSUtil", "resumable_tracker_dir") {
        PathBuf::from(custom)
    } else {
        config.state_dir().join("tracker-files")
    };
    fs::create_dir_all(&dir).map_err(|e| {
        GsutilError::command(format!(
            "Couldn't create tracker directory ({}): {e}",
            dir.display()
        ))
    })?;
    Ok(dir)
}

fn sanitize_tracker_name(raw: &str) -> String {
    raw.replace(['/', '\\'], "_")
}

fn hash_and_return_path(
    config: &BotoConfig,
    raw_name: &str,
    tracker_type: TrackerFileType,
) -> Result<PathBuf> {
    let dir = create_tracker_dir_if_needed(config)?;
    let hashed = hash_filename(raw_name);
    let file_name = format!("{}_{hashed}", tracker_type.as_str());
    debug_assert!(file_name.len() < MAX_TRACKER_FILE_NAME_LENGTH);
    Ok(dir.join(file_name))
}

fn canonical_or_raw(path: &str) -> String {
    let p = Path::new(path);
    // Canonicalize the parent directory + filename so the result is identical both
    // before the destination file exists (download start) and after (download finish),
    // including on macOS (`/var` -> `/private/var`) and Windows (`\\?\` prefix).
    if let (Some(parent), Some(fname)) = (p.parent(), p.file_name()) {
        if !parent.as_os_str().is_empty() {
            if let Ok(canon_parent) = fs::canonicalize(parent) {
                return canon_parent.join(fname).to_string_lossy().into_owned();
            }
        }
    }
    fs::canonicalize(p)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

/// Compute the tracker file path for upload, download, parallel upload, or sliced download.
pub fn get_tracker_file_path(
    config: &BotoConfig,
    dst_url: &StorageUrl,
    tracker_type: TrackerFileType,
    api_selector: &str,
    src_url: Option<&StorageUrl>,
    component_num: Option<usize>,
) -> Result<PathBuf> {
    let raw = match tracker_type {
        TrackerFileType::Upload => {
            let bucket = dst_url.bucket_name().unwrap_or("");
            let obj = dst_url.object_name().unwrap_or("");
            sanitize_tracker_name(&format!(
                "resumable_upload__{bucket}__{obj}__{api_selector}.url"
            ))
        }
        TrackerFileType::Download => {
            let real = canonical_or_raw(dst_url.object_name().unwrap_or(""));
            sanitize_tracker_name(&format!("resumable_download__{real}__{api_selector}.etag"))
        }
        TrackerFileType::DownloadComponent => {
            let real = canonical_or_raw(dst_url.object_name().unwrap_or(""));
            let num = component_num.unwrap_or(0);
            sanitize_tracker_name(&format!(
                "resumable_download__{real}__{api_selector}__{num}.etag"
            ))
        }
        TrackerFileType::ParallelUpload => {
            let bucket = dst_url.bucket_name().unwrap_or("");
            let obj = dst_url.object_name().unwrap_or("");
            let src = src_url.map(|u| u.url_string()).unwrap_or_default();
            sanitize_tracker_name(&format!(
                "parallel_upload__{bucket}__{obj}__{src}__{api_selector}.url"
            ))
        }
        TrackerFileType::SlicedDownload => {
            let real = canonical_or_raw(dst_url.object_name().unwrap_or(""));
            sanitize_tracker_name(&format!("sliced_download__{real}__{api_selector}.etag"))
        }
        TrackerFileType::Rewrite => {
            return Err(GsutilError::argument(
                "Use get_rewrite_tracker_file_path for Rewrite tracker files.",
            ));
        }
    };
    hash_and_return_path(config, &raw, tracker_type)
}

/// Compute the tracker file path for an object rewrite operation.
pub fn get_rewrite_tracker_file_path(
    config: &BotoConfig,
    src_bucket: &str,
    src_obj: &str,
    dst_bucket: &str,
    dst_obj: &str,
    api_selector: &str,
) -> Result<PathBuf> {
    let raw = sanitize_tracker_name(&format!(
        "rewrite__{src_bucket}__{src_obj}__{dst_bucket}__{dst_obj}__{api_selector}.token"
    ));
    hash_and_return_path(config, &raw, TrackerFileType::Rewrite)
}

/// Write raw string data to a tracker file with `0o600` permissions on Unix.
pub fn write_tracker_file(path: &Path, data: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            GsutilError::command(format!(
                "Couldn't write tracker file ({}): {e}. This can happen if gsutil is \
                 configured to save tracker files to an unwritable directory)",
                path.display()
            ))
        })?;
    }

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(path).map_err(|e| {
        GsutilError::command(format!(
            "Couldn't write tracker file ({}): {e}. This can happen if gsutil is \
             configured to save tracker files to an unwritable directory)",
            path.display()
        ))
    })?;
    file.write_all(data.as_bytes()).map_err(|e| {
        GsutilError::command(format!(
            "Couldn't write tracker file ({}): {e}. This can happen if gsutil is \
             configured to save tracker files to an unwritable directory)",
            path.display()
        ))
    })?;
    Ok(())
}

/// Delete a tracker file if it exists.
pub fn delete_tracker_file(path: &Path) {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
}

/// Read upload tracker data, deleting the tracker file if the encryption key changed.
pub fn read_upload_tracker(path: &Path, encryption_key_sha256: Option<&str>) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    if let Ok(parsed) = serde_json::from_str::<UploadTrackerData>(&contents) {
        if parsed.encryption_key_sha256.as_deref() == encryption_key_sha256 {
            return Some(parsed.serialization_data);
        }
        delete_tracker_file(path);
        return None;
    }
    // Legacy non-JSON tracker format: usable only when no encryption key is set.
    delete_tracker_file(path);
    if encryption_key_sha256.is_none() {
        Some(contents)
    } else {
        None
    }
}

/// Write upload tracker JSON data.
pub fn write_upload_tracker(
    path: &Path,
    encryption_key_sha256: Option<String>,
    serialization_data: String,
) -> Result<()> {
    let data = UploadTrackerData {
        encryption_key_sha256,
        serialization_data,
    };
    let json = serde_json::to_string(&data)
        .map_err(|e| GsutilError::command(format!("Failed to serialize upload tracker: {e}")))?;
    write_tracker_file(path, &json)
}

/// Read or initialize a download tracker file. Returns `(tracker_path, download_start_byte)`.
pub fn read_or_create_download_tracker(
    config: &BotoConfig,
    src_obj: &Object,
    dst_url: &StorageUrl,
    api_selector: &str,
    start_byte: u64,
    existing_file_size: u64,
    component_num: Option<usize>,
) -> Result<(Option<PathBuf>, u64)> {
    if src_obj.size_bytes() < config.resumable_threshold() {
        return Ok((None, start_byte));
    }

    let etag = src_obj.etag.as_deref().unwrap_or("");
    let tracker_type = if component_num.is_some() {
        TrackerFileType::DownloadComponent
    } else {
        TrackerFileType::Download
    };
    let path = get_tracker_file_path(
        config,
        dst_url,
        tracker_type,
        api_selector,
        None,
        component_num,
    )?;

    if let Ok(contents) = fs::read_to_string(&path) {
        match tracker_type {
            TrackerFileType::Download => {
                let saved_etag = contents.lines().next().unwrap_or("").trim();
                if !etag.is_empty() && saved_etag == etag {
                    return Ok((Some(path), existing_file_size));
                }
            }
            TrackerFileType::DownloadComponent => {
                if let Ok(comp) = serde_json::from_str::<DownloadComponentTrackerData>(&contents) {
                    if comp.etag == etag && comp.generation == src_obj.generation {
                        return Ok((Some(path), comp.download_start_byte));
                    }
                }
            }
            _ => {}
        }
    }

    match tracker_type {
        TrackerFileType::Download => {
            write_tracker_file(&path, &format!("{etag}\n"))?;
        }
        TrackerFileType::DownloadComponent => {
            write_download_component_tracker(&path, src_obj, start_byte)?;
        }
        _ => {}
    }
    Ok((Some(path), start_byte))
}

/// Update or create a download component tracker file.
pub fn write_download_component_tracker(
    path: &Path,
    src_obj: &Object,
    current_file_pos: u64,
) -> Result<()> {
    let data = DownloadComponentTrackerData {
        etag: src_obj.etag.clone().unwrap_or_default(),
        generation: src_obj.generation.clone(),
        download_start_byte: current_file_pos,
    };
    let json = serde_json::to_string(&data).map_err(|e| {
        GsutilError::command(format!(
            "Failed to serialize download component tracker: {e}"
        ))
    })?;
    write_tracker_file(path, &json)
}

/// Write a sliced download parent tracker file.
pub fn write_sliced_download_tracker(
    path: &Path,
    src_obj: &Object,
    num_components: usize,
) -> Result<()> {
    let data = SlicedDownloadTrackerData {
        etag: src_obj.etag.clone().unwrap_or_default(),
        generation: src_obj.generation.clone(),
        num_components,
    };
    let json = serde_json::to_string(&data).map_err(|e| {
        GsutilError::command(format!("Failed to serialize sliced download tracker: {e}"))
    })?;
    write_tracker_file(path, &json)
}

/// Delete all download tracker files (regular + sliced parent + component trackers).
pub fn delete_download_tracker_files(
    config: &BotoConfig,
    dst_url: &StorageUrl,
    api_selector: &str,
) {
    if let Ok(p) = get_tracker_file_path(
        config,
        dst_url,
        TrackerFileType::Download,
        api_selector,
        None,
        None,
    ) {
        delete_tracker_file(&p);
    }

    if let Ok(parent) = get_tracker_file_path(
        config,
        dst_url,
        TrackerFileType::SlicedDownload,
        api_selector,
        None,
        None,
    ) {
        if let Ok(contents) = fs::read_to_string(&parent) {
            if let Ok(parsed) = serde_json::from_str::<SlicedDownloadTrackerData>(&contents) {
                for i in 0..parsed.num_components {
                    if let Ok(comp) = get_tracker_file_path(
                        config,
                        dst_url,
                        TrackerFileType::DownloadComponent,
                        api_selector,
                        None,
                        Some(i),
                    ) {
                        delete_tracker_file(&comp);
                    }
                }
            }
        }
        delete_tracker_file(&parent);
    }
}

/// Read parallel composite upload tracker data.
pub fn read_parallel_upload_tracker(path: &Path) -> Option<ParallelUploadTrackerData> {
    let contents = fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Write parallel composite upload tracker data.
pub fn write_parallel_upload_tracker(path: &Path, data: &ParallelUploadTrackerData) -> Result<()> {
    let json = serde_json::to_string(data).map_err(|e| {
        GsutilError::command(format!("Failed to serialize parallel upload tracker: {e}"))
    })?;
    write_tracker_file(path, &json)
}

/// Parameters hashed into a rewrite tracker file so parameter changes restart the rewrite.
#[derive(Debug, Default)]
pub struct RewriteTrackerParams<'a> {
    pub src_bucket: &'a str,
    pub src_obj: &'a str,
    pub src_etag: &'a str,
    pub dst_bucket: &'a str,
    pub dst_obj: &'a str,
    pub dst_storage_class: Option<&'a str>,
    pub src_generation: Option<&'a str>,
    pub gen_match: Option<i64>,
    pub meta_gen_match: Option<i64>,
    pub canned_acl: Option<&'a str>,
    pub max_bytes_per_call: Option<u64>,
    pub src_dec_key_sha256: Option<&'a str>,
    pub dst_enc_key_sha256: Option<&'a str>,
}

/// Compute MD5 hex digest of rewrite parameters (matching `HashRewriteParameters`).
pub fn hash_rewrite_parameters(params: &RewriteTrackerParams<'_>) -> String {
    let mut hasher = Md5Hasher::new();
    hasher.update(params.src_bucket.as_bytes());
    hasher.update(b"\0");
    hasher.update(params.src_obj.as_bytes());
    hasher.update(b"\0");
    hasher.update(params.src_etag.as_bytes());
    hasher.update(b"\0");
    hasher.update(params.dst_bucket.as_bytes());
    hasher.update(b"\0");
    hasher.update(params.dst_obj.as_bytes());
    hasher.update(b"\0");
    if let Some(sc) = params.dst_storage_class {
        hasher.update(sc.as_bytes());
    }
    hasher.update(b"\0");
    if let Some(g) = params.src_generation {
        hasher.update(g.as_bytes());
    }
    hasher.update(b"\0");
    if let Some(gm) = params.gen_match {
        hasher.update(gm.to_string().as_bytes());
    }
    hasher.update(b"\0");
    if let Some(mgm) = params.meta_gen_match {
        hasher.update(mgm.to_string().as_bytes());
    }
    hasher.update(b"\0");
    if let Some(acl) = params.canned_acl {
        hasher.update(acl.as_bytes());
    }
    hasher.update(b"\0");
    if let Some(mb) = params.max_bytes_per_call {
        hasher.update(mb.to_string().as_bytes());
    }
    hasher.update(b"\0");
    if let Some(dk) = params.src_dec_key_sha256 {
        hasher.update(dk.as_bytes());
    }
    hasher.update(b"\0");
    if let Some(ek) = params.dst_enc_key_sha256 {
        hasher.update(ek.as_bytes());
    }
    hasher.finalize_hex()
}

/// Read a rewrite tracker file and return its `rewrite_token` if the parameter hash matches.
pub fn read_rewrite_tracker(path: &Path, expected_params_hash: &str) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let mut lines = contents.lines();
    let saved_hash = lines.next()?.trim();
    if saved_hash == expected_params_hash {
        let token = lines.next()?.trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    None
}

/// Write a rewrite tracker file containing `<params_hash>\n<rewrite_token>\n`.
pub fn write_rewrite_tracker(path: &Path, params_hash: &str, rewrite_token: &str) -> Result<()> {
    write_tracker_file(path, &format!("{params_hash}\n{rewrite_token}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_rfc3174_vectors() {
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn test_hash_filename_format() {
        let hashed = hash_filename("resumable_upload__mybucket__path_to_file.txt__JSON.url");
        assert!(hashed.starts_with("TRACKER_"));
        assert!(hashed.ends_with("e.txt__JSON.url") || hashed.ends_with(".txt__JSON.url"));
        // "TRACKER_" (8) + 40 hex + "." (1) + 16 trailing = 65 chars
        assert_eq!(hashed.len(), 65);
    }

    #[test]
    fn test_upload_and_rewrite_tracker_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = BotoConfig::new();
        cfg.set(
            "GSUtil",
            "resumable_tracker_dir",
            tmp.path().to_string_lossy().into_owned(),
        );

        let dst = StorageUrl::parse("gs://my-bucket/dir/obj.bin").unwrap();
        let path =
            get_tracker_file_path(&cfg, &dst, TrackerFileType::Upload, "JSON", None, None).unwrap();
        assert!(path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("upload_TRACKER_"));
        assert!(path.file_name().unwrap().to_str().unwrap().len() < MAX_TRACKER_FILE_NAME_LENGTH);

        write_upload_tracker(&path, Some("sha256-abc".into()), "session-uri-1".into()).unwrap();
        assert_eq!(
            read_upload_tracker(&path, Some("sha256-abc")).as_deref(),
            Some("session-uri-1")
        );
        // Mismatched encryption key deletes tracker and returns None.
        assert_eq!(read_upload_tracker(&path, Some("sha256-different")), None);
        assert!(!path.exists());

        // Rewrite tracker
        let rw_path =
            get_rewrite_tracker_file_path(&cfg, "src-b", "a/b", "dst-b", "c/d", "JSON").unwrap();
        let p_hash = hash_rewrite_parameters(&RewriteTrackerParams {
            src_bucket: "src-b",
            src_obj: "a/b",
            src_etag: "etag-1",
            dst_bucket: "dst-b",
            dst_obj: "c/d",
            dst_storage_class: Some("NEARLINE"),
            ..Default::default()
        });
        write_rewrite_tracker(&rw_path, &p_hash, "tok-123").unwrap();
        assert_eq!(
            read_rewrite_tracker(&rw_path, &p_hash).as_deref(),
            Some("tok-123")
        );
        assert_eq!(read_rewrite_tracker(&rw_path, "other-hash"), None);
        delete_tracker_file(&rw_path);
        assert!(!rw_path.exists());
    }

    #[test]
    fn test_sliced_download_tracker_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = BotoConfig::new();
        cfg.set(
            "GSUtil",
            "resumable_tracker_dir",
            tmp.path().to_string_lossy().into_owned(),
        );
        cfg.set("GSUtil", "resumable_threshold", "10");

        let local_file = tmp.path().join("out.bin");
        let dst = StorageUrl::parse(&local_file.to_string_lossy()).unwrap();
        let obj = Object {
            etag: Some("etag-42".into()),
            generation: Some("100".into()),
            size: Some("1024".into()),
            ..Default::default()
        };

        let parent = get_tracker_file_path(
            &cfg,
            &dst,
            TrackerFileType::SlicedDownload,
            "JSON",
            None,
            None,
        )
        .unwrap();
        write_sliced_download_tracker(&parent, &obj, 3).unwrap();
        for i in 0..3 {
            let (cp, start) = read_or_create_download_tracker(
                &cfg,
                &obj,
                &dst,
                "JSON",
                i as u64 * 100,
                0,
                Some(i),
            )
            .unwrap();
            assert!(cp.is_some());
            assert_eq!(start, i as u64 * 100);
        }

        delete_download_tracker_files(&cfg, &dst, "JSON");
        assert!(!parent.exists());
    }
}
