//! POSIX metadata preservation (`-P`) helpers.
//!
//! Matches `gslib/utils/posix_util.py` in Python gsutil v5.38.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use gsutil_core::error::Result;

/// Custom metadata keys matching `gslib/utils/posix_util.py`.
pub const ATIME_ATTR: &str = "goog-reserved-file-atime";
pub const MTIME_ATTR: &str = "goog-reserved-file-mtime";
pub const UID_ATTR: &str = "goog-reserved-posix-uid";
pub const GID_ATTR: &str = "goog-reserved-posix-gid";
pub const MODE_ATTR: &str = "goog-reserved-posix-mode";

/// POSIX attributes extracted from a local file or GCS custom metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PosixAttributes {
    pub atime: Option<i64>,
    pub mtime: Option<i64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// File permission bits (e.g. `0o644`).
    pub mode: Option<u32>,
}

impl PosixAttributes {
    pub fn is_empty(&self) -> bool {
        self.atime.is_none()
            && self.mtime.is_none()
            && self.uid.is_none()
            && self.gid.is_none()
            && self.mode.is_none()
    }

    /// Format permission bits as 3-digit octal string (e.g. `"644"`), matching gsutil.
    pub fn mode_octal_string(&self) -> Option<String> {
        self.mode.map(|m| format!("{:03o}", m & 0o777))
    }
}

/// Read POSIX attributes from a local filesystem path.
pub fn read_local_posix_attributes(path: &Path) -> Result<PosixAttributes> {
    let meta = std::fs::metadata(path)?;
    let mtime = meta.modified().ok().and_then(system_time_to_epoch_secs);
    let atime = meta.accessed().ok().and_then(system_time_to_epoch_secs);

    #[cfg(unix)]
    let (uid, gid, mode) = {
        use std::os::unix::fs::MetadataExt;
        (
            Some(meta.uid()),
            Some(meta.gid()),
            Some(meta.mode() & 0o777),
        )
    };

    #[cfg(not(unix))]
    let (uid, gid, mode) = (None, None, None);

    Ok(PosixAttributes {
        atime,
        mtime,
        uid,
        gid,
        mode,
    })
}

/// Serialize POSIX attributes into GCS object custom metadata map.
pub fn serialize_posix_to_metadata(
    attrs: &PosixAttributes,
    metadata: &mut BTreeMap<String, String>,
) {
    if let Some(atime) = attrs.atime {
        if atime >= 0 {
            metadata.insert(ATIME_ATTR.to_string(), atime.to_string());
        }
    }
    if let Some(mtime) = attrs.mtime {
        if mtime >= 0 {
            metadata.insert(MTIME_ATTR.to_string(), mtime.to_string());
        }
    }
    if let Some(uid) = attrs.uid {
        metadata.insert(UID_ATTR.to_string(), uid.to_string());
    }
    if let Some(gid) = attrs.gid {
        metadata.insert(GID_ATTR.to_string(), gid.to_string());
    }
    if let Some(mode_str) = attrs.mode_octal_string() {
        metadata.insert(MODE_ATTR.to_string(), mode_str);
    }
}

/// Deserialize POSIX attributes from GCS object custom metadata map.
pub fn deserialize_posix_from_metadata(metadata: &BTreeMap<String, String>) -> PosixAttributes {
    let atime = metadata
        .get(ATIME_ATTR)
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|&v| v >= 0);
    let mtime = metadata
        .get(MTIME_ATTR)
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|&v| v >= 0);
    let uid = metadata
        .get(UID_ATTR)
        .and_then(|v| v.trim().parse::<u32>().ok());
    let gid = metadata
        .get(GID_ATTR)
        .and_then(|v| v.trim().parse::<u32>().ok());
    let mode = metadata.get(MODE_ATTR).and_then(|v| {
        let s = v.trim();
        if s.len() == 3 && s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            u32::from_str_radix(s, 8).ok()
        } else {
            None
        }
    });

    PosixAttributes {
        atime,
        mtime,
        uid,
        gid,
        mode,
    }
}

/// Apply POSIX attributes (mtime/atime, then mode) to a local file.
///
/// Timestamps are applied BEFORE `set_permissions` so read-only modes (e.g. `0o444`)
/// do not prevent opening the file handle to update `mtime`/`atime`.
/// UID/GID changes require elevated privileges on Unix and are skipped if not permitted.
pub fn apply_posix_to_local_file(path: &Path, attrs: &PosixAttributes) -> Result<()> {
    // Apply mtime / atime first using std::fs::File::set_times (stabilized in Rust 1.75).
    if attrs.mtime.is_some() || attrs.atime.is_some() {
        let mut times = std::fs::FileTimes::new();
        if let Some(mtime) = attrs.mtime {
            if mtime >= 0 {
                times =
                    times.set_modified(UNIX_EPOCH + std::time::Duration::from_secs(mtime as u64));
            }
        }
        if let Some(atime) = attrs.atime {
            if atime >= 0 {
                times =
                    times.set_accessed(UNIX_EPOCH + std::time::Duration::from_secs(atime as u64));
            }
        }
        if let Ok(file) = std::fs::OpenOptions::new().write(true).open(path) {
            let _ = file.set_times(times);
        }
    }

    #[cfg(unix)]
    if let Some(gid) = attrs.gid {
        let _ = std::os::unix::fs::chown(path, None, Some(gid));
    }

    #[cfg(unix)]
    if let Some(mode) = attrs.mode {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode & 0o777);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Validate that applying `attrs` (uid/gid/mode) to a downloaded file will not orphan it.
///
/// Mirrors `gslib/utils/posix_util.py::ValidateFilePermissionAccess`.
pub fn validate_file_permission_access(
    url_str: &str,
    attrs: &PosixAttributes,
) -> std::result::Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (url_str, attrs);
        Ok(())
    }

    #[cfg(unix)]
    {
        let uid_present = attrs.uid.is_some();
        let gid_present = attrs.gid.is_some();
        let mode_present = attrs.mode.is_some();
        if !uid_present && !gid_present && !mode_present {
            return Ok(());
        }

        // Root can access files regardless of permissions.
        if unsafe { libc::geteuid() } == 0 {
            return Ok(());
        }

        const U_R: u32 = 0o400;
        const G_R: u32 = 0o040;
        const O_R: u32 = 0o004;

        let mode_valid = attrs
            .mode
            .map(|m| (m & U_R) != 0 || (m & G_R) != 0 || (m & O_R) != 0)
            .unwrap_or(false);
        let mode = if let Some(m) = attrs.mode {
            if !mode_valid {
                return Err(format!("Mode for {url_str} won't allow read access."));
            }
            m
        } else {
            0o666
        };

        if let Some(uid) = attrs.uid {
            let pw = unsafe { libc::getpwuid(uid as libc::uid_t) };
            if pw.is_null() {
                return Err(format!(
                    "UID for {url_str} doesn't exist on current system. uid: {uid}"
                ));
            }
        }
        if let Some(gid) = attrs.gid {
            let gr = unsafe { libc::getgrgid(gid as libc::gid_t) };
            if gr.is_null() {
                return Err(format!(
                    "GID for {url_str} doesn't exist on current system. gid: {gid}"
                ));
            }
        }

        let current_uid = unsafe { libc::getuid() };
        let uid_is_current_user = attrs.uid.is_some_and(|u| u == current_uid);

        if !uid_present && gid_present && mode_present && (mode & U_R) == 0 {
            return Err(format!(
                "Insufficient access with uid/gid/mode for {url_str}, gid: {}, mode: {:03o}",
                attrs.gid.unwrap_or(0),
                mode & 0o777
            ));
        }

        if uid_is_current_user {
            if (mode & U_R) != 0 {
                return Ok(());
            }
            return Err(format!(
                "Insufficient access with uid/gid/mode for {url_str}, uid: {}, mode: {:03o}",
                attrs.uid.unwrap_or(0),
                mode & 0o777
            ));
        }

        let user_groups = current_user_groups();
        if let Some(gid) = attrs.gid {
            if user_groups.contains(&gid) {
                if (mode & G_R) != 0 {
                    return Ok(());
                }
                return Err(format!(
                    "Insufficient access with uid/gid/mode for {url_str}, gid: {gid}, mode: {:03o}",
                    mode & 0o777
                ));
            }
        }

        if (mode & O_R) != 0 {
            return Ok(());
        }
        if !uid_present && !gid_present && mode_valid {
            return Ok(());
        }
        Err(format!("There was a problem validating {url_str}."))
    }
}

#[cfg(unix)]
fn current_user_groups() -> Vec<u32> {
    let mut groups = vec![unsafe { libc::getgid() }];
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n > 0 {
        let mut buf = vec![0 as libc::gid_t; n as usize];
        let actual = unsafe { libc::getgroups(n, buf.as_mut_ptr()) };
        if actual > 0 {
            for &g in &buf[..actual as usize] {
                if !groups.contains(&g) {
                    groups.push(g);
                }
            }
        }
    }
    groups
}

/// Parse an RFC 3339 timestamp string (e.g. GCS `timeCreated`) to Unix epoch seconds.
pub fn parse_rfc3339_to_epoch_secs(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.timestamp())
}

fn system_time_to_epoch_secs(t: SystemTime) -> Option<i64> {
    t.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_posix_metadata_roundtrip() {
        let attrs = PosixAttributes {
            atime: Some(1_700_000_100),
            mtime: Some(1_700_000_200),
            uid: Some(1000),
            gid: Some(1000),
            mode: Some(0o640),
        };
        let mut map = BTreeMap::new();
        serialize_posix_to_metadata(&attrs, &mut map);
        assert_eq!(map.get(MODE_ATTR).map(String::as_str), Some("640"));
        assert_eq!(map.get(MTIME_ATTR).map(String::as_str), Some("1700000200"));

        let decoded = deserialize_posix_from_metadata(&map);
        assert_eq!(decoded, attrs);
    }

    #[test]
    fn test_local_posix_read_and_apply() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("sample.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        let target = PosixAttributes {
            atime: Some(1_700_000_000),
            mtime: Some(1_700_000_123),
            uid: None,
            gid: None,
            mode: Some(0o600),
        };
        apply_posix_to_local_file(&file_path, &target).unwrap();

        let read_back = read_local_posix_attributes(&file_path).unwrap();
        assert_eq!(read_back.mtime, Some(1_700_000_123));
        #[cfg(unix)]
        assert_eq!(read_back.mode, Some(0o600));
    }
}
