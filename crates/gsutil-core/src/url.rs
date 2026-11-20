//! File and Cloud Storage URL representation and parsing.
//!
//! Matches `gslib/storage_url.py` in Python gsutil v5.38.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use crate::error::{GsutilError, Result};

/// Returns `true` if `s` contains any wildcard characters (`*`, `?`, `[`, `]`).
pub fn contains_wildcard(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, b'*' | b'?' | b'[' | b']'))
}

/// Strip at most one trailing `/` from `s`.
pub fn strip_one_slash(s: &str) -> &str {
    s.strip_suffix('/').unwrap_or(s)
}

/// Extract the lowercased URL scheme, defaulting to `"file"` when no `://` is present.
pub fn get_scheme_from_url_string(url_str: &str) -> String {
    match url_str.find("://") {
        Some(idx) => url_str[..idx].to_ascii_lowercase(),
        None => "file".to_string(),
    }
}

/// Returns `true` if `scheme` is one of `"file"`, `"gs"`, or `"s3"`.
pub fn is_known_url_scheme(scheme: &str) -> bool {
    matches!(scheme, "file" | "gs" | "s3")
}

/// Returns `true` if `url_str` has the `"file"` scheme (or no scheme).
pub fn is_file_url_string(url_str: &str) -> bool {
    get_scheme_from_url_string(url_str) == "file"
}

fn get_path_from_url_string(url_str: &str) -> &str {
    match url_str.find("://") {
        Some(idx) => &url_str[idx + 3..],
        None => url_str,
    }
}

/// Check if `object_name` uses `**` in an undefined position (directly preceded or
/// followed by characters other than `delim`).
pub fn has_unsupported_double_wildcard(object_name: &str, delim: char) -> bool {
    if object_name.is_empty() {
        return false;
    }
    let bounded = format!("{delim}{object_name}{delim}");
    let sep = format!("{delim}**{delim}");
    let stripped: String = bounded.split(&sep).collect();
    stripped.contains("**")
}

/// Cloud storage provider scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloudScheme {
    Gs,
    S3,
}

impl CloudScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Gs => "gs",
            Self::S3 => "s3",
        }
    }
}

impl fmt::Display for CloudScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Representation of a local filesystem URL (`file://...` or bare path).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileUrl {
    pub object_name: String,
    pub is_stream: bool,
    pub is_fifo: bool,
}

impl FileUrl {
    pub fn parse(url_str: &str) -> Self {
        let path = get_path_from_url_string(url_str);
        let is_stream = path == "-";
        let is_fifo = is_path_fifo(path);
        Self {
            object_name: path.to_string(),
            is_stream,
            is_fifo,
        }
    }

    pub fn scheme(&self) -> &'static str {
        "file"
    }

    pub fn delim(&self) -> char {
        std::path::MAIN_SEPARATOR
    }

    pub fn is_directory(&self) -> bool {
        !self.is_stream && !self.is_fifo && Path::new(&self.object_name).is_dir()
    }

    pub fn url_string(&self) -> String {
        format!("file://{}", self.object_name)
    }

    pub fn versionless_url_string(&self) -> String {
        self.url_string()
    }

    pub fn create_prefix_url(&self, _wildcard_suffix: Option<&str>) -> String {
        self.url_string()
    }
}

impl fmt::Display for FileUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "file://{}", self.object_name)
    }
}

#[cfg(unix)]
fn is_path_fifo(path: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path)
        .map(|m| m.file_type().is_fifo())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_path_fifo(_path: &str) -> bool {
    false
}

/// Representation of a cloud storage URL (`gs://...` or `s3://...`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CloudUrl {
    pub scheme: CloudScheme,
    pub bucket_name: Option<String>,
    pub object_name: Option<String>,
    pub generation: Option<String>,
}

impl CloudUrl {
    pub fn parse(url_str: &str) -> Result<Self> {
        let scheme_end = url_str.find("://").ok_or_else(|| {
            GsutilError::invalid_url(format!(
                "CloudUrl: URL string {url_str} did not match URL regex"
            ))
        })?;
        let raw_scheme = &url_str[..scheme_end];
        let scheme = match raw_scheme.to_ascii_lowercase().as_str() {
            "gs" => CloudScheme::Gs,
            "s3" => CloudScheme::S3,
            other => {
                return Err(GsutilError::invalid_url(format!(
                    "Unrecognized scheme \"{other}\""
                )));
            }
        };

        let rest = &url_str[scheme_end + 3..];
        if rest.starts_with('/') {
            return Err(GsutilError::invalid_url(format!(
                "Cloud URL scheme should be followed by colon and two slashes: \"://\". Found: \"{url_str}\""
            )));
        }

        if rest.is_empty() {
            return Ok(Self {
                scheme,
                bucket_name: None,
                object_name: None,
                generation: None,
            });
        }

        match rest.find('/') {
            None => Ok(Self {
                scheme,
                bucket_name: Some(rest.to_string()),
                object_name: None,
                generation: None,
            }),
            Some(slash_idx) => {
                let bucket = &rest[..slash_idx];
                let obj = &rest[slash_idx + 1..];
                if obj.is_empty() {
                    return Ok(Self {
                        scheme,
                        bucket_name: Some(bucket.to_string()),
                        object_name: None,
                        generation: None,
                    });
                }

                if obj == "." || obj == ".." {
                    return Err(GsutilError::invalid_url(format!(
                        "{obj} is an invalid root-level object name"
                    )));
                }

                let (object_name, generation) = split_object_generation(scheme, obj);
                Ok(Self {
                    scheme,
                    bucket_name: Some(bucket.to_string()),
                    object_name: Some(object_name),
                    generation,
                })
            }
        }
    }

    pub fn delim(&self) -> char {
        '/'
    }

    pub fn is_provider(&self) -> bool {
        self.bucket_name.is_none()
    }

    pub fn is_bucket(&self) -> bool {
        self.bucket_name.as_deref().is_some_and(|b| !b.is_empty()) && self.object_name.is_none()
    }

    pub fn is_object(&self) -> bool {
        self.bucket_name.as_deref().is_some_and(|b| !b.is_empty())
            && self.object_name.as_deref().is_some_and(|o| !o.is_empty())
    }

    pub fn has_generation(&self) -> bool {
        self.generation.as_deref().is_some_and(|g| !g.is_empty())
    }

    pub fn bucket_url_string(&self) -> String {
        match &self.bucket_name {
            Some(b) => format!("{}://{b}/", self.scheme),
            None => format!("{}://", self.scheme),
        }
    }

    pub fn versionless_url_string(&self) -> String {
        if self.is_provider() {
            format!("{}://", self.scheme)
        } else if self.is_bucket() {
            self.bucket_url_string()
        } else {
            format!(
                "{}://{}/{}",
                self.scheme,
                self.bucket_name.as_deref().unwrap_or(""),
                self.object_name.as_deref().unwrap_or("")
            )
        }
    }

    pub fn url_string(&self) -> String {
        let mut s = self.versionless_url_string();
        if let Some(ref gen) = self.generation {
            if !gen.is_empty() {
                s.push('#');
                s.push_str(gen);
            }
        }
        s
    }

    /// Matches `_CloudUrl.CreatePrefixUrl`.
    pub fn create_prefix_url(&self, wildcard_suffix: Option<&str>) -> String {
        let base = self.versionless_url_string();
        let prefix = strip_one_slash(&base);
        match wildcard_suffix {
            Some(suffix) if !suffix.is_empty() => format!("{prefix}/{suffix}"),
            _ => prefix.to_string(),
        }
    }
}

impl fmt::Display for CloudUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url_string())
    }
}

/// Split `#generation` (for `gs://`, numeric) or `#version_id` (for `s3://`, any non-empty).
fn split_object_generation(scheme: CloudScheme, obj: &str) -> (String, Option<String>) {
    if let Some(hash_idx) = obj.rfind('#') {
        let before = &obj[..hash_idx];
        let after = &obj[hash_idx + 1..];
        if !before.is_empty() && !after.is_empty() {
            match scheme {
                CloudScheme::Gs => {
                    if after.bytes().all(|b| b.is_ascii_digit()) {
                        return (before.to_string(), Some(after.to_string()));
                    }
                }
                CloudScheme::S3 => {
                    return (before.to_string(), Some(after.to_string()));
                }
            }
        }
    }
    (obj.to_string(), None)
}

/// Unified Storage URL (either `File` or `Cloud`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StorageUrl {
    File(FileUrl),
    Cloud(CloudUrl),
}

impl StorageUrl {
    /// Static factory matching `StorageUrlFromString` in `gslib/storage_url.py`.
    pub fn parse(url_str: &str) -> Result<Self> {
        let scheme = get_scheme_from_url_string(url_str);
        if !is_known_url_scheme(&scheme) {
            return Err(GsutilError::invalid_url(format!(
                "Unrecognized scheme \"{scheme}\""
            )));
        }
        if scheme == "file" {
            Ok(Self::File(FileUrl::parse(url_str)))
        } else {
            Ok(Self::Cloud(CloudUrl::parse(url_str)?))
        }
    }

    pub fn is_file_url(&self) -> bool {
        matches!(self, Self::File(_))
    }

    pub fn is_cloud_url(&self) -> bool {
        matches!(self, Self::Cloud(_))
    }

    pub fn is_provider(&self) -> bool {
        matches!(self, Self::Cloud(c) if c.is_provider())
    }

    pub fn is_bucket(&self) -> bool {
        matches!(self, Self::Cloud(c) if c.is_bucket())
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Self::Cloud(c) if c.is_object())
    }

    pub fn is_stream(&self) -> bool {
        matches!(self, Self::File(f) if f.is_stream)
    }

    pub fn is_fifo(&self) -> bool {
        matches!(self, Self::File(f) if f.is_fifo)
    }

    pub fn scheme(&self) -> &'static str {
        match self {
            Self::File(f) => f.scheme(),
            Self::Cloud(c) => c.scheme.as_str(),
        }
    }

    pub fn bucket_name(&self) -> Option<&str> {
        match self {
            Self::File(_) => None,
            Self::Cloud(c) => c.bucket_name.as_deref(),
        }
    }

    pub fn object_name(&self) -> Option<&str> {
        match self {
            Self::File(f) => Some(f.object_name.as_str()),
            Self::Cloud(c) => c.object_name.as_deref(),
        }
    }

    pub fn generation(&self) -> Option<&str> {
        match self {
            Self::File(_) => None,
            Self::Cloud(c) => c.generation.as_deref(),
        }
    }

    pub fn has_generation(&self) -> bool {
        self.generation().is_some()
    }

    pub fn url_string(&self) -> String {
        match self {
            Self::File(f) => f.url_string(),
            Self::Cloud(c) => c.url_string(),
        }
    }

    pub fn versionless_url_string(&self) -> String {
        match self {
            Self::File(f) => f.versionless_url_string(),
            Self::Cloud(c) => c.versionless_url_string(),
        }
    }

    pub fn create_prefix_url(&self, wildcard_suffix: Option<&str>) -> String {
        match self {
            Self::File(f) => f.create_prefix_url(wildcard_suffix),
            Self::Cloud(c) => c.create_prefix_url(wildcard_suffix),
        }
    }

    pub fn as_cloud(&self) -> Option<&CloudUrl> {
        match self {
            Self::Cloud(c) => Some(c),
            Self::File(_) => None,
        }
    }

    pub fn as_file(&self) -> Option<&FileUrl> {
        match self {
            Self::File(f) => Some(f),
            Self::Cloud(_) => None,
        }
    }

    /// Returns `true` if this URL represents a cloud subdir placeholder
    /// (`_$folder$` or zero-size object ending in `/`).
    pub fn is_cloud_subdir_placeholder(&self, object_size: Option<u64>) -> bool {
        if !self.is_cloud_url() {
            return false;
        }
        let url_str = self.url_string();
        if url_str.ends_with("_$folder$") {
            return true;
        }
        let size = object_size.unwrap_or(0);
        size == 0 && url_str.ends_with('/')
    }
}

impl FromStr for StorageUrl {
    type Err = GsutilError;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl fmt::Display for StorageUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.url_string())
    }
}

/// Checks whether any URL string in `args` is a file URL.
pub fn have_file_urls<S: AsRef<str>>(args: &[S]) -> Result<bool> {
    for arg in args {
        if StorageUrl::parse(arg.as_ref())?.is_file_url() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Checks whether any URL string in `args` is a cloud provider URL (`gs://`, `s3://`).
pub fn have_provider_urls<S: AsRef<str>>(args: &[S]) -> Result<bool> {
    for arg in args {
        if StorageUrl::parse(arg.as_ref())?.is_provider() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Returns `true` if `args` is non-empty and all URLs share the same scheme.
pub fn urls_are_for_single_provider<S: AsRef<str>>(args: &[S]) -> Result<bool> {
    let mut provider: Option<&'static str> = None;
    for arg in args {
        let u = StorageUrl::parse(arg.as_ref())?;
        match provider {
            None => provider = Some(u.scheme()),
            Some(p) if p != u.scheme() => return Ok(false),
            _ => {}
        }
    }
    Ok(provider.is_some())
}

/// Returns `true` if `urls` are all cloud URLs and contain a mix of buckets and objects.
pub fn urls_are_mix_of_buckets_and_objects(urls: &[StorageUrl]) -> bool {
    if !urls.iter().all(|u| u.is_cloud_url()) {
        return false;
    }
    let any_bucket = urls.iter().any(|u| u.is_bucket());
    let all_buckets = urls.iter().all(|u| u.is_bucket());
    any_bucket && !all_buckets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_provider_bucket_object() {
        let p = StorageUrl::parse("gs://").unwrap();
        assert!(p.is_cloud_url());
        assert!(p.is_provider());
        assert!(!p.is_bucket());
        assert!(!p.is_object());
        assert_eq!(p.url_string(), "gs://");

        let b = StorageUrl::parse("gs://my-bucket").unwrap();
        assert!(b.is_bucket());
        assert_eq!(b.bucket_name(), Some("my-bucket"));
        assert_eq!(b.url_string(), "gs://my-bucket/");

        let b_slash = StorageUrl::parse("gs://my-bucket/").unwrap();
        assert_eq!(b, b_slash);

        let o = StorageUrl::parse("gs://my-bucket/path/to/obj").unwrap();
        assert!(o.is_object());
        assert_eq!(o.bucket_name(), Some("my-bucket"));
        assert_eq!(o.object_name(), Some("path/to/obj"));
        assert_eq!(o.generation(), None);
        assert_eq!(o.url_string(), "gs://my-bucket/path/to/obj");
    }

    #[test]
    fn test_generation_parsing() {
        let o = StorageUrl::parse("gs://bkt/a/b#123456789").unwrap();
        assert_eq!(o.object_name(), Some("a/b"));
        assert_eq!(o.generation(), Some("123456789"));
        assert_eq!(o.versionless_url_string(), "gs://bkt/a/b");
        assert_eq!(o.url_string(), "gs://bkt/a/b#123456789");

        // Non-numeric `#tag` on gs:// is part of object name, not generation.
        let o2 = StorageUrl::parse("gs://bkt/file#v1").unwrap();
        assert_eq!(o2.object_name(), Some("file#v1"));
        assert_eq!(o2.generation(), None);

        // S3 accepts arbitrary version IDs.
        let s3 = StorageUrl::parse("s3://bkt/file#NULL").unwrap();
        assert_eq!(s3.object_name(), Some("file"));
        assert_eq!(s3.generation(), Some("NULL"));
    }

    #[test]
    fn test_invalid_urls() {
        assert!(StorageUrl::parse("http://example.com").is_err());
        assert!(StorageUrl::parse("gs:///leading-slash").is_err());
        assert!(StorageUrl::parse("gs://bkt/.").is_err());
        assert!(StorageUrl::parse("gs://bkt/..").is_err());
    }

    #[test]
    fn test_file_urls() {
        let f1 = StorageUrl::parse("/tmp/foo.txt").unwrap();
        assert!(f1.is_file_url());
        assert_eq!(f1.object_name(), Some("/tmp/foo.txt"));
        assert_eq!(f1.url_string(), "file:///tmp/foo.txt");

        let f2 = StorageUrl::parse("file:///tmp/foo.txt").unwrap();
        assert_eq!(f1, f2);

        let stream = StorageUrl::parse("-").unwrap();
        assert!(stream.is_stream());
    }

    #[test]
    fn test_create_prefix_url() {
        let u1 = StorageUrl::parse("gs://bucket/subdir/").unwrap();
        assert_eq!(u1.create_prefix_url(Some("*")), "gs://bucket/subdir/*");
        let u2 = StorageUrl::parse("gs://bucket/").unwrap();
        assert_eq!(u2.create_prefix_url(Some("*")), "gs://bucket/*");
        assert_eq!(u2.create_prefix_url(None), "gs://bucket");
        let u3 = StorageUrl::parse("gs://bucket/subdir//").unwrap();
        assert_eq!(u3.create_prefix_url(Some("*")), "gs://bucket/subdir//*");
    }

    #[test]
    fn test_cloud_subdir_placeholder() {
        let p1 = StorageUrl::parse("gs://b/dir_$folder$").unwrap();
        assert!(p1.is_cloud_subdir_placeholder(Some(10)));
        let p2 = StorageUrl::parse("gs://b/dir/").unwrap();
        assert!(p2.is_cloud_subdir_placeholder(Some(0)));
        assert!(!p2.is_cloud_subdir_placeholder(Some(5)));
    }

    #[test]
    fn test_unsupported_double_wildcard() {
        assert!(!has_unsupported_double_wildcard("**", '/'));
        assert!(!has_unsupported_double_wildcard("**/foo", '/'));
        assert!(!has_unsupported_double_wildcard("foo/**", '/'));
        assert!(!has_unsupported_double_wildcard("foo/**/bar", '/'));
        assert!(has_unsupported_double_wildcard("foo**/bar", '/'));
        assert!(has_unsupported_double_wildcard("foo/**bar", '/'));
    }
}
