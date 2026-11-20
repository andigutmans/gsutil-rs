//! Wildcard pattern matching (`*`, `?`, `[...]`, `**` recursive globs).
//!
//! Matches `gslib/wildcard_iterator.py` in Python gsutil v5.38.

use regex::Regex;

use crate::error::{GsutilError, Result};
use crate::url::{contains_wildcard, strip_one_slash};

/// Result of `_BuildBucketFilterStrings` in `gslib/wildcard_iterator.py`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketFilterStrings {
    /// Prefix sent to GCS `objects.list` request.
    pub prefix: Option<String>,
    /// Delimiter sent to GCS `objects.list` request (`Some("/")` or `None` for `**`).
    pub delimiter: Option<String>,
    /// Wildcard pattern used to filter results of this listing level.
    pub prefix_wildcard: String,
    /// Remaining wildcard suffix for subsequent recursive prefix expansion.
    pub suffix_wildcard: String,
}

/// Builds `(prefix, delimiter, prefix_wildcard, suffix_wildcard)` for querying a GCS bucket
/// and filtering results, matching `CloudWildcardIterator._BuildBucketFilterStrings`.
pub fn build_bucket_filter_strings(wildcard: &str) -> BucketFilterStrings {
    let first_wc = wildcard
        .bytes()
        .position(|b| matches!(b, b'*' | b'?' | b'[' | b']'));

    let Some(wc_idx) = first_wc else {
        return BucketFilterStrings {
            prefix: Some(wildcard.to_string()),
            delimiter: Some("/".to_string()),
            prefix_wildcard: wildcard.to_string(),
            suffix_wildcard: String::new(),
        };
    };

    let (prefix, wildcard_part_full) = if wc_idx > 0 {
        (Some(wildcard[..wc_idx].to_string()), &wildcard[wc_idx..])
    } else {
        (None, wildcard)
    };

    let wildcard_part = match wildcard_part_full.find('/') {
        Some(end) => &wildcard_part_full[..=end],
        None => wildcard_part_full,
    };

    let mut prefix_wildcard = format!("{}{wildcard_part}", prefix.as_deref().unwrap_or(""));
    if !prefix_wildcard.ends_with("**/") {
        prefix_wildcard = strip_one_slash(&prefix_wildcard).to_string();
    }

    let after_wc = &wildcard[wc_idx + 1..];
    let mut suffix_wildcard = match after_wc.find('/') {
        Some(end) => after_wc[end + 1..].to_string(),
        None => String::new(),
    };

    let delimiter = if prefix_wildcard.contains("**") {
        prefix_wildcard.push_str(&suffix_wildcard);
        suffix_wildcard.clear();
        None
    } else {
        Some("/".to_string())
    };

    BucketFilterStrings {
        prefix,
        delimiter,
        prefix_wildcard,
        suffix_wildcard,
    }
}

/// Translates a shell-style fnmatch pattern (`*`, `?`, `[seq]`, `[!seq]`) into a
/// full-match regex string, matching Python's `fnmatch.translate`.
pub fn fnmatch_to_regex(pat: &str) -> String {
    let chars: Vec<char> = pat.chars().collect();
    let n = chars.len();
    let mut i = 0;
    let mut res = String::from("(?s)\\A");

    while i < n {
        let c = chars[i];
        i += 1;
        match c {
            '*' => {
                // Collapse consecutive `*` to avoid quadratic backtracking.
                while i < n && chars[i] == '*' {
                    i += 1;
                }
                res.push_str(".*");
            }
            '?' => {
                res.push('.');
            }
            '[' => {
                let mut j = i;
                if j < n && chars[j] == '!' {
                    j += 1;
                }
                if j < n && chars[j] == ']' {
                    j += 1;
                }
                while j < n && chars[j] != ']' {
                    j += 1;
                }
                if j >= n {
                    res.push_str("\\[");
                } else {
                    let stuff: String = chars[i..j].iter().collect();
                    let mut class_inner = String::new();
                    let mut stuff_chars = stuff.chars().peekable();
                    if stuff_chars.peek() == Some(&'!') {
                        stuff_chars.next();
                        class_inner.push('^');
                    } else if stuff_chars.peek() == Some(&'^') {
                        stuff_chars.next();
                        class_inner.push_str("\\^");
                    }
                    for sc in stuff_chars {
                        if sc == '\\' {
                            class_inner.push_str("\\\\");
                        } else if sc == '[' {
                            class_inner.push_str("\\[");
                        } else {
                            class_inner.push(sc);
                        }
                    }
                    res.push('[');
                    res.push_str(&class_inner);
                    res.push(']');
                    i = j + 1;
                }
            }
            other => {
                res.push_str(&regex::escape(&other.to_string()));
            }
        }
    }

    res.push_str("\\z");
    res
}

/// Compiled wildcard matcher matching `CloudWildcardIterator._GetRegexPatterns`
/// (including zero-or-more folder expansion for `/**/` and leading `**/`).
#[derive(Debug, Clone)]
pub struct WildcardMatcher {
    patterns: Vec<Regex>,
}

impl WildcardMatcher {
    /// Compile a gsutil wildcard pattern into one or more regexes.
    pub fn compile(wildcard_pattern: &str) -> Result<Self> {
        let mut raw_patterns = vec![wildcard_pattern.to_string()];

        let updated_pattern = if wildcard_pattern.contains("/**/") {
            let replaced = wildcard_pattern.replace("/**/", "/");
            raw_patterns.push(replaced.clone());
            replaced
        } else {
            wildcard_pattern.to_string()
        };

        for p in [wildcard_pattern, updated_pattern.as_str()] {
            if let Some(stripped) = p.strip_prefix("**/") {
                if !raw_patterns.iter().any(|existing| existing == stripped) {
                    raw_patterns.push(stripped.to_string());
                }
            }
        }

        let mut patterns = Vec::with_capacity(raw_patterns.len());
        for p in raw_patterns {
            let re_str = fnmatch_to_regex(&p);
            let re = Regex::new(&re_str).map_err(|e| {
                GsutilError::Wildcard(format!("Invalid wildcard pattern '{p}': {e}"))
            })?;
            patterns.push(re);
        }

        Ok(Self { patterns })
    }

    /// Returns `true` if `candidate` matches the wildcard pattern.
    pub fn is_match(&self, candidate: &str) -> bool {
        self.patterns.iter().any(|re| re.is_match(candidate))
    }
}

/// Convenience function to test whether `text` matches a gsutil wildcard `pattern`.
pub fn matches_wildcard(pattern: &str, text: &str) -> Result<bool> {
    if !contains_wildcard(pattern) {
        return Ok(pattern == text);
    }
    Ok(WildcardMatcher::compile(pattern)?.is_match(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnmatch_basic() {
        assert!(matches_wildcard("*.txt", "hello.txt").unwrap());
        assert!(!matches_wildcard("*.txt", "hello.rs").unwrap());
        assert!(matches_wildcard("file?.log", "file1.log").unwrap());
        assert!(!matches_wildcard("file?.log", "file12.log").unwrap());
        assert!(matches_wildcard("file[0-9].log", "file7.log").unwrap());
        assert!(!matches_wildcard("file[!0-9].log", "file7.log").unwrap());
        assert!(matches_wildcard("file[!0-9].log", "filea.log").unwrap());
    }

    #[test]
    fn test_double_star_zero_or_more_dirs() {
        let m1 = WildcardMatcher::compile("dir1/**/a.txt").unwrap();
        assert!(m1.is_match("dir1/a.txt"));
        assert!(m1.is_match("dir1/sub/a.txt"));
        assert!(m1.is_match("dir1/sub1/sub2/a.txt"));
        assert!(!m1.is_match("dir2/a.txt"));

        let m2 = WildcardMatcher::compile("**/a.txt").unwrap();
        assert!(m2.is_match("a.txt"));
        assert!(m2.is_match("x/y/a.txt"));

        let m3 = WildcardMatcher::compile("**/dir1/**/a.txt").unwrap();
        assert!(m3.is_match("dir1/a.txt"));
        assert!(m3.is_match("x/dir1/y/a.txt"));
    }

    #[test]
    fn test_build_bucket_filter_strings() {
        let f1 = build_bucket_filter_strings("abc/d*e/f*.txt");
        assert_eq!(f1.prefix.as_deref(), Some("abc/d"));
        assert_eq!(f1.delimiter.as_deref(), Some("/"));
        assert_eq!(f1.prefix_wildcard, "abc/d*e");
        assert_eq!(f1.suffix_wildcard, "f*.txt");

        let f2 = build_bucket_filter_strings("abc/**/f*.txt");
        assert_eq!(f2.prefix.as_deref(), Some("abc/"));
        assert_eq!(f2.delimiter, None);
        assert_eq!(f2.prefix_wildcard, "abc/**/f*.txt");
        assert_eq!(f2.suffix_wildcard, "");

        let f3 = build_bucket_filter_strings("dir/plain.txt");
        assert_eq!(f3.prefix.as_deref(), Some("dir/plain.txt"));
        assert_eq!(f3.delimiter.as_deref(), Some("/"));
        assert_eq!(f3.prefix_wildcard, "dir/plain.txt");
        assert_eq!(f3.suffix_wildcard, "");
    }
}
