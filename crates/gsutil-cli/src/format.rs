//! Output formatting helpers matching `gslib/utils/ls_helper.py`, `gslib/commands/ls.py`,
//! and `gslib/utils/unit_util.py` in Python gsutil v5.38.

use chrono::{DateTime, Utc};
use gsutil_core::api::{Bucket, Object};

const EXP_STRINGS: &[(u32, &str)] = &[
    (0, "B"),
    (10, "KiB"),
    (20, "MiB"),
    (30, "GiB"),
    (40, "TiB"),
    (50, "PiB"),
    (60, "EiB"),
];

/// Port of `MakeHumanReadable(num)` from `gslib/utils/unit_util.py`.
/// Uses `%g %s` formatting after rounding to 2 decimal places at the nearest binary power.
pub fn make_human_readable(num: u64) -> String {
    let mut i = 0usize;
    while i + 1 < EXP_STRINGS.len() && (num as u128) >= (1u128 << EXP_STRINGS[i + 1].0) {
        i += 1;
    }
    let divisor = (1u64 << EXP_STRINGS[i].0) as f64;
    let rounded = ((num as f64 / divisor) * 100.0).round() / 100.0;
    let formatted = format_g(rounded);
    format!("{formatted} {}", EXP_STRINGS[i].1)
}

/// Approximate Python's `%g` formatting for values already rounded to 2 decimal places.
fn format_g(val: f64) -> String {
    if val == 0.0 {
        return "0".to_string();
    }
    let s = format!("{val:.2}");
    let trimmed = s.trim_end_matches('0').trim_end_matches('.');
    trimmed.to_string()
}

/// Format an RFC 3339 timestamp string into `YYYY-MM-DDTHH:MM:SSZ` (matching `ls -l`).
pub fn format_ls_timestamp(ts: Option<&str>) -> String {
    let Some(raw) = ts else {
        return "None".to_string();
    };
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return dt
            .with_timezone(&Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
    }
    raw.to_string()
}

/// Format an RFC 3339 timestamp string into `%a, %d %b %Y %H:%M:%S GMT` (matching `ls -L` / `stat`).
pub fn format_rfc2822_gmt(ts: &str) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        return dt
            .with_timezone(&Utc)
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
    }
    ts.to_string()
}

/// Format an RFC 3339 timestamp string into `%a, %d %b %Y` (matching `ls -L -b` autoclass toggle time).
pub fn format_date_only(ts: &str) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
        return dt.with_timezone(&Utc).format("%a, %d %b %Y").to_string();
    }
    ts.to_string()
}

/// Port of `MakeMetadataLine(label, value, indent=1)` from `gslib/utils/ls_helper.py`.
pub fn make_metadata_line(label: &str, value: &str, indent: usize) -> String {
    let prefix = format!("{}{label}:", " ".repeat(indent * 4));
    if prefix.len() < 28 {
        format!("{prefix:<28}{value}")
    } else {
        format!("{prefix}{value}")
    }
}

/// Format full object metadata lines (matching `PrintFullInfoAboutObject` in `gslib/utils/ls_helper.py`).
/// Returns `(lines, num_objs, num_bytes)`.
pub fn format_full_info_about_object(
    url_str: &str,
    obj: &Object,
    incl_acl: bool,
) -> (Vec<String>, u64, u64) {
    let size = obj.size_bytes();
    let mut lines = Vec::new();
    lines.push(format!("{url_str}:"));

    if let Some(ref tc) = obj.time_created {
        lines.push(make_metadata_line(
            "Creation time",
            &format_rfc2822_gmt(tc),
            1,
        ));
    }
    if let Some(ref upd) = obj.updated {
        lines.push(make_metadata_line(
            "Update time",
            &format_rfc2822_gmt(upd),
            1,
        ));
    }
    if let Some(ref tscu) = obj.time_storage_class_updated {
        if obj.time_created.as_deref() != Some(tscu.as_str()) {
            lines.push(make_metadata_line(
                "Storage class update time",
                &format_rfc2822_gmt(tscu),
                1,
            ));
        }
    }
    if let Some(ref sc) = obj.storage_class {
        lines.push(make_metadata_line("Storage class", sc, 1));
    }
    if obj.temporary_hold == Some(true) {
        lines.push(make_metadata_line("Temporary Hold", "Enabled", 1));
    }
    if obj.event_based_hold == Some(true) {
        lines.push(make_metadata_line("Event-Based Hold", "Enabled", 1));
    }
    if let Some(ref ret) = obj.retention_expiration_time {
        lines.push(make_metadata_line(
            "Retention Expiration",
            &format_rfc2822_gmt(ret),
            1,
        ));
    }
    if let Some(ref kms) = obj.kms_key_name {
        lines.push(make_metadata_line("KMS key", kms, 1));
    }
    if let Some(ref cc) = obj.cache_control {
        lines.push(make_metadata_line("Cache-Control", cc, 1));
    }
    if let Some(ref cd) = obj.content_disposition {
        lines.push(make_metadata_line("Content-Disposition", cd, 1));
    }
    if let Some(ref ce) = obj.content_encoding {
        lines.push(make_metadata_line("Content-Encoding", ce, 1));
    }
    if let Some(ref cl) = obj.content_language {
        lines.push(make_metadata_line("Content-Language", cl, 1));
    }
    lines.push(make_metadata_line("Content-Length", &size.to_string(), 1));
    lines.push(make_metadata_line(
        "Content-Type",
        obj.content_type.as_deref().unwrap_or("None"),
        1,
    ));
    if let Some(cc) = obj.component_count {
        lines.push(make_metadata_line("Component-Count", &cc.to_string(), 1));
    }
    if let Some(ref ct) = obj.custom_time {
        lines.push(make_metadata_line("Custom-Time", ct, 1));
    }
    if let Some(ref td) = obj.time_deleted {
        lines.push(make_metadata_line(
            "Noncurrent time",
            &format_rfc2822_gmt(td),
            1,
        ));
    }
    if let Some(ref meta) = obj.metadata {
        if !meta.is_empty() {
            lines.push(make_metadata_line("Metadata", "", 1));
            for (k, v) in meta {
                lines.push(make_metadata_line(k, v, 2));
            }
        }
    }
    if let Some(ref ce) = obj.customer_encryption {
        if obj.crc32c.is_none() {
            lines.push(make_metadata_line("Hash (crc32c)", "encrypted", 1));
        }
        if obj.md5_hash.is_none() {
            lines.push(make_metadata_line("Hash (md5)", "encrypted", 1));
        }
        if let Some(ref alg) = ce.encryption_algorithm {
            lines.push(make_metadata_line("Encryption algorithm", alg, 1));
        }
        if let Some(ref sha) = ce.key_sha256 {
            lines.push(make_metadata_line("Encryption key SHA256", sha, 1));
        }
    }
    if let Some(ref crc) = obj.crc32c {
        lines.push(make_metadata_line("Hash (crc32c)", crc, 1));
    }
    if let Some(ref md5) = obj.md5_hash {
        lines.push(make_metadata_line("Hash (md5)", md5, 1));
    }
    let etag = obj
        .etag
        .as_deref()
        .unwrap_or("")
        .trim_matches(|c| c == '"' || c == '\'');
    lines.push(make_metadata_line("ETag", etag, 1));
    if let Some(ref gen) = obj.generation {
        lines.push(make_metadata_line("Generation", gen, 1));
    }
    if let Some(ref mgen) = obj.metageneration {
        lines.push(make_metadata_line("Metageneration", mgen, 1));
    }
    if incl_acl {
        let acl_str = match &obj.acl {
            Some(acl) if !acl.is_empty() => {
                serde_json::to_string_pretty(acl).unwrap_or_else(|_| "[]".to_string())
            }
            _ => "[]".to_string(),
        };
        lines.push(make_metadata_line("ACL", &acl_str, 1));
    }

    (lines, 1, size)
}

fn indent_multiline(val: &str) -> String {
    if !val.contains('\n') {
        return val.to_string();
    }
    let replaced = val.replace('\n', "\n\t  ");
    if replaced.starts_with('\n') {
        replaced
    } else {
        format!("\n\t  {replaced}")
    }
}

/// Format full bucket metadata (matching `_PrintBucketInfo` with `ListingStyle.LONG_LONG` in `gslib/commands/ls.py`).
pub fn format_bucket_info_long_long(url_str: &str, bucket: &Bucket) -> String {
    let storage_class = bucket.storage_class.as_deref().unwrap_or("None");
    let location_constraint = bucket.location.as_deref().unwrap_or("None");
    let versioning = match bucket.versioning.as_ref().and_then(|v| v.enabled) {
        Some(true) => "True",
        Some(false) => "False",
        None => "None",
    };
    let logging_config = if bucket.logging.is_some() {
        "Present"
    } else {
        "None"
    };
    let website_config = if bucket.website.is_some() {
        "Present"
    } else {
        "None"
    };
    let cors_config = if bucket.cors.as_ref().is_some_and(|c| !c.is_empty()) {
        "Present"
    } else {
        "None"
    };
    let lifecycle_config = if bucket.lifecycle.is_some() {
        "Present"
    } else {
        "None"
    };
    let requester_pays = match bucket.billing.as_ref().and_then(|b| b.requester_pays) {
        Some(true) => "True",
        Some(false) => "False",
        None => "None",
    };
    let labels = match &bucket.labels {
        Some(map) if !map.is_empty() => indent_multiline(
            &serde_json::to_string_pretty(map).unwrap_or_else(|_| "None".to_string()),
        ),
        _ => "None".to_string(),
    };
    let default_kms_key = bucket
        .encryption
        .as_ref()
        .and_then(|e| e.default_kms_key_name.as_deref())
        .unwrap_or("None");
    let acl = match &bucket.acl {
        Some(a) if !a.is_empty() => {
            indent_multiline(&serde_json::to_string_pretty(a).unwrap_or_else(|_| "[]".to_string()))
        }
        _ => "[]".to_string(),
    };
    let default_acl = match &bucket.default_object_acl {
        Some(a) if !a.is_empty() => {
            indent_multiline(&serde_json::to_string_pretty(a).unwrap_or_else(|_| "[]".to_string()))
        }
        _ => "[]".to_string(),
    };

    let mut out = String::new();
    out.push_str(&format!("{url_str} :\n"));
    out.push_str(&format!("\tStorage class:\t\t\t{storage_class}\n"));
    if let Some(ref lt) = bucket.location_type {
        out.push_str(&format!("\tLocation type:\t\t\t{lt}\n"));
    }
    out.push_str(&format!(
        "\tLocation constraint:\t\t{location_constraint}\n"
    ));
    if let Some(ref cpc) = bucket.custom_placement_config {
        if let Some(ref locs) = cpc.data_locations {
            let formatted = locs
                .iter()
                .map(|l| format!("'{l}'"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("\tPlacement locations:\t\t[{formatted}]\n"));
        }
    }
    out.push_str(&format!("\tVersioning enabled:\t\t{versioning}\n"));
    out.push_str(&format!("\tLogging configuration:\t\t{logging_config}\n"));
    out.push_str(&format!("\tWebsite configuration:\t\t{website_config}\n"));
    out.push_str(&format!("\tCORS configuration: \t\t{cors_config}\n"));
    out.push_str(&format!("\tLifecycle configuration:\t{lifecycle_config}\n"));
    out.push_str(&format!("\tRequester Pays enabled:\t\t{requester_pays}\n"));
    if bucket.retention_policy.is_some() {
        out.push_str("\tRetention Policy:\t\tPresent\n");
    }
    if let Some(debh) = bucket.default_event_based_hold {
        let s = if debh { "True" } else { "False" };
        out.push_str(&format!("\tDefault Event-Based Hold:\t{s}\n"));
    }
    out.push_str(&format!("\tLabels:\t\t\t\t{labels}\n"));
    out.push_str(&format!("\tDefault KMS key:\t\t{default_kms_key}\n"));
    if let Some(ref tc) = bucket.time_created {
        out.push_str(&format!(
            "\tTime created:\t\t\t{}\n",
            format_rfc2822_gmt(tc)
        ));
    }
    if let Some(ref upd) = bucket.updated {
        out.push_str(&format!(
            "\tTime updated:\t\t\t{}\n",
            format_rfc2822_gmt(upd)
        ));
    }
    if let Some(ref mg) = bucket.metageneration {
        out.push_str(&format!("\tMetageneration:\t\t\t{mg}\n"));
    }
    if let Some(ref iam) = bucket.iam_configuration {
        let bpo = iam
            .bucket_policy_only
            .as_ref()
            .and_then(|b| b.enabled)
            .or_else(|| {
                iam.uniform_bucket_level_access
                    .as_ref()
                    .and_then(|u| u.enabled)
            });
        if let Some(enabled) = bpo {
            let s = if enabled { "True" } else { "False" };
            out.push_str(&format!("\tBucket Policy Only enabled:\t{s}\n"));
        }
    }
    if let Some(ref ac) = bucket.autoclass {
        if ac.enabled == Some(true) {
            let date = ac
                .toggle_time
                .as_deref()
                .map(format_date_only)
                .unwrap_or_default();
            out.push_str(&format!("\tAutoclass:\t\t\tEnabled on {date}\n"));
        }
    }
    if let Some(ref iam) = bucket.iam_configuration {
        if let Some(ref pap) = iam.public_access_prevention {
            out.push_str(&format!("\tPublic access prevention:\t{pap}\n"));
        }
    }
    if let Some(ref rpo) = bucket.rpo {
        out.push_str(&format!("\tRPO:\t\t\t\t{rpo}\n"));
    }
    if let Some(pzs) = bucket.satisfies_pzs {
        let s = if pzs { "True" } else { "False" };
        out.push_str(&format!("\tSatisfies PZS:\t\t\t{s}\n"));
    }
    out.push_str(&format!("\tACL:\t\t\t\t{acl}\n"));
    out.push_str(&format!("\tDefault ACL:\t\t\t{default_acl}"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_human_readable() {
        assert_eq!(make_human_readable(0), "0 B");
        assert_eq!(make_human_readable(512), "512 B");
        assert_eq!(make_human_readable(1024), "1 KiB");
        assert_eq!(make_human_readable(60183), "58.77 KiB");
        assert_eq!(make_human_readable(6_190_979), "5.9 MiB");
    }

    #[test]
    fn test_make_metadata_line() {
        assert_eq!(
            make_metadata_line("Storage class", "STANDARD", 1),
            "    Storage class:          STANDARD"
        );
        assert_eq!(
            make_metadata_line("foo", "bar", 2),
            "        foo:                bar"
        );
    }

    #[test]
    fn test_timestamps() {
        assert_eq!(
            format_ls_timestamp(Some("2020-03-02T19:25:17.123Z")),
            "2020-03-02T19:25:17Z"
        );
        assert_eq!(
            format_rfc2822_gmt("2017-05-26T22:55:44.000Z"),
            "Fri, 26 May 2017 22:55:44 GMT"
        );
    }
}
