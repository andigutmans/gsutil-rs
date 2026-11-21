//! Customer-Supplied (CSEK) and Customer-Managed (CMEK) encryption key resolution
//! from `.boto` `[GSUtil] encryption_key` and `decryption_key1..100`.
//!
//! Mirrors `gslib/utils/encryption_helper.py` in Python gsutil v5.38.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};

use gsutil_core::api::EncryptionKey;
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result};

const MAX_DECRYPTION_KEYS: usize = 100;

/// Parse a raw key value from `.boto` (`encryption_key` or `decryption_keyN`) into
/// an [`EncryptionKey`] (`Cmek` if `projects/.../cryptoKeys/...`, else 32-byte base64 `Csek`).
pub fn parse_encryption_key(raw: &str) -> Result<EncryptionKey> {
    let trimmed = raw.trim();
    if trimmed.starts_with("projects/") && trimmed.contains("/cryptoKeys/") {
        return Ok(EncryptionKey::Cmek {
            kms_key_name: trimmed.to_string(),
        });
    }
    let decoded = BASE64.decode(trimmed).map_err(|_| {
        GsutilError::command(
            "Invalid encryption_key: expected a valid base64-encoded 256-bit AES key \
             or Cloud KMS key resource name.",
        )
    })?;
    if decoded.len() != 32 {
        return Err(GsutilError::command(format!(
            "Invalid CSEK key length: expected 32 bytes (256 bits), got {} bytes.",
            decoded.len()
        )));
    }
    let sha = Sha256::digest(&decoded);
    let key_sha256_b64 = BASE64.encode(sha);
    Ok(EncryptionKey::Csek {
        key_b64: trimmed.to_string(),
        key_sha256_b64,
    })
}

/// Read `[GSUtil] encryption_key` from `.boto` if configured.
pub fn configured_encryption_key(config: &BotoConfig) -> Result<Option<EncryptionKey>> {
    match config.get("GSUtil", "encryption_key") {
        Some(raw) if !raw.trim().is_empty() => Ok(Some(parse_encryption_key(raw)?)),
        _ => Ok(None),
    }
}

/// Collect all configured CSEK keys (`encryption_key` + `decryption_key1..100`).
pub fn all_csek_keys(config: &BotoConfig) -> Result<Vec<EncryptionKey>> {
    let mut keys = Vec::new();
    if let Some(k @ EncryptionKey::Csek { .. }) = configured_encryption_key(config)? {
        keys.push(k);
    }
    for i in 1..=MAX_DECRYPTION_KEYS {
        let key_name = format!("decryption_key{i}");
        if let Some(raw) = config.get("GSUtil", &key_name) {
            if !raw.trim().is_empty() {
                let parsed = parse_encryption_key(raw)?;
                if matches!(parsed, EncryptionKey::Csek { .. }) {
                    keys.push(parsed);
                }
            }
        }
    }
    Ok(keys)
}

/// Find the CSEK matching a specific object's `customerEncryption.keySha256`.
pub fn find_matching_csek(
    config: &BotoConfig,
    expected_sha256: &str,
) -> Result<Option<EncryptionKey>> {
    for key in all_csek_keys(config)? {
        if let EncryptionKey::Csek {
            ref key_sha256_b64, ..
        } = key
        {
            if key_sha256_b64 == expected_sha256 {
                return Ok(Some(key));
            }
        }
    }
    Ok(None)
}

/// Return the primary configured CSEK decryption key (first of `encryption_key` or `decryption_key1..100`).
pub fn primary_decryption_key(config: &BotoConfig) -> Result<Option<EncryptionKey>> {
    Ok(all_csek_keys(config)?.into_iter().next())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cmek_and_csek() {
        let cmek =
            parse_encryption_key("projects/p/locations/us/keyRings/kr/cryptoKeys/k").unwrap();
        assert!(matches!(cmek, EncryptionKey::Cmek { .. }));

        let raw_key = BASE64.encode([0x42u8; 32]);
        let csek = parse_encryption_key(&raw_key).unwrap();
        match csek {
            EncryptionKey::Csek {
                key_b64,
                key_sha256_b64,
            } => {
                assert_eq!(key_b64, raw_key);
                assert!(!key_sha256_b64.is_empty());
            }
            _ => panic!("expected Csek"),
        }

        // Wrong byte length should error.
        let short_key = BASE64.encode([0x42u8; 16]);
        assert!(parse_encryption_key(&short_key).is_err());
    }

    #[test]
    fn test_find_matching_csek_from_boto() {
        let mut cfg = BotoConfig::new();
        let k1 = BASE64.encode([1u8; 32]);
        let k2 = BASE64.encode([2u8; 32]);
        cfg.set("GSUtil", "encryption_key", &k1);
        cfg.set("GSUtil", "decryption_key1", &k2);

        let expected_sha = BASE64.encode(Sha256::digest([2u8; 32]));
        let found = find_matching_csek(&cfg, &expected_sha).unwrap().unwrap();
        match found {
            EncryptionKey::Csek { key_b64, .. } => assert_eq!(key_b64, k2),
            _ => panic!("expected Csek"),
        }
    }
}
