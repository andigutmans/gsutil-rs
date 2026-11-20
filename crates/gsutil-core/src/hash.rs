//! Hardware-accelerated CRC32C, MD5, base64/hex helpers, and `concat_crc32c`.
//!
//! Matches `gslib/utils/hashing_helper.py` in Python gsutil v5.38.

use std::io::Read;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use md5::{Digest, Md5};

use crate::error::{GsutilError, Result};

/// Castagnoli polynomial (x^32 + ... + 1) used by CRC32C.
const CASTAGNOLI_POLY: u64 = 4_812_730_177;
const DEGREE: usize = 32;

/// Table storing polynomial values of `x^(2^k) mod CASTAGNOLI_POLY` for `k < 31`.
const X_POW_2K_TABLE: [u64; 31] = [
    2, 4, 16, 256, 65536, 517762881, 984302966, 408362264, 1503875210, 2862076957, 3884826397,
    1324787473, 621200174, 1758783527, 1416537776, 1180494764, 648569364, 2521473789, 994858823,
    1728245375, 3498467999, 4059169852, 3345064394, 2828422810, 2429203150, 3336788029, 860151998,
    2102628683, 1033187991, 4243778976, 1123580069,
];

/// Streaming hardware-accelerated CRC32C hasher.
#[derive(Debug, Clone, Default)]
pub struct Crc32cHasher {
    value: u32,
}

impl Crc32cHasher {
    pub fn new() -> Self {
        Self { value: 0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.value = crc32c::crc32c_append(self.value, data);
    }

    pub fn finalize(&self) -> u32 {
        self.value
    }

    /// Big-endian 4-byte digest matching `crcmod` / GCS `crc32c` wire format.
    pub fn finalize_bytes(&self) -> [u8; 4] {
        self.value.to_be_bytes()
    }

    /// Lowercase hex digest (8 chars).
    pub fn finalize_hex(&self) -> String {
        hex::encode(self.finalize_bytes())
    }

    /// Base64-encoded digest (matching GCS `crc32c` JSON field and `gsutil hash`).
    pub fn finalize_base64(&self) -> String {
        BASE64.encode(self.finalize_bytes())
    }
}

/// Streaming MD5 hasher.
#[derive(Debug, Clone, Default)]
pub struct Md5Hasher {
    inner: Md5,
}

impl Md5Hasher {
    pub fn new() -> Self {
        Self { inner: Md5::new() }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(&self) -> [u8; 16] {
        let digest = self.inner.clone().finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest);
        out
    }

    /// Lowercase hex digest (32 chars).
    pub fn finalize_hex(&self) -> String {
        hex::encode(self.finalize())
    }

    /// Base64-encoded digest (matching GCS `md5Hash` JSON field and `gsutil hash`).
    pub fn finalize_base64(&self) -> String {
        BASE64.encode(self.finalize())
    }
}

/// Combined CRC32C + MD5 digest result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHashes {
    pub crc32c: Option<u32>,
    pub md5: Option<[u8; 16]>,
}

impl FileHashes {
    pub fn crc32c_base64(&self) -> Option<String> {
        self.crc32c.map(|v| BASE64.encode(v.to_be_bytes()))
    }

    pub fn crc32c_hex(&self) -> Option<String> {
        self.crc32c.map(|v| hex::encode(v.to_be_bytes()))
    }

    pub fn md5_base64(&self) -> Option<String> {
        self.md5.map(|b| BASE64.encode(b))
    }

    pub fn md5_hex(&self) -> Option<String> {
        self.md5.map(hex::encode)
    }
}

/// Compute CRC32C and/or MD5 of a reader in a single streaming pass.
pub fn hash_reader<R: Read>(
    reader: &mut R,
    compute_crc32c: bool,
    compute_md5: bool,
) -> Result<FileHashes> {
    let mut crc = compute_crc32c.then(Crc32cHasher::new);
    let mut md5 = compute_md5.then(Md5Hasher::new);
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        if let Some(ref mut c) = crc {
            c.update(chunk);
        }
        if let Some(ref mut m) = md5 {
            m.update(chunk);
        }
    }

    Ok(FileHashes {
        crc32c: crc.map(|c| c.finalize()),
        md5: md5.map(|m| m.finalize()),
    })
}

/// Compute CRC32C of a byte slice.
pub fn crc32c_bytes(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
}

/// Compute base64-encoded CRC32C of a byte slice.
pub fn crc32c_base64(data: &[u8]) -> String {
    BASE64.encode(crc32c_bytes(data).to_be_bytes())
}

/// Compute MD5 of a byte slice.
pub fn md5_bytes(data: &[u8]) -> [u8; 16] {
    let mut h = Md5Hasher::new();
    h.update(data);
    h.finalize()
}

/// Compute base64-encoded MD5 of a byte slice.
pub fn md5_base64(data: &[u8]) -> String {
    BASE64.encode(md5_bytes(data))
}

/// Convert a hex-encoded hash string to base64 (matches `Base64EncodeHash`).
pub fn base64_encode_hex_hash(hex_digest: &str) -> Result<String> {
    let bytes = hex::decode(hex_digest.trim())
        .map_err(|e| GsutilError::argument(format!("Invalid hex digest: {e}")))?;
    Ok(BASE64.encode(bytes))
}

/// Convert a base64-encoded hash string to lowercase hex (matches `Base64ToHexHash`).
pub fn base64_to_hex_hash(base64_hash: &str) -> Result<String> {
    let cleaned = base64_hash.trim_matches(|c| c == '\n' || c == '\r' || c == '"' || c == '\'');
    let bytes = BASE64
        .decode(cleaned)
        .map_err(|e| GsutilError::argument(format!("Invalid base64 hash: {e}")))?;
    Ok(hex::encode(bytes))
}

/// Decode a base64-encoded 4-byte CRC32C string to `u32`.
pub fn crc32c_from_base64(b64: &str) -> Result<u32> {
    let cleaned = b64.trim_matches(|c| c == '\n' || c == '\r' || c == '"' || c == '\'');
    let bytes = BASE64
        .decode(cleaned)
        .map_err(|e| GsutilError::argument(format!("Invalid base64 crc32c: {e}")))?;
    if bytes.len() != 4 {
        return Err(GsutilError::argument(format!(
            "Invalid crc32c byte length: expected 4, got {}",
            bytes.len()
        )));
    }
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Encode a `u32` CRC32C value to base64 (big-endian 4 bytes).
pub fn crc32c_to_base64(crc: u32) -> String {
    BASE64.encode(crc.to_be_bytes())
}

/// Computes `CRC32C(concat(A, B))` given `crc(A)`, `crc(B)`, and `len(B)`.
///
/// Direct port of `ConcatCrc32c` in `gslib/utils/hashing_helper.py`.
pub fn concat_crc32c(crc_a: u32, crc_b: u32, num_bytes_in_b: u64) -> u32 {
    if num_bytes_in_b == 0 {
        return crc_a;
    }
    extend_by_zeros(crc_a, num_bytes_in_b.saturating_mul(8)) ^ crc_b
}

fn crc_multiply(mut p: u64, mut q: u64) -> u64 {
    let mut result = 0u64;
    let top_bit = 1u64 << DEGREE;
    for _ in 0..DEGREE {
        if (p & 1) != 0 {
            result ^= q;
        }
        q <<= 1;
        if (q & top_bit) != 0 {
            q ^= CASTAGNOLI_POLY;
        }
        p >>= 1;
    }
    result
}

fn extend_by_zeros(crc: u32, mut num_bits: u64) -> u32 {
    let mut poly = u64::from(crc.reverse_bits());
    let mut i = 0usize;
    while num_bits != 0 {
        if (num_bits & 1) != 0 {
            poly = crc_multiply(poly, X_POW_2K_TABLE[i % X_POW_2K_TABLE.len()]);
        }
        i += 1;
        num_bits >>= 1;
    }
    (poly as u32).reverse_bits()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_crc32c_known_vectors() {
        // Standard RFC 3720 / GCS test vector: "123456789" -> 0xe3069283
        assert_eq!(crc32c_bytes(b"123456789"), 0xe306_9283);
        // Empty input -> 0x00000000 -> "AAAAAA=="
        assert_eq!(crc32c_base64(b""), "AAAAAA==");
        // "hello" -> 0x9a71bb4c -> base64 "mnG7TA=="
        assert_eq!(crc32c_bytes(b"hello"), 0x9a71_bb4c);
        assert_eq!(crc32c_base64(b"hello"), "mnG7TA==");
    }

    #[test]
    fn test_md5_known_vectors() {
        let mut h = Md5Hasher::new();
        h.update(b"hello");
        assert_eq!(h.finalize_hex(), "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(h.finalize_base64(), "XUFAKrxLKna5cZ2REBfFkg==");
    }

    #[test]
    fn test_concat_crc32c() {
        let a = b"The quick brown fox ";
        let b = b"jumps over the lazy dog!";
        let mut ab = Vec::new();
        ab.extend_from_slice(a);
        ab.extend_from_slice(b);

        let crc_a = crc32c_bytes(a);
        let crc_b = crc32c_bytes(b);
        let crc_ab = crc32c_bytes(&ab);

        assert_eq!(concat_crc32c(crc_a, crc_b, b.len() as u64), crc_ab);
        assert_eq!(concat_crc32c(crc_a, 0, 0), crc_a);
    }

    #[test]
    fn test_base64_hex_roundtrip() {
        let b64 = "XUFAKrxLKna5cZ2REBfFkg==";
        let hex_str = base64_to_hex_hash(b64).unwrap();
        assert_eq!(hex_str, "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(base64_encode_hex_hash(&hex_str).unwrap(), b64);

        let crc = crc32c_from_base64("mnG7TA==").unwrap();
        assert_eq!(crc, 0x9a71_bb4c);
        assert_eq!(crc32c_to_base64(crc), "mnG7TA==");
    }

    #[test]
    fn test_hash_reader_streaming() {
        let data = b"hello world from gsutil-rs";
        let mut cursor = Cursor::new(data);
        let hashes = hash_reader(&mut cursor, true, true).unwrap();
        assert_eq!(hashes.crc32c, Some(crc32c_bytes(data)));
        assert_eq!(hashes.md5, Some(md5_bytes(data)));
    }
}
