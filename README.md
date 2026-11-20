# gsutil-rs

A high-performance, 100% CLI-compatible Rust rewrite of Google Cloud Storage's `gsutil` (targeting v5.38 parity).

## Architecture

This workspace is organized into modular crates:

- `crates/gsutil-core` — Error taxonomy, `.boto` configuration loader, `StorageUrl`, `CloudApi` trait & GCS JSON models, wildcard matching, and hardware-accelerated hashing (`CRC32C`, `MD5`).
- `crates/gsutil-auth` — Credential resolution chain (`.boto`, ADC, `gcloud`, GCE metadata, service account impersonation, HMAC).
- `crates/gsutil-gcs` — Async GCS JSON API v1 client (`reqwest` + `tokio`), resumable/multipart uploads, sliced downloads, retries, and exact HTTP error translation.
- `crates/gsutil-transfer` — Parallel transfer engine (`cp`, `mv`, `rsync`, composite uploads, sliced downloads).
- `crates/gsutil-cli` — CLI binary (`gsutil`) with exact global flags, command dispatch, deprecated aliases, and output formatting.
- `crates/gsutil-parity` — Differential compatibility test harness comparing `gsutil-rs` against Python `gsutil`.

## Building & Testing

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
