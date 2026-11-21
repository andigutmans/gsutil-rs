# gsutil-rs

A high-performance Rust rewrite of Google Cloud Storage's [`gsutil`](https://github.com/GoogleCloudPlatform/gsutil) CLI, targeting drop-in CLI, error-code, and protocol compatibility with **gsutil v5.38**.

> **Status:** Active pre-production development (Linux `x86_64` verified; macOS & Windows support planned).

---

## Highlights

- **Comprehensive Command Surface:** All **41 `gsutil` commands** plus all **15 legacy `OLD_ALIAS_MAP` aliases** (`getacl`, `setacl`, `chacl`, `getcors`, `setcors`, `getversioning`, `setversioning`, `enablelogging`, `disablelogging`, `getwebcfg`, `setwebcfg`, etc.), POSIX `getopt` global flags (`-m`, `-q`, `-h`, `-o`, `-d`/`-D`/`-DD`, `-u`, `-i`, `-v`, `--trace-token`, `--perf-trace-token`), `.boto` INI config + `-o Section:Key=Val` overrides, and `Did you mean this?` fuzzy command suggestions.
- **Exact Error & Exit-Code Parity:** Matches `gsutil`'s exit codes (`0` on success or `EPIPE`, `1` on errors / `-m` partial failures), `CommandException:` / `ServiceException:` / `AccessDeniedException:` / `NotFoundException:` / `PreconditionException:` formatting, and secret redaction under `-D`.
- **Constant-Memory Streaming I/O:** Bounded-memory streaming uploads (`8 MiB` chunked disk reads), streaming downloads directly to `_.gstmp` with on-the-fly hardware-accelerated **CRC32C** (`crc32c`) / **MD5** / **gzip** (`-z`/`-Z` storage & `-j`/`-J` transport), bounded `256 KiB` duplex daisy-chain copies (`-D`), and streaming `cat`. Uploading/downloading **200 MiB** objects uses **< 28 MiB peak RSS**.
- **Real Cross-Process Resumable Recovery:** Persists real GCS resumable session URIs under `~/.gsutil/tracker-files/` and probes `Content-Range: bytes */<total>` → `308 Range` on restart to resume from the exact committed byte offset.
- **Full GCP Integration:** GCS JSON API v1, GCS XML & S3 SigV4 (`XmlApiClient` + `CloudApiDelegator`), Cloud KMS / CMEK & CSEK encryption, Cloud Pub/Sub notifications, V2/V4 `signurl`, HMAC keys, SOCKS4/5 proxies, Enterprise Certificate Proxy (mTLS/ECP), interactive TTY progress (`UIController`), and `SIGINT`/`SIGTERM` cleanup.

---

## Workspace Architecture

| Crate | Responsibility |
| --- | --- |
| `crates/gsutil-core` | Error taxonomy (`GsutilError`, `ServiceError`), `.boto` config & `-o` overrides, `StorageUrl`, wildcard matcher, async `CloudApi`/`KmsApi`/`PubsubApi` traits, GCS JSON v1 models with explicit-`null` `PATCH` tombstones, hardware CRC32C/MD5, and `SIGINT`/`SIGTERM` cleanup registry. |
| `crates/gsutil-auth` | Credential resolution chain (`.boto` OAuth2, SA JSON, `.p12`, HMAC, ADC, `gcloud` with `0600` disk token cache, GCE metadata, `-i` impersonation, `NoOpCredentials`). |
| `crates/gsutil-gcs` | Async GCS JSON API v1 client (`reqwest` + `tokio`), streaming resumable/multipart uploads & downloads, retries, exact `_TranslateApitoolsException` error mapping, `XmlApiClient` (GCS XML & S3 SigV4), `CloudApiDelegator`, `EcpProxy`, plus `KmsClient`, `PubsubClient`, and `IamCredentialsClient`. |
| `crates/gsutil-transfer` | Parallel async transfer engine (`cp`, `mv`, `rsync` external merge-sort, `compose`, `rewrite`), parallel composite uploads, sliced downloads, tracker files, POSIX metadata (`-P`), symlink handling (`-e`), and TTY `UIController`. |
| `crates/gsutil-admin` | All 21 bucket-config, security, and messaging commands (`acl`, `defacl`, `iam`, `kms`, `signurl`, `hmac`, `notification`, `retention`, `versioning`, `cors`, `lifecycle`, `logging`, `web`, `label`, `requesterpays`, `defstorageclass`, `ubla`, `bucketpolicyonly`, `pap`, `rpo`, `autoclass`). |
| `crates/gsutil-cli` | Main `gsutil` binary, POSIX global option parser, command dispatch, `help`/`addlhelp`, `ls`, `stat`, `du`, `cat`, `rm`, `mb`, `rb`, `hash`, `setmeta`, `version`, `config`, `perfdiag`, `update`, and `test`. |
| `crates/gsutil-parity` | Differential compatibility harness comparing Rust `gsutil` against Python `gsutil` v5.38 across offline, 2-tier CA TLS mock GCS, live GCS, and Stage 1 production gates. |
| `crates/gsutil-bench` | `wait4`-based benchmark suite measuring latency (min/median/p95), throughput (MiB/s), and exact child peak RSS (`ru_maxrss`). |
| `scripts/run_upstream_gsutil_tests.py` | Black-box runner executing unmodified official upstream Python `gslib/tests/test_*.py` integration suites against `target/release/gsutil` (supports `--backend mock` and `--backend live`). |

---

## Performance (`target/release/gsutil` vs. Python `gsutil` v5.38)

Measured on Linux `x86_64` via `gsutil-bench --suite all --iterations 3` and `gsutil-parity --mode stage1`:

| Category | Workload | Python Median | Rust Median | Speedup | Python RSS | Rust RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Cold start | `version` | 2,254.7 ms | 5.4 ms | **419.4×** | 74.9 MiB | 5.8 MiB |
| Cold start | `help` | 2,045.3 ms | 5.2 ms | **392.7×** | 74.1 MiB | 5.7 MiB |
| Hashing | `hash` (10 MiB) | 2,087.1 ms | 34.1 ms | **61.2×** | 73.9 MiB | 13.1 MiB |
| Local | `cp` (10 MiB) | 2,158.9 ms | 15.6 ms | **138.7×** | 74.2 MiB | 13.1 MiB |
| Local | `rsync -r -d` (50×64 KiB) | 2,596.1 ms | 8.2 ms | **315.6×** | 73.9 MiB | 13.2 MiB |
| Live GCS | `ls` | 5,450.0 ms | 126.2 ms | **43.2×** | 93.0 MiB | 13.5 MiB |
| Live GCS | `cp` upload (5 MiB) | 5,534.2 ms | 342.0 ms | **16.2×** | 124.2 MiB | 18.9 MiB |
| Live GCS | `cp` download (5 MiB) | 4,953.1 ms | 172.8 ms | **28.7×** | 94.9 MiB | 21.0 MiB |
| Live GCS | `-m cp` upload (10×64 KiB) | 11,529.7 ms | 534.7 ms | **21.6×** | 94.3 MiB | 13.5 MiB |
| Live GCS | `-m cp` download (10×64 KiB) | 12,289.2 ms | 291.7 ms | **42.1×** | 94.3 MiB | 13.5 MiB |
| Live GCS (200 MiB) | Streaming upload / download | — | 3.11 s / 1.00 s | — | — | **27.9 / 18.0 MiB** |

---

## Verification & Compatibility Status

- **Unit & Integration Tests:** `cargo test --workspace` — **145/145 passing** (`cargo fmt` & `cargo clippy -D warnings` clean).
- **Differential Parity (`gsutil-parity`):**
  - `--mode offline` vs. Python `gsutil` v5.38: **63/63 (100.0%)**
  - `--mode mock` vs. Python `gsutil` v5.38 over 2-tier CA TLS: **64/64 (100.0%)**
  - `--mode live` against real GCS + Cloud KMS + Pub/Sub: **100%** across multi-topology buckets (UBLA, versioned, dual-region, Requester Pays, retention, KMS/CMEK, Pub/Sub)
  - `--mode stage1` production gates: **5/5 (100.0%)** (200 MiB `< 64 MiB` RSS upload/download, cross-process `308` crash-resume, live `_.gstmp` recovery, `SIGINT` cleanup)
- **Official Upstream Python `gslib/tests/` Black-Box Gate (`scripts/run_upstream_gsutil_tests.py`):**
  - **Live GCP (`--backend live`, 25 modules):** **284/297 (95.6%)** passing outside org-policy UBLA blocks, with **16 modules at 100.0% live pass** (including `test_retention`, `test_cors`, `test_setmeta`, `test_compose` with live Cloud KMS/CMEK, `test_lifecycle`, `test_web`, `test_pap`, `test_label`, `test_versioning`, `test_cat`, `test_rb`, `test_autoclass`, `test_defstorageclass`, `test_rpo`, `test_hash`, `test_notification`).
  - **Hermetic TLS Mock (`--backend mock`, 39 modules):** **615/774 (79.5%)** passing, **19 modules at 100.0%**.

### Known Limitations / Roadmap
- Remaining upstream edge cases in `test_cp` (multi-source naming edge cases; Python-internal `--testcallbackfile` pickle tests do not apply), `test_rsync`, and `test_Doption`.
- Live testing against a non-org-restricted GCP project (non-UBLA fine-grained ACLs, HMAC key CRUD, SA key `signurl` HTTP `GET`/`PUT`, `-i` impersonation) and real AWS S3.
- Cross-platform support (macOS & Windows), `_ARGCOMPLETE` shell tab completion, standalone interactive OAuth `gsutil config`, and `cargo audit`/`cargo deny`.

---

## Building & Running

Requires Rust **1.87+**.

```bash
# Build release binary
cargo build --release -p gsutil-cli
./target/release/gsutil version -l

# Run formatting, clippy, and unit/integration tests
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### Running Parity, Upstream Tests & Benchmarks

```bash
# Offline & TLS mock differential parity (requires Python gsutil installed)
cargo run -p gsutil-parity -- --mode offline
cargo run -p gsutil-parity -- --mode mock

# Live GCS differential parity & Stage 1 200 MiB streaming gates
GSUTIL_TEST_PROJECT=<your-project> GSUTIL_TEST_BUCKET=gs://<your-bucket> \
  cargo run -p gsutil-parity -- --mode live
GSUTIL_TEST_PROJECT=<your-project> GSUTIL_TEST_BUCKET=gs://<your-bucket> \
  cargo run -p gsutil-parity -- --mode stage1 --rust-bin target/release/gsutil

# Official upstream Python gslib/tests/ black-box runner
./scripts/run_upstream_gsutil_tests.py --backend mock
./scripts/run_upstream_gsutil_tests.py --backend live --project <your-project>

# Benchmarks vs. Python gsutil
cargo run --release -p gsutil-bench -- --suite all --rust-bin target/release/gsutil
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE).
