//! Differential compatibility & integration test harness for `gsutil-rs`.
//!
//! Invokes both the reference Python `/usr/bin/gsutil` (v5.38) and the Rust
//! `gsutil` binary on identical commands and compares:
//! - Exit codes (exact match)
//! - Stdout (exact, normalized, or structured substring matching)
//! - Stderr error prefixes and messages
//! - Side effects (local files, mock GCS state, or live GCS bucket state)

pub mod cases;
pub mod live_cases;
pub mod mock_cases;
pub mod mock_gcs;
pub mod normalize;
pub mod runner;
pub mod scorecard;
pub mod stage1_gates;
