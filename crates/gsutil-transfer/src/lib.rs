//! Parallel transfer engine for `gsutil-rs`.
//!
//! Provides the core transfer implementations for `cp`, `mv`, `rsync`, `compose`,
//! and `rewrite`, backed by `gsutil_core::api::CloudApi` and Tokio async concurrency.

pub mod compose;
pub mod copy;
pub mod mv;
pub mod parallel;
pub mod posix;
pub mod rewrite;
pub mod rsync;
pub mod tracker;
pub mod ui;

#[cfg(test)]
pub(crate) mod mock_api;
