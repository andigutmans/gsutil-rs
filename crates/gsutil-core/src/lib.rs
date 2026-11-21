//! Core primitives for `gsutil-rs`: error taxonomy, `.boto` configuration,
//! `StorageUrl` parsing, async `CloudApi` trait & GCS JSON v1 models,
//! wildcard matching, and hardware-accelerated hashing.

pub mod api;
pub mod config;
pub mod error;
pub mod hash;
pub mod signals;
pub mod url;
pub mod wildcard;
