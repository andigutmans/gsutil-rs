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

use std::sync::atomic::{AtomicU8, Ordering};

static GLOBAL_DEBUG_LEVEL: AtomicU8 = AtomicU8::new(0);

/// Set the process-wide gsutil debug verbosity level (0=normal, 2=-d, 3=-D, 4=-DD).
pub fn set_debug_level(level: u8) {
    GLOBAL_DEBUG_LEVEL.store(level, Ordering::Relaxed);
}

/// Return the current process-wide gsutil debug verbosity level.
pub fn debug_level() -> u8 {
    GLOBAL_DEBUG_LEVEL.load(Ordering::Relaxed)
}
