//! Process shutdown & cleanup hook registry for `SIGINT`/`SIGTERM` handling.
//!
//! Allows long-lived resources (such as a spawned `ecp_http_proxy` child process
//! or non-resumable temp files) to register deterministic cleanup hooks that run
//! immediately on signal interruption, while automatically unregistering via
//! [`CleanupGuard`] on normal drop.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

type CleanupFn = Box<dyn FnOnce() + Send + 'static>;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static NEXT_HOOK_ID: AtomicU64 = AtomicU64::new(1);

fn registry() -> &'static Mutex<BTreeMap<u64, CleanupFn>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<u64, CleanupFn>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// RAII guard returned by [`register_cleanup`]. Unregisters the hook when dropped
/// normally (if [`run_all_cleanups`] has not already drained it).
#[derive(Debug)]
pub struct CleanupGuard {
    id: u64,
}

impl CleanupGuard {
    /// Explicitly disarm and unregister this cleanup hook without running it.
    pub fn disarm(self) {
        // Drop handles unregistration.
        drop(self);
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = registry().lock() {
            map.remove(&self.id);
        }
    }
}

/// Register a cleanup hook to be executed if [`run_all_cleanups`] is called
/// (e.g., on `SIGINT` or `SIGTERM`).
pub fn register_cleanup<F>(f: F) -> CleanupGuard
where
    F: FnOnce() + Send + 'static,
{
    let id = NEXT_HOOK_ID.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut map) = registry().lock() {
        map.insert(id, Box::new(f));
    }
    CleanupGuard { id }
}

/// Mark shutdown as requested.
pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Returns `true` if [`request_shutdown`] or [`run_all_cleanups`] has been triggered.
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Mark shutdown as requested and execute all registered cleanup hooks in LIFO order.
/// Safe to call multiple times (subsequent calls are no-ops once hooks are drained).
pub fn run_all_cleanups() {
    request_shutdown();
    let hooks: Vec<CleanupFn> = match registry().lock() {
        Ok(mut map) => {
            let drained: Vec<(u64, CleanupFn)> = std::mem::take(&mut *map).into_iter().collect();
            drained.into_iter().rev().map(|(_, f)| f).collect()
        }
        Err(poisoned) => {
            let mut map = poisoned.into_inner();
            let drained: Vec<(u64, CleanupFn)> = std::mem::take(&mut *map).into_iter().collect();
            drained.into_iter().rev().map(|(_, f)| f).collect()
        }
    };
    for hook in hooks {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_cleanup_guard_unregisters_on_drop() {
        let ran = Arc::new(AtomicBool::new(false));
        let ran_clone = Arc::clone(&ran);
        {
            let _guard = register_cleanup(move || {
                ran_clone.store(true, Ordering::SeqCst);
            });
        }
        // Guard dropped before run_all_cleanups; hook must not run.
        run_all_cleanups();
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[test]
    fn test_run_all_cleanups_executes_lifo() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let o1 = Arc::clone(&order);
        let o2 = Arc::clone(&order);
        let _g1 = register_cleanup(move || o1.lock().unwrap().push(1));
        let _g2 = register_cleanup(move || o2.lock().unwrap().push(2));

        run_all_cleanups();
        assert!(is_shutdown_requested());
        assert_eq!(*order.lock().unwrap(), vec![2, 1]);

        // Second call is a no-op.
        run_all_cleanups();
        assert_eq!(*order.lock().unwrap(), vec![2, 1]);
    }
}
