//! Tokio-based async concurrency pool for parallel transfer operations.
//!
//! Respects `-m` (`parallel_operations`), `parallel_process_count * parallel_thread_count`,
//! and aggregates `failure_count` so partial failures return exit code 1.

use std::future::Future;
use std::sync::Arc;

use futures::stream::{self, StreamExt};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result};
use tokio::sync::Semaphore;

/// Concurrency and error-handling settings for batch transfer operations.
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Whether `-m` (multi-threaded/multi-processing) was requested.
    pub parallel_operations: bool,
    /// `GSUtil:parallel_process_count` (default 1).
    pub process_count: usize,
    /// `GSUtil:parallel_thread_count` (default 24).
    pub thread_count: usize,
    /// Continue processing remaining items when an item fails (`-c`, `-f`, or `-C`).
    pub continue_on_error: bool,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            parallel_operations: false,
            process_count: 1,
            thread_count: 24,
            continue_on_error: false,
        }
    }
}

impl ParallelConfig {
    /// Construct from `.boto` config and CLI flags.
    pub fn from_boto(
        config: &BotoConfig,
        parallel_operations: bool,
        continue_on_error: bool,
    ) -> Self {
        Self {
            parallel_operations,
            process_count: config.parallel_process_count().max(1),
            thread_count: config.parallel_thread_count().max(1),
            continue_on_error,
        }
    }

    /// Maximum number of concurrent in-flight tasks.
    pub fn concurrency(&self) -> usize {
        if self.parallel_operations {
            self.process_count.saturating_mul(self.thread_count).max(1)
        } else {
            1
        }
    }

    /// Concurrency for internal sub-operations (e.g., parallel composite upload
    /// components or sliced object download ranges), which run concurrently
    /// even without `-m`, capped by `process_count * thread_count`.
    pub fn sub_operation_concurrency(&self) -> usize {
        self.process_count.saturating_mul(self.thread_count).max(1)
    }
}

/// Summary of a batch transfer execution.
#[derive(Debug, Default)]
pub struct BatchSummary {
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub errors: Vec<GsutilError>,
}

impl BatchSummary {
    /// Returns `Ok(())` if `failed == 0`, otherwise returns a `GsutilError`
    /// with exit code 1 matching gsutil's partial-failure behavior.
    pub fn into_result(mut self) -> Result<()> {
        if self.failed == 0 {
            return Ok(());
        }
        if self.errors.len() == 1 && self.succeeded == 0 {
            return Err(self.errors.remove(0));
        }
        Err(GsutilError::command(format!(
            "{} file(s)/object(s) could not be transferred.",
            self.failed
        )))
    }
}

/// Execute `f` across `items` respecting `config.concurrency()` and
/// `config.continue_on_error`, collecting results and failures.
pub async fn run_parallel_with_results<T, R, F, Fut>(
    items: Vec<T>,
    config: &ParallelConfig,
    f: F,
) -> (Vec<R>, BatchSummary)
where
    T: Send + 'static,
    R: Send + 'static,
    F: Fn(T) -> Fut + Send + Sync,
    Fut: Future<Output = Result<R>> + Send,
{
    let mut results = Vec::new();
    let mut summary = BatchSummary::default();

    let concurrency = config.concurrency();
    if concurrency <= 1 {
        for item in items {
            match f(item).await {
                Ok(val) => {
                    summary.succeeded += 1;
                    results.push(val);
                }
                Err(err) => {
                    summary.failed += 1;
                    summary.errors.push(err);
                    if !config.continue_on_error {
                        break;
                    }
                }
            }
        }
        return (results, summary);
    }

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let f_ref = &f;

    let outcomes: Vec<Result<R>> = stream::iter(items)
        .map(|item| {
            let sem = Arc::clone(&semaphore);
            async move {
                let _permit = sem.acquire_owned().await.map_err(|e| {
                    GsutilError::command(format!("Parallel pool closed unexpectedly: {e}"))
                })?;
                f_ref(item).await
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    for outcome in outcomes {
        match outcome {
            Ok(val) => {
                summary.succeeded += 1;
                results.push(val);
            }
            Err(err) => {
                summary.failed += 1;
                summary.errors.push(err);
            }
        }
    }

    (results, summary)
}

/// Execute `f` across `items` when only success/failure summary is needed.
pub async fn run_parallel<T, F, Fut>(items: Vec<T>, config: &ParallelConfig, f: F) -> BatchSummary
where
    T: Send + 'static,
    F: Fn(T) -> Fut + Send + Sync,
    Fut: Future<Output = Result<()>> + Send,
{
    let (_, summary) = run_parallel_with_results(items, config, f).await;
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_concurrency_calculation() {
        let mut cfg = BotoConfig::new();
        cfg.set("GSUtil", "parallel_process_count", "2");
        cfg.set("GSUtil", "parallel_thread_count", "8");

        let serial = ParallelConfig::from_boto(&cfg, false, false);
        assert_eq!(serial.concurrency(), 1);
        assert_eq!(serial.sub_operation_concurrency(), 16);

        let par = ParallelConfig::from_boto(&cfg, true, false);
        assert_eq!(par.concurrency(), 16);
    }

    #[tokio::test]
    async fn test_serial_fail_fast_vs_continue() {
        let cfg_stop = ParallelConfig {
            parallel_operations: false,
            process_count: 1,
            thread_count: 4,
            continue_on_error: false,
        };
        let executed = Arc::new(AtomicUsize::new(0));
        let ex_clone = Arc::clone(&executed);
        let summary = run_parallel(vec![1, 2, 3, 4], &cfg_stop, move |n| {
            let ex = Arc::clone(&ex_clone);
            async move {
                ex.fetch_add(1, Ordering::SeqCst);
                if n == 2 {
                    Err(GsutilError::command("boom"))
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert_eq!(executed.load(Ordering::SeqCst), 2);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.into_result().unwrap_err().exit_code(), 1);

        let cfg_cont = ParallelConfig {
            continue_on_error: true,
            ..cfg_stop
        };
        let summary2 = run_parallel(vec![1, 2, 3, 4], &cfg_cont, |n| async move {
            if n % 2 == 0 {
                Err(GsutilError::command("even fail"))
            } else {
                Ok(())
            }
        })
        .await;
        assert_eq!(summary2.succeeded, 2);
        assert_eq!(summary2.failed, 2);
        let err = summary2.into_result().unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("2 file(s)/object(s)"));
    }

    #[tokio::test]
    async fn test_parallel_pool_aggregates_failures() {
        let cfg = ParallelConfig {
            parallel_operations: true,
            process_count: 2,
            thread_count: 4,
            continue_on_error: false,
        };
        let (results, summary) =
            run_parallel_with_results((0..20).collect(), &cfg, |n| async move {
                if n == 5 || n == 15 {
                    Err(GsutilError::command(format!("fail {n}")))
                } else {
                    Ok(n * 2)
                }
            })
            .await;
        assert_eq!(results.len(), 18);
        assert_eq!(summary.succeeded, 18);
        assert_eq!(summary.failed, 2);
        assert_eq!(summary.into_result().unwrap_err().exit_code(), 1);
    }
}
