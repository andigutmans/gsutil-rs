//! Exponential backoff retry policy matching `gslib/utils/retry_util.py`
//! and `apitools.base.py.util.CalculateWaitForRetry`.

use std::future::Future;
use std::time::{Duration, Instant};

use gsutil_core::config::BotoConfig;
use tracing::{debug, info};

/// Warn if cumulative retry wait exceeds 60 seconds (matches `LONG_RETRY_WARN_SEC`).
pub const LONG_RETRY_WARN_SEC: u64 = 60;

/// Retry configuration derived from `BotoConfig`.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub max_retry_delay_secs: u64,
    /// Base delay unit (1 second in production, configurable to 0ms in tests).
    pub base_delay: Duration,
}

impl RetryPolicy {
    pub fn from_config(config: &BotoConfig) -> Self {
        Self {
            max_retries: config.num_retries(),
            max_retry_delay_secs: config.max_retry_delay(),
            base_delay: Duration::from_secs(1),
        }
    }

    /// Fast retry policy for unit/mock tests (minimal sleep).
    pub fn fast_for_tests(max_retries: u32) -> Self {
        Self {
            max_retries,
            max_retry_delay_secs: 1,
            base_delay: Duration::from_millis(5),
        }
    }

    /// Calculate exponential backoff delay with deterministic jitter
    /// (`min(base * 2^(attempt-1) * jitter, max_retry_delay)`).
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let shift = attempt.saturating_sub(1).min(20);
        let mult = 1u64 << shift;
        let base_ms = self.base_delay.as_millis() as u64;
        let raw_ms = base_ms.saturating_mul(mult);
        let max_ms = self.max_retry_delay_secs.saturating_mul(1000);
        let capped_ms = raw_ms.min(max_ms);

        // Add subtle ±25% deterministic jitter derived from system clock nanos.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        let jitter_pct = 75 + (nanos % 51); // 75%..=125%
        let jittered_ms = (capped_ms.saturating_mul(jitter_pct) / 100).min(max_ms);
        Duration::from_millis(jittered_ms)
    }

    /// Returns `true` if an HTTP status code is retryable in GCS / apitools.
    pub fn is_retryable_status(status: u16) -> bool {
        matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
    }

    /// Returns `true` if a `reqwest::Error` is transient and retryable.
    pub fn is_retryable_reqwest_error(err: &reqwest::Error) -> bool {
        err.is_timeout() || err.is_connect() || err.is_request() || err.is_body()
    }

    /// Execute an async operation with exponential backoff retries.
    ///
    /// `should_retry` inspects each `Err(&E)` and returns `true` if the operation should be retried.
    pub async fn execute<T, E, F, Fut, P>(&self, mut op: F, should_retry: P) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        P: Fn(&E) -> bool,
    {
        let start = Instant::now();
        let mut attempt: u32 = 0;

        loop {
            match op().await {
                Ok(val) => return Ok(val),
                Err(err) => {
                    if attempt >= self.max_retries || !should_retry(&err) {
                        return Err(err);
                    }
                    attempt += 1;
                    let delay = self.delay_for_attempt(attempt);
                    let elapsed = start.elapsed().as_secs();
                    if elapsed >= LONG_RETRY_WARN_SEC {
                        info!("Retrying request, attempt #{}...", attempt);
                    } else {
                        debug!(
                            "Retryable error encountered; retrying attempt {}/{} after {:?}",
                            attempt, self.max_retries, delay
                        );
                    }
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
    }
}
