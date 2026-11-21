//! Interactive TTY progress controller (`UIController`).
//!
//! Mirrors `gslib/ui_controller.py` in Python gsutil v5.38:
//! - Tracks completed/total files, bytes transferred/total, sliding-window throughput, and ETA.
//! - Renders a throttled (~200ms) `\r` progress line to stderr ONLY when stderr is a TTY and
//!   `!quiet`, ensuring non-TTY scripts and differential tests see clean stderr output.

use std::collections::VecDeque;
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SPINNER_CHARS: [char; 4] = ['-', '\\', '|', '/'];
const RENDER_INTERVAL: Duration = Duration::from_millis(200);
const THROUGHPUT_WINDOW: Duration = Duration::from_secs(5);

/// Format a byte count into human-readable IEC units matching gsutil (`B`, `KiB`, `MiB`, `GiB`, `TiB`).
pub fn format_human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * KIB;
    const GIB: f64 = 1024.0 * MIB;
    const TIB: f64 = 1024.0 * GIB;

    let b = bytes as f64;
    if b >= TIB {
        format!("{:.1} TiB", b / TIB)
    } else if b >= GIB {
        format!("{:.1} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.1} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.1} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

/// Format an ETA duration in seconds as `HH:MM:SS`.
pub fn format_eta(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

struct RenderState {
    last_render: Option<Instant>,
    samples: VecDeque<(Instant, u64)>,
    last_line_len: usize,
}

/// Thread-safe progress tracker and throttled TTY renderer for `cp`, `mv`, and `rsync`.
pub struct UIController {
    quiet: bool,
    is_tty: bool,
    total_files: AtomicU64,
    completed_files: AtomicU64,
    total_bytes: AtomicU64,
    transferred_bytes: AtomicU64,
    spinner_idx: AtomicUsize,
    state: Mutex<RenderState>,
}

impl std::fmt::Debug for UIController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UIController")
            .field("quiet", &self.quiet)
            .field("is_tty", &self.is_tty)
            .field(
                "completed_files",
                &self.completed_files.load(Ordering::Relaxed),
            )
            .field("total_files", &self.total_files.load(Ordering::Relaxed))
            .field(
                "transferred_bytes",
                &self.transferred_bytes.load(Ordering::Relaxed),
            )
            .field("total_bytes", &self.total_bytes.load(Ordering::Relaxed))
            .finish()
    }
}

impl UIController {
    /// Create a new `UIController`, automatically detecting whether `stderr` is a TTY.
    pub fn new(quiet: bool) -> Arc<Self> {
        let is_tty = io::stderr().is_terminal();
        Self::with_tty(quiet, is_tty)
    }

    /// Create a `UIController` with explicit TTY flag (useful for tests).
    pub fn with_tty(quiet: bool, is_tty: bool) -> Arc<Self> {
        Arc::new(Self {
            quiet,
            is_tty,
            total_files: AtomicU64::new(0),
            completed_files: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            transferred_bytes: AtomicU64::new(0),
            spinner_idx: AtomicUsize::new(0),
            state: Mutex::new(RenderState {
                last_render: None,
                samples: VecDeque::new(),
                last_line_len: 0,
            }),
        })
    }

    /// Returns `true` if interactive progress output is active (`is_tty && !quiet`).
    pub fn is_interactive(&self) -> bool {
        self.is_tty && !self.quiet
    }

    /// Set the expected total number of files and bytes for the operation.
    pub fn set_totals(&self, total_files: u64, total_bytes: u64) {
        self.total_files.store(total_files, Ordering::Relaxed);
        self.total_bytes.store(total_bytes, Ordering::Relaxed);
    }

    /// Increment expected totals (for incremental discovery).
    pub fn add_totals(&self, files: u64, bytes: u64) {
        self.total_files.fetch_add(files, Ordering::Relaxed);
        self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record `delta` bytes transferred and render a throttled progress update if interactive.
    pub fn add_bytes(&self, delta: u64) {
        if delta == 0 {
            return;
        }
        let total_so_far = self.transferred_bytes.fetch_add(delta, Ordering::Relaxed) + delta;
        let now = Instant::now();

        let should_render = if let Ok(mut st) = self.state.lock() {
            st.samples.push_back((now, total_so_far));
            while let Some(&(ts, _)) = st.samples.front() {
                if now.duration_since(ts) > THROUGHPUT_WINDOW && st.samples.len() > 2 {
                    st.samples.pop_front();
                } else {
                    break;
                }
            }
            if self.is_interactive() {
                let due = st
                    .last_render
                    .is_none_or(|prev| now.duration_since(prev) >= RENDER_INTERVAL);
                if due {
                    st.last_render = Some(now);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if should_render {
            self.render_line_to_stderr();
        }
    }

    /// Mark one file/object as completed.
    pub fn finish_file(&self) {
        self.completed_files.fetch_add(1, Ordering::Relaxed);
        if self.is_interactive() {
            let now = Instant::now();
            let should_render = self
                .state
                .lock()
                .map(|mut st| {
                    let due = st
                        .last_render
                        .is_none_or(|prev| now.duration_since(prev) >= RENDER_INTERVAL);
                    if due {
                        st.last_render = Some(now);
                        true
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
            if should_render {
                self.render_line_to_stderr();
            }
        }
    }

    /// Compute sliding-window throughput in bytes per second.
    pub fn throughput_bytes_per_sec(&self) -> f64 {
        let Ok(st) = self.state.lock() else {
            return 0.0;
        };
        let (Some(&(t0, b0)), Some(&(t1, b1))) = (st.samples.front(), st.samples.back()) else {
            return 0.0;
        };
        let dt = t1.duration_since(t0).as_secs_f64();
        if dt <= 0.001 || b1 <= b0 {
            return 0.0;
        }
        (b1 - b0) as f64 / dt
    }

    /// Format the current progress bar line (without leading `\r`).
    pub fn format_progress_line(&self) -> String {
        let spinner = SPINNER_CHARS[self.spinner_idx.fetch_add(1, Ordering::Relaxed) % 4];
        let done_files = self.completed_files.load(Ordering::Relaxed);
        let tot_files = self.total_files.load(Ordering::Relaxed);
        let done_bytes = self.transferred_bytes.load(Ordering::Relaxed);
        let tot_bytes = self.total_bytes.load(Ordering::Relaxed);

        let files_part = if tot_files > 0 {
            format!("[{done_files}/{tot_files} files]")
        } else {
            format!("[{done_files} files]")
        };

        let bytes_part = if tot_bytes > 0 {
            let pct = ((done_bytes as f64 / tot_bytes as f64) * 100.0).min(100.0);
            format!(
                "[{:>9}/{:>9}] {:>3.0}% Done",
                format_human_bytes(done_bytes),
                format_human_bytes(tot_bytes),
                pct
            )
        } else {
            format!("[{:>9}]", format_human_bytes(done_bytes))
        };

        let bps = self.throughput_bytes_per_sec();
        let speed_part = if bps > 0.0 {
            let mut s = format!("  {}/s", format_human_bytes(bps as u64));
            if tot_bytes > done_bytes {
                let eta_secs = ((tot_bytes - done_bytes) as f64 / bps).ceil() as u64;
                s.push_str(&format!(" ETA {}", format_eta(eta_secs)));
            }
            s
        } else {
            String::new()
        };

        format!("{spinner} {files_part}{bytes_part}{speed_part}")
    }

    /// Format the final completion summary matching `gslib/ui_controller.py`.
    pub fn format_final_summary(&self) -> String {
        let files = self.completed_files.load(Ordering::Relaxed);
        let bytes = self.transferred_bytes.load(Ordering::Relaxed);
        format!(
            "Operation completed over {files} objects/{}.",
            format_human_bytes(bytes)
        )
    }

    /// Emit the final summary line to stderr when interactive (`is_tty && !quiet`).
    pub fn finish(&self) {
        if !self.is_interactive() {
            return;
        }
        let summary = self.format_final_summary();
        let pad = self
            .state
            .lock()
            .map(|st| st.last_line_len.saturating_sub(summary.len()))
            .unwrap_or(0);
        let mut stderr = io::stderr();
        let _ = write!(stderr, "\r{summary}{}\n", " ".repeat(pad));
        let _ = stderr.flush();
    }

    /// Create a `ProgressCallback` adapter that forwards byte deltas to `self.add_bytes`.
    pub fn progress_callback(self: &Arc<Self>) -> Arc<dyn Fn(u64, Option<u64>) + Send + Sync> {
        let ui = Arc::clone(self);
        let prev = AtomicU64::new(0);
        Arc::new(move |cumulative_bytes, _total| {
            let last = prev.swap(cumulative_bytes, Ordering::Relaxed);
            if cumulative_bytes > last {
                ui.add_bytes(cumulative_bytes - last);
            }
        })
    }

    fn render_line_to_stderr(&self) {
        let line = self.format_progress_line();
        let pad = if let Ok(mut st) = self.state.lock() {
            let p = st.last_line_len.saturating_sub(line.len());
            st.last_line_len = line.len();
            p
        } else {
            0
        };
        let mut stderr = io::stderr();
        let _ = write!(stderr, "\r{line}{}", " ".repeat(pad));
        let _ = stderr.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_human_bytes_and_eta() {
        assert_eq!(format_human_bytes(0), "0 B");
        assert_eq!(format_human_bytes(512), "512 B");
        assert_eq!(format_human_bytes(1024), "1.0 KiB");
        assert_eq!(format_human_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(format_human_bytes(2 * 1024 * 1024 * 1024), "2.0 GiB");
        assert_eq!(format_eta(0), "00:00:00");
        assert_eq!(format_eta(3661), "01:01:01");
    }

    #[test]
    fn test_ui_controller_progress_and_summary() {
        let ui = UIController::with_tty(false, false);
        assert!(!ui.is_interactive());

        let tty_ui = UIController::with_tty(false, true);
        assert!(tty_ui.is_interactive());
        let quiet_tty_ui = UIController::with_tty(true, true);
        assert!(!quiet_tty_ui.is_interactive());

        ui.set_totals(4, 10 * 1024 * 1024);
        ui.add_bytes(5 * 1024 * 1024);
        ui.finish_file();

        let line = ui.format_progress_line();
        assert!(line.contains("[1/4 files]"));
        assert!(line.contains("5.0 MiB"));
        assert!(line.contains("10.0 MiB"));
        assert!(line.contains("50% Done"));

        let cb = ui.progress_callback();
        cb(2 * 1024 * 1024, Some(10 * 1024 * 1024));
        cb(5 * 1024 * 1024, Some(10 * 1024 * 1024));
        ui.finish_file();
        ui.finish_file();
        ui.finish_file();

        assert_eq!(
            ui.format_final_summary(),
            "Operation completed over 4 objects/10.0 MiB."
        );
    }
}
