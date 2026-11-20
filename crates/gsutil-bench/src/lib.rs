//! Benchmark harness comparing Python `gsutil` (`/usr/bin/gsutil`) vs Rust `gsutil-rs`
//! across cold start, local transfers, mock GCS `-m` fanout, and live GCS (`GSUTIL_TEST_BUCKET`).

pub mod mock_server;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Single execution measurement for a child process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMeasurement {
    pub duration_ms: f64,
    pub peak_rss_kib: u64,
    pub exit_code: i32,
}

/// Aggregated statistics across N iterations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkStats {
    pub iterations: usize,
    pub min_ms: f64,
    pub median_ms: f64,
    pub p95_ms: f64,
    pub mean_ms: f64,
    pub peak_rss_mib: f64,
    pub throughput_mib_s: Option<f64>,
    pub all_succeeded: bool,
}

/// Side-by-side comparison of Python gsutil vs Rust gsutil for one benchmark case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkComparison {
    pub category: String,
    pub name: String,
    pub bytes_processed: Option<u64>,
    pub python: Option<BenchmarkStats>,
    pub rust: BenchmarkStats,
    pub speedup_median: Option<f64>,
    pub rss_reduction_ratio: Option<f64>,
}

/// Spawn `bin` with `args` and `env_vars`, waiting via `wait4` on Unix to capture
/// exact child `ru_maxrss` (peak RSS) and wall-clock latency with zero wrapper overhead.
pub fn measure_command(
    bin: &Path,
    args: &[String],
    env_vars: &BTreeMap<String, String>,
) -> std::io::Result<RunMeasurement> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env("GSUTIL_NO_BANNER", "true")
        .env("LC_ALL", "C.UTF-8")
        .env("TZ", "UTC");
    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    let start = Instant::now();
    let child = cmd.spawn()?;
    let (exit_code, peak_rss_kib) = wait_child_with_rusage(child)?;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    Ok(RunMeasurement {
        duration_ms,
        peak_rss_kib,
        exit_code,
    })
}

#[cfg(unix)]
fn wait_child_with_rusage(mut child: std::process::Child) -> std::io::Result<(i32, u64)> {
    let pid = child.id() as libc::pid_t;
    let mut status: libc::c_int = 0;
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };

    let ret = loop {
        let r = unsafe { libc::wait4(pid, &mut status, 0, &mut rusage) };
        if r == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // Fallback to standard wait if wait4 failed unexpectedly.
            let st = child.wait()?;
            return Ok((st.code().unwrap_or(-1), 0));
        }
        break r;
    };
    let _ = ret;

    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        -1
    };

    // On Linux ru_maxrss is in KiB; on macOS it is in bytes.
    #[cfg(target_os = "macos")]
    let rss_kib = (rusage.ru_maxrss as u64) / 1024;
    #[cfg(not(target_os = "macos"))]
    let rss_kib = rusage.ru_maxrss.max(0) as u64;

    Ok((exit_code, rss_kib))
}

#[cfg(not(unix))]
fn wait_child_with_rusage(mut child: std::process::Child) -> std::io::Result<(i32, u64)> {
    let status = child.wait()?;
    Ok((status.code().unwrap_or(-1), 0))
}

/// Aggregate raw measurements into `BenchmarkStats`.
pub fn summarize(runs: &[RunMeasurement], bytes_processed: Option<u64>) -> BenchmarkStats {
    if runs.is_empty() {
        return BenchmarkStats {
            iterations: 0,
            min_ms: 0.0,
            median_ms: 0.0,
            p95_ms: 0.0,
            mean_ms: 0.0,
            peak_rss_mib: 0.0,
            throughput_mib_s: None,
            all_succeeded: false,
        };
    }

    let mut durations: Vec<f64> = runs.iter().map(|r| r.duration_ms).collect();
    durations.sort_by(|a, b| a.total_cmp(b));

    let n = durations.len();
    let min_ms = durations[0];
    let median_ms = if n % 2 == 1 {
        durations[n / 2]
    } else {
        (durations[n / 2 - 1] + durations[n / 2]) / 2.0
    };
    let p95_idx = ((n as f64) * 0.95).ceil() as usize;
    let p95_ms = durations[p95_idx.saturating_sub(1).min(n - 1)];
    let mean_ms = durations.iter().sum::<f64>() / (n as f64);

    let max_rss_kib = runs.iter().map(|r| r.peak_rss_kib).max().unwrap_or(0);
    let peak_rss_mib = (max_rss_kib as f64) / 1024.0;

    let throughput_mib_s = bytes_processed.and_then(|bytes| {
        if median_ms > 0.0 {
            let mib = (bytes as f64) / (1024.0 * 1024.0);
            Some(mib / (median_ms / 1000.0))
        } else {
            None
        }
    });

    let all_succeeded = runs.iter().all(|r| r.exit_code == 0);

    BenchmarkStats {
        iterations: n,
        min_ms,
        median_ms,
        p95_ms,
        mean_ms,
        peak_rss_mib,
        throughput_mib_s,
        all_succeeded,
    }
}

/// Build a `BenchmarkComparison` from optional Python stats and Rust stats.
pub fn compare(
    category: impl Into<String>,
    name: impl Into<String>,
    bytes_processed: Option<u64>,
    python: Option<BenchmarkStats>,
    rust: BenchmarkStats,
) -> BenchmarkComparison {
    let speedup_median = python.as_ref().and_then(|py| {
        if rust.median_ms > 0.0 {
            Some(py.median_ms / rust.median_ms)
        } else {
            None
        }
    });
    let rss_reduction_ratio = python.as_ref().and_then(|py| {
        if rust.peak_rss_mib > 0.0 && py.peak_rss_mib > 0.0 {
            Some(py.peak_rss_mib / rust.peak_rss_mib)
        } else {
            None
        }
    });

    BenchmarkComparison {
        category: category.into(),
        name: name.into(),
        bytes_processed,
        python,
        rust,
        speedup_median,
        rss_reduction_ratio,
    }
}

/// Render a Markdown benchmark scorecard comparing Python gsutil vs Rust gsutil.
pub fn render_markdown_report(comparisons: &[BenchmarkComparison]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# gsutil-rs Benchmark Report\n");
    let _ = writeln!(
        out,
        "| Category | Benchmark | Python Median (ms) | Rust Median (ms) | Speedup | Rust p95 (ms) | Python RSS (MiB) | Rust RSS (MiB) | Rust Throughput (MiB/s) |"
    );
    let _ = writeln!(
        out,
        "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
    );

    for c in comparisons {
        let py_med = c
            .python
            .as_ref()
            .map(|p| format!("{:.1}", p.median_ms))
            .unwrap_or_else(|| "—".to_string());
        let speedup = c
            .speedup_median
            .map(|s| format!("**{s:.1}x**"))
            .unwrap_or_else(|| "—".to_string());
        let py_rss = c
            .python
            .as_ref()
            .map(|p| format!("{:.1}", p.peak_rss_mib))
            .unwrap_or_else(|| "—".to_string());
        let throughput = c
            .rust
            .throughput_mib_s
            .map(|t| format!("{t:.1}"))
            .unwrap_or_else(|| "—".to_string());
        let py_failed = c.python.as_ref().is_some_and(|p| !p.all_succeeded);
        let rs_failed = !c.rust.all_succeeded;
        let status_mark = match (py_failed, rs_failed) {
            (false, false) => "",
            (true, false) => " (py!)",
            (false, true) => " (rs!)",
            (true, true) => " (py!,rs!)",
        };

        let _ = writeln!(
            out,
            "| {} | {}{} | {} | {:.1} | {} | {:.1} | {} | {:.1} | {} |",
            c.category,
            c.name,
            status_mark,
            py_med,
            c.rust.median_ms,
            speedup,
            c.rust.p95_ms,
            py_rss,
            c.rust.peak_rss_mib,
            throughput
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_summarize_and_compare() {
        let py_runs = vec![
            RunMeasurement {
                duration_ms: 420.0,
                peak_rss_kib: 65_536,
                exit_code: 0,
            },
            RunMeasurement {
                duration_ms: 400.0,
                peak_rss_kib: 64_000,
                exit_code: 0,
            },
            RunMeasurement {
                duration_ms: 450.0,
                peak_rss_kib: 66_000,
                exit_code: 0,
            },
        ];
        let rs_runs = vec![
            RunMeasurement {
                duration_ms: 8.0,
                peak_rss_kib: 6_144,
                exit_code: 0,
            },
            RunMeasurement {
                duration_ms: 10.0,
                peak_rss_kib: 6_144,
                exit_code: 0,
            },
            RunMeasurement {
                duration_ms: 12.0,
                peak_rss_kib: 6_144,
                exit_code: 0,
            },
        ];

        let py_stats = summarize(&py_runs, Some(10 * 1024 * 1024));
        let rs_stats = summarize(&rs_runs, Some(10 * 1024 * 1024));
        assert!((py_stats.median_ms - 420.0).abs() < 1e-6);
        assert!((rs_stats.median_ms - 10.0).abs() < 1e-6);
        assert!(rs_stats.throughput_mib_s.unwrap() > 900.0);

        let cmp = compare(
            "cold",
            "version",
            Some(10 * 1024 * 1024),
            Some(py_stats),
            rs_stats,
        );
        assert!((cmp.speedup_median.unwrap() - 42.0).abs() < 1e-6);

        let md = render_markdown_report(&[cmp]);
        assert!(md.contains("**42.0x**"));
        assert!(md.contains("| cold | version |"));
    }

    #[test]
    fn test_measure_command_captures_exit_and_rss() {
        let m = measure_command(Path::new("/bin/true"), &[], &BTreeMap::new()).unwrap();
        assert_eq!(m.exit_code, 0);
        assert!(m.duration_ms >= 0.0);
    }
}
