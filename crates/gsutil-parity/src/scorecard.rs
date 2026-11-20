//! Parity scorecard reporter (JSON and Markdown) grouped by category & command.

use crate::runner::CaseResult;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BucketStats {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub ref_total_ms: u64,
    pub rust_total_ms: u64,
}

impl BucketStats {
    pub fn record(&mut self, r: &CaseResult) {
        self.total += 1;
        if r.skipped {
            self.skipped += 1;
        } else if r.passed {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
        if let Some(ref o) = r.ref_output {
            self.ref_total_ms += o.duration_ms;
        }
        if let Some(ref o) = r.rust_output {
            self.rust_total_ms += o.duration_ms;
        }
    }

    pub fn pass_rate_pct(&self) -> f64 {
        let executed = self.passed + self.failed;
        if executed == 0 {
            0.0
        } else {
            (self.passed as f64 / executed as f64) * 100.0
        }
    }

    pub fn speedup(&self) -> Option<f64> {
        if self.rust_total_ms > 0 && self.ref_total_ms > 0 {
            Some(self.ref_total_ms as f64 / self.rust_total_ms as f64)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityScorecard {
    pub generated_at: String,
    pub summary: BucketStats,
    pub by_category: BTreeMap<String, BucketStats>,
    pub by_command: BTreeMap<String, BucketStats>,
    pub results: Vec<CaseResult>,
}

impl ParityScorecard {
    pub fn from_results(results: Vec<CaseResult>) -> Self {
        let mut summary = BucketStats::default();
        let mut by_category: BTreeMap<String, BucketStats> = BTreeMap::new();
        let mut by_command: BTreeMap<String, BucketStats> = BTreeMap::new();

        for r in &results {
            summary.record(r);
            by_category.entry(r.category.clone()).or_default().record(r);
            by_command.entry(r.command.clone()).or_default().record(r);
        }

        Self {
            generated_at: Utc::now().to_rfc3339(),
            summary,
            by_category,
            by_command,
            results,
        }
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# gsutil-rs Differential Parity Scorecard\n\n");
        md.push_str(&format!("Generated: `{}`\n\n", self.generated_at));

        let speedup_str = self
            .summary
            .speedup()
            .map(|s| format!("{:.1}x", s))
            .unwrap_or_else(|| "n/a".into());
        md.push_str(&format!(
            "**Overall:** {}/{} passed ({:.1}%), {} failed, {} skipped | Python: {}ms vs Rust: {}ms (speedup: **{}**)\n\n",
            self.summary.passed,
            self.summary.passed + self.summary.failed,
            self.summary.pass_rate_pct(),
            self.summary.failed,
            self.summary.skipped,
            self.summary.ref_total_ms,
            self.summary.rust_total_ms,
            speedup_str,
        ));

        md.push_str("## By Category\n\n");
        md.push_str("| Category | Passed | Failed | Skipped | Pass Rate | Py (ms) | Rust (ms) | Speedup |\n");
        md.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
        for (cat, st) in &self.by_category {
            let sp = st
                .speedup()
                .map(|s| format!("{:.1}x", s))
                .unwrap_or_else(|| "-".into());
            md.push_str(&format!(
                "| `{}` | {} | {} | {} | {:.1}% | {} | {} | {} |\n",
                cat,
                st.passed,
                st.failed,
                st.skipped,
                st.pass_rate_pct(),
                st.ref_total_ms,
                st.rust_total_ms,
                sp
            ));
        }

        md.push_str("\n## By Command\n\n");
        md.push_str("| Command | Passed | Failed | Skipped | Pass Rate |\n");
        md.push_str("| --- | ---: | ---: | ---: | ---: |\n");
        for (cmd, st) in &self.by_command {
            md.push_str(&format!(
                "| `{}` | {} | {} | {} | {:.1}% |\n",
                cmd,
                st.passed,
                st.failed,
                st.skipped,
                st.pass_rate_pct()
            ));
        }

        let failures: Vec<&CaseResult> = self
            .results
            .iter()
            .filter(|r| !r.passed && !r.skipped)
            .collect();
        if !failures.is_empty() {
            md.push_str("\n## Discrepancies\n\n");
            for f in failures {
                md.push_str(&format!(
                    "### `{}` (`{}`)\n- Args: `{:?}`\n",
                    f.id, f.command, f.args
                ));
                if !f.exit_code_match {
                    let ref_ec = f.ref_output.as_ref().map(|o| o.exit_code);
                    let rust_ec = f.rust_output.as_ref().map(|o| o.exit_code);
                    md.push_str(&format!(
                        "- **Exit code mismatch**: ref=`{:?}`, rust=`{:?}`\n",
                        ref_ec, rust_ec
                    ));
                }
                if let Some(ref sc) = f.stdout_cmp {
                    if !sc.matched {
                        if let Some(ref d) = sc.detail {
                            md.push_str(&format!("- **Stdout**:\n```text\n{}\n```\n", d));
                        }
                    }
                }
                if let Some(ref sc) = f.stderr_cmp {
                    if !sc.matched {
                        if let Some(ref d) = sc.detail {
                            md.push_str(&format!("- **Stderr**:\n```text\n{}\n```\n", d));
                        }
                    }
                }
                if let Some(ref se) = f.side_effect_error {
                    md.push_str(&format!("- **Side effect / execution error**: {}\n", se));
                }
                md.push('\n');
            }
        }

        md
    }
}
