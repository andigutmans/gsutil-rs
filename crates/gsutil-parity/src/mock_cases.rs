//! True differential Mock GCS test suite (`--mode mock`) comparing native
//! `/usr/bin/gsutil` v5.38 against Rust `gsutil` over self-signed localhost TLS.
//!
//! Uses isolated paired buckets (`py-bkt` vs `rs-bkt`, `py-ubla` vs `rs-ubla`)
//! so Python and Rust never collide on mutations, enabling exact/normalized
//! stdout/stderr diffs PLUS post-operation server & local filesystem checks.

use crate::cases::{matches_filter, seeded_random_bytes};
use crate::mock_gcs::MockGcsServer;
use crate::normalize::{CompareRule, NormalizeContext};
use crate::runner::{CaseResult, GsutilRunner, RunOptions};
use serde_json::json;
use tempfile::TempDir;

/// Run true differential mock GCS tests against native `/usr/bin/gsutil` v5.38 over TLS.
pub async fn run_mock_gcs_suite(runner: &GsutilRunner, filter: Option<&str>) -> Vec<CaseResult> {
    let mut results = Vec::new();
    let server = match MockGcsServer::start_tls().await {
        Ok(s) => s,
        Err(e) => {
            results.push(CaseResult {
                id: "mock_gcs_tls_startup".into(),
                category: "mock_gcs".into(),
                command: "setup".into(),
                args: vec![],
                passed: false,
                skipped: false,
                skip_reason: None,
                exit_code_match: false,
                ref_output: None,
                rust_output: None,
                stdout_cmp: None,
                stderr_cmp: None,
                side_effect_error: Some(format!("failed to start TLS MockGcsServer: {}", e)),
            });
            return results;
        }
    };

    let binary_payload = seeded_random_bytes(0xC0FF_EE42, 4096);

    // Seed identical paired buckets for Python (`py-*`) and Rust (`rs-*`).
    for bkt in ["py-bkt", "rs-bkt"] {
        server.seed_bucket(bkt);
        server.seed_object(bkt, "hello.txt", b"0123456789");
        server.seed_object(bkt, "second.txt", b"abcdefghij");
        server.seed_object(bkt, "empty.bin", b"");
        server.seed_object(bkt, "dir/nested.txt", b"nested-payload");
        server.seed_object(bkt, "binary.bin", &binary_payload);
    }
    // Seed paired UBLA-enabled buckets to test UBLA enforcement (400 on ACLs).
    for bkt in ["py-ubla", "rs-ubla"] {
        server.seed_bucket(bkt);
        let mut st = server.state.lock().expect("lock");
        if let Some(b) = st.buckets.get_mut(bkt) {
            b.extra_fields.insert(
                "iamConfiguration".into(),
                json!({
                    "uniformBucketLevelAccess": { "enabled": true },
                    "bucketPolicyOnly": { "enabled": true }
                }),
            );
        }
    }

    // Seed paired 1,050-object buckets to test >1,000 `nextPageToken` pagination boundary!
    for bkt in ["py-page", "rs-page"] {
        server.seed_bucket(bkt);
        let mut st = server.state.lock().expect("lock");
        for i in 0..1050 {
            let name = format!("obj-{i:04}.txt");
            st.put_object(bkt, &name, b"x".to_vec(), "text/plain");
        }
    }

    let tmp = TempDir::new().expect("temp dir");
    let boto = tmp.path().join("mock_tls.boto");
    server.write_boto_config(&boto).expect("write tls boto");
    let ca_path = tmp.path().join("mock_ca.pem");
    let fake_home = tmp.path().join("home");
    std::fs::create_dir_all(&fake_home).expect("mkdir fake home");
    let adc_path = tmp.path().join("adc.json");
    std::fs::write(
        &adc_path,
        json!({
            "type": "authorized_user",
            "client_id": "mock-client-id",
            "client_secret": "mock-client-secret",
            "refresh_token": "mock-refresh-token",
            "token_uri": format!("{}/oauth2/token", server.base_url()),
        })
        .to_string(),
    )
    .expect("write mock adc.json");

    let mk_opts = |args: Vec<String>| -> RunOptions {
        RunOptions::new(args)
            .with_boto_config(&boto)
            .with_env("GOOGLE_APPLICATION_CREDENTIALS", adc_path.to_string_lossy())
            .with_env("SSL_CERT_FILE", ca_path.to_string_lossy())
            .with_env("REQUESTS_CA_BUNDLE", ca_path.to_string_lossy())
            .with_env("CLOUDSDK_CORE_PASS_CREDENTIALS_TO_GSUTIL", "False")
            .with_env("CLOUDSDK_CONTEXT_AWARE_USE_CLIENT_CERTIFICATE", "false")
            .with_env("CLOUDSDK_CONFIG", fake_home.to_string_lossy())
            .with_env("HOME", fake_home.to_string_lossy())
    };

    let base_ctx = NormalizeContext::default()
        .with_temp_path(tmp.path().to_string_lossy())
        .with_test_bucket("py-bkt")
        .with_test_bucket("rs-bkt")
        .with_test_bucket("py-ubla")
        .with_test_bucket("rs-ubla")
        .with_test_bucket("py-new-bkt")
        .with_test_bucket("rs-new-bkt")
        .with_test_bucket("py-page")
        .with_test_bucket("rs-page")
        .strip_ui();

    // Helper: runs identical command on `py-bkt` (ref) vs `rs-bkt` (rust) via `run_diff`.
    let run_pair = |results: &mut Vec<CaseResult>,
                    id: &str,
                    cmd: &str,
                    template_args: &[&str],
                    stdout_rule: CompareRule,
                    stderr_rule: CompareRule| {
        if !matches_filter(filter, id, "mock_gcs", cmd) {
            return;
        }
        let ref_args: Vec<String> = template_args
            .iter()
            .map(|a| {
                a.replace("{BKT}", "py-bkt")
                    .replace("{UBLA}", "py-ubla")
                    .replace("{NEWBKT}", "py-new-bkt")
            })
            .collect();
        let rust_args: Vec<String> = template_args
            .iter()
            .map(|a| {
                a.replace("{BKT}", "rs-bkt")
                    .replace("{UBLA}", "rs-ubla")
                    .replace("{NEWBKT}", "rs-new-bkt")
            })
            .collect();
        let ref_opts = mk_opts(ref_args);
        let rust_opts = mk_opts(rust_args);
        results.push(runner.run_diff(
            id,
            "mock_gcs",
            cmd,
            &ref_opts,
            &rust_opts,
            &stdout_rule,
            &stderr_rule,
            &base_ctx,
        ));
    };

    // -------------------------------------------------------------------------
    // 1. Read / Inspect commands (true differential Normalized/Exact stdout)
    // -------------------------------------------------------------------------
    run_pair(
        &mut results,
        "mock_ls_bucket",
        "ls",
        &["ls", "gs://{BKT}"],
        CompareRule::Normalized,
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_ls_long",
        "ls",
        &["ls", "-l", "gs://{BKT}/hello.txt"],
        CompareRule::Normalized,
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_stat_object",
        "stat",
        &["stat", "gs://{BKT}/hello.txt"],
        CompareRule::Normalized,
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_cat_full",
        "cat",
        &["cat", "gs://{BKT}/hello.txt"],
        CompareRule::Exact,
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_cat_empty_file",
        "cat",
        &["cat", "gs://{BKT}/empty.bin"],
        CompareRule::Exact,
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_cat_range_1_3",
        "cat",
        &["cat", "-r", "1-3", "gs://{BKT}/hello.txt"],
        CompareRule::Exact,
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_cat_range_suffix",
        "cat",
        &["cat", "-r", "-3", "gs://{BKT}/hello.txt"],
        CompareRule::Exact,
        CompareRule::Normalized,
    );
    // Bug #8 regression test: multi-object `cat -r`
    run_pair(
        &mut results,
        "mock_cat_range_multi_object",
        "cat",
        &[
            "cat",
            "-r",
            "0-2",
            "gs://{BKT}/hello.txt",
            "gs://{BKT}/second.txt",
        ],
        CompareRule::Exact,
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_cat_header",
        "cat",
        &["cat", "-h", "gs://{BKT}/hello.txt"],
        CompareRule::Exact,
        CompareRule::ContainsAll(vec!["==> gs://<TEST_BUCKET>/hello.txt <==".into()]),
    );
    run_pair(
        &mut results,
        "mock_hash_cloud_base64",
        "hash",
        &["hash", "gs://{BKT}/hello.txt"],
        CompareRule::Normalized,
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_hash_cloud_hex",
        "hash",
        &["hash", "-h", "gs://{BKT}/hello.txt"],
        CompareRule::Normalized,
        CompareRule::Normalized,
    );
    // Bug #8 regression tests: cloud `hash -c` and `hash -m`
    // Note: native Python gsutil v5.38 prints both md5+crc32c on cloud objects even with -c/-m,
    // while gcloud storage & Rust honor -c/-m; verify both exit 0 and contain the requested hash.
    run_pair(
        &mut results,
        "mock_hash_cloud_crc32c_only",
        "hash",
        &["hash", "-c", "gs://{BKT}/hello.txt"],
        CompareRule::ContainsAll(vec!["Hash (crc32c):".into(), "KAwGng==".into()]),
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_hash_cloud_md5_only",
        "hash",
        &["hash", "-m", "gs://{BKT}/hello.txt"],
        CompareRule::ContainsAll(vec![
            "Hash (md5):".into(),
            "eB5eJF1ptWaXm4bijSPyxw==".into(),
        ]),
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_du_bucket",
        "du",
        &["du", "gs://{BKT}"],
        CompareRule::Normalized,
        CompareRule::Normalized,
    );

    // -------------------------------------------------------------------------
    // 2. Transfers + Side-Effect Verification (upload, download, gzip -Z, c2c,
    //    compose, rewrite, mv, rm, mb, rb)
    // -------------------------------------------------------------------------
    let local_up = tmp.path().join("upload.bin");
    let up_bytes = seeded_random_bytes(0x1234_5678, 8192);
    std::fs::write(&local_up, &up_bytes).unwrap();
    let local_up_s = local_up.to_string_lossy().into_owned();

    run_pair(
        &mut results,
        "mock_cp_upload_binary",
        "cp",
        &["cp", &local_up_s, "gs://{BKT}/uploaded.bin"],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    if let Some(last) = results.last_mut() {
        if last.id == "mock_cp_upload_binary" && !last.skipped && last.passed {
            let st = server.state.lock().expect("lock");
            let py_b = st.buckets.get("py-bkt").and_then(|b| {
                b.objects
                    .iter()
                    .find(|o| o.name == "uploaded.bin" && !o.deleted)
            });
            let rs_b = st.buckets.get("rs-bkt").and_then(|b| {
                b.objects
                    .iter()
                    .find(|o| o.name == "uploaded.bin" && !o.deleted)
            });
            if py_b.map(|o| o.data.as_slice()) != Some(up_bytes.as_slice())
                || rs_b.map(|o| o.data.as_slice()) != Some(up_bytes.as_slice())
            {
                last.passed = false;
                last.side_effect_error =
                    Some("uploaded binary bytes differ in mock GCS state".into());
            }
        }
    }

    // Download binary & verify exact byte parity
    if matches_filter(filter, "mock_cp_download_binary", "mock_gcs", "cp") {
        let py_dl = tmp.path().join("dl_py.bin");
        let rs_dl = tmp.path().join("dl_rs.bin");
        let ref_opts = mk_opts(vec![
            "cp".into(),
            "gs://py-bkt/binary.bin".into(),
            py_dl.to_string_lossy().into_owned(),
        ]);
        let rust_opts = mk_opts(vec![
            "cp".into(),
            "gs://rs-bkt/binary.bin".into(),
            rs_dl.to_string_lossy().into_owned(),
        ]);
        let mut res = runner.run_diff(
            "mock_cp_download_binary",
            "mock_gcs",
            "cp",
            &ref_opts,
            &rust_opts,
            &CompareRule::Exact,
            &CompareRule::Ignore,
            &base_ctx,
        );
        if !res.skipped && res.passed {
            let py_b = std::fs::read(&py_dl).ok();
            let rs_b = std::fs::read(&rs_dl).ok();
            if py_b.as_deref() != Some(binary_payload.as_slice())
                || rs_b.as_deref() != Some(binary_payload.as_slice())
            {
                res.passed = false;
                res.side_effect_error = Some("downloaded binary bytes mismatch".into());
            }
        }
        results.push(res);
    }

    // Bug #2 regression test: cp -Z upload + download through transparent gzip decompression!
    let gzip_src = tmp.path().join("compressible.txt");
    let gzip_text = b"gsutil-rs gzip roundtrip verification line 1234567890\n".repeat(40);
    std::fs::write(&gzip_src, &gzip_text).unwrap();
    let gzip_src_s = gzip_src.to_string_lossy().into_owned();

    run_pair(
        &mut results,
        "mock_cp_gzip_upload",
        "cp",
        &["cp", "-Z", &gzip_src_s, "gs://{BKT}/gzipped.txt"],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    if matches_filter(filter, "mock_cp_gzip_download", "mock_gcs", "cp") {
        let py_dl = tmp.path().join("gz_dl_py.txt");
        let rs_dl = tmp.path().join("gz_dl_rs.txt");
        let ref_opts = mk_opts(vec![
            "cp".into(),
            "gs://py-bkt/gzipped.txt".into(),
            py_dl.to_string_lossy().into_owned(),
        ]);
        let rust_opts = mk_opts(vec![
            "cp".into(),
            "gs://rs-bkt/gzipped.txt".into(),
            rs_dl.to_string_lossy().into_owned(),
        ]);
        let mut res = runner.run_diff(
            "mock_cp_gzip_download",
            "mock_gcs",
            "cp",
            &ref_opts,
            &rust_opts,
            &CompareRule::Exact,
            &CompareRule::Ignore,
            &base_ctx,
        );
        if !res.skipped && res.passed {
            let py_b = std::fs::read(&py_dl).ok();
            let rs_b = std::fs::read(&rs_dl).ok();
            if py_b.as_deref() != Some(gzip_text.as_slice())
                || rs_b.as_deref() != Some(gzip_text.as_slice())
            {
                res.passed = false;
                res.side_effect_error = Some(format!(
                    "gzip download byte mismatch (py={:?}B, rs={:?}B, expected={}B)",
                    py_b.map(|v| v.len()),
                    rs_b.map(|v| v.len()),
                    gzip_text.len()
                ));
            }
        }
        results.push(res);
    }

    run_pair(
        &mut results,
        "mock_cp_cloud_to_cloud",
        "cp",
        &["cp", "gs://{BKT}/hello.txt", "gs://{BKT}/hello_copy.txt"],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_pair(
        &mut results,
        "mock_compose",
        "compose",
        &[
            "compose",
            "gs://{BKT}/hello.txt",
            "gs://{BKT}/second.txt",
            "gs://{BKT}/composed.txt",
        ],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_pair(
        &mut results,
        "mock_cat_composed",
        "cat",
        &["cat", "gs://{BKT}/composed.txt"],
        CompareRule::Exact,
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_rewrite_nearline",
        "rewrite",
        &["rewrite", "-s", "NEARLINE", "gs://{BKT}/hello_copy.txt"],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    if let Some(last) = results.last_mut() {
        if last.id == "mock_rewrite_nearline" && !last.skipped && last.passed {
            let st = server.state.lock().expect("lock");
            let rs_sc = st
                .buckets
                .get("rs-bkt")
                .and_then(|b| {
                    b.objects
                        .iter()
                        .find(|o| o.name == "hello_copy.txt" && !o.deleted)
                })
                .map(|o| o.storage_class.as_str());
            if rs_sc != Some("NEARLINE") {
                last.passed = false;
                last.side_effect_error = Some(format!(
                    "rewrite did not update storageClass (got {:?})",
                    rs_sc
                ));
            }
        }
    }

    // Bug #3 regression test: setmeta set AND remove custom metadata key!
    run_pair(
        &mut results,
        "mock_setmeta_set",
        "setmeta",
        &[
            "setmeta",
            "-h",
            "x-goog-meta-foo:bar",
            "gs://{BKT}/hello_copy.txt",
        ],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_pair(
        &mut results,
        "mock_setmeta_remove",
        "setmeta",
        &[
            "setmeta",
            "-h",
            "x-goog-meta-foo",
            "gs://{BKT}/hello_copy.txt",
        ],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    if let Some(last) = results.last_mut() {
        if last.id == "mock_setmeta_remove" && !last.skipped && last.passed {
            let st = server.state.lock().expect("lock");
            let rs_has_foo = st
                .buckets
                .get("rs-bkt")
                .and_then(|b| {
                    b.objects
                        .iter()
                        .find(|o| o.name == "hello_copy.txt" && !o.deleted)
                })
                .is_some_and(|o| o.metadata.contains_key("foo"));
            if rs_has_foo {
                last.passed = false;
                last.side_effect_error = Some(
                    "setmeta removal failed: x-goog-meta-foo still present after PATCH".into(),
                );
            }
        }
    }

    run_pair(
        &mut results,
        "mock_mv_cloud",
        "mv",
        &[
            "mv",
            "gs://{BKT}/hello_copy.txt",
            "gs://{BKT}/hello_moved.txt",
        ],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_pair(
        &mut results,
        "mock_rm_object",
        "rm",
        &["rm", "gs://{BKT}/hello_moved.txt"],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_pair(
        &mut results,
        "mock_mb_new_bucket",
        "mb",
        &["mb", "gs://{NEWBKT}"],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_pair(
        &mut results,
        "mock_rb_empty_bucket",
        "rb",
        &["rb", "gs://{NEWBKT}"],
        CompareRule::Exact,
        CompareRule::Ignore,
    );

    // -------------------------------------------------------------------------
    // 3. Admin & Bucket Config Roundtrips (Bugs #1, #3, #7 — Normalized stdout!)
    // -------------------------------------------------------------------------
    // Bug #7: defstorageclass get (no trailing slash) & set nl
    run_pair(
        &mut results,
        "mock_defstorageclass_get",
        "defstorageclass",
        &["defstorageclass", "get", "gs://{BKT}"],
        CompareRule::Normalized,
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_defstorageclass_set_nl",
        "defstorageclass",
        &["defstorageclass", "set", "nl", "gs://{BKT}"],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_pair(
        &mut results,
        "mock_defstorageclass_get_after_set",
        "defstorageclass",
        &["defstorageclass", "get", "gs://{BKT}"],
        CompareRule::Normalized,
        CompareRule::Normalized,
    );
    // Bug #7: iam get (no extra kind/resourceId/version)
    run_pair(
        &mut results,
        "mock_iam_get",
        "iam",
        &["iam", "get", "gs://{BKT}"],
        CompareRule::Normalized,
        CompareRule::Normalized,
    );
    // Bug #3: label ch -l & label ch -d (null tombstone removal!)
    run_pair(
        &mut results,
        "mock_label_ch_add",
        "label",
        &["label", "ch", "-l", "env:prod", "gs://{BKT}"],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_pair(
        &mut results,
        "mock_label_ch_delete",
        "label",
        &["label", "ch", "-d", "env", "gs://{BKT}"],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_pair(
        &mut results,
        "mock_label_get_after_delete",
        "label",
        &["label", "get", "gs://{BKT}"],
        CompareRule::Normalized,
        CompareRule::Normalized,
    );
    // Bug #1: retention set 1m (2,678,400s!) + retention get exact format + retention clear
    run_pair(
        &mut results,
        "mock_retention_set_1m",
        "retention",
        &["retention", "set", "1m", "gs://{BKT}"],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_pair(
        &mut results,
        "mock_retention_get",
        "retention",
        &["retention", "get", "gs://{BKT}"],
        CompareRule::Normalized,
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_retention_clear",
        "retention",
        &["retention", "clear", "gs://{BKT}"],
        CompareRule::Exact,
        CompareRule::Ignore,
    );

    // Remaining bucket config getters (true Normalized stdout diff!)
    for (id, cmd, args) in [
        (
            "mock_versioning_get",
            "versioning",
            &["versioning", "get", "gs://{BKT}"][..],
        ),
        ("mock_cors_get", "cors", &["cors", "get", "gs://{BKT}"][..]),
        (
            "mock_lifecycle_get",
            "lifecycle",
            &["lifecycle", "get", "gs://{BKT}"][..],
        ),
        (
            "mock_logging_get",
            "logging",
            &["logging", "get", "gs://{BKT}"][..],
        ),
        ("mock_web_get", "web", &["web", "get", "gs://{BKT}"][..]),
        (
            "mock_requesterpays_get",
            "requesterpays",
            &["requesterpays", "get", "gs://{BKT}"][..],
        ),
        ("mock_ubla_get", "ubla", &["ubla", "get", "gs://{BKT}"][..]),
        ("mock_pap_get", "pap", &["pap", "get", "gs://{BKT}"][..]),
        ("mock_rpo_get", "rpo", &["rpo", "get", "gs://{BKT}"][..]),
        (
            "mock_autoclass_get",
            "autoclass",
            &["autoclass", "get", "gs://{BKT}"][..],
        ),
        (
            "mock_notification_list",
            "notification",
            &["notification", "list", "gs://{BKT}"][..],
        ),
    ] {
        run_pair(
            &mut results,
            id,
            cmd,
            args,
            CompareRule::Normalized,
            CompareRule::Normalized,
        );
    }

    // Fine-grained ACL get on non-UBLA bucket vs 400 error on UBLA bucket
    run_pair(
        &mut results,
        "mock_acl_get_non_ubla",
        "acl",
        &["acl", "get", "gs://{BKT}"],
        CompareRule::Normalized,
        CompareRule::Normalized,
    );
    run_pair(
        &mut results,
        "mock_acl_get_ubla_rejected",
        "acl",
        &["acl", "get", "gs://{UBLA}"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["400".into()],
        },
    );

    // -------------------------------------------------------------------------
    // 4. Deterministic HTTP Error Parity (403, 404, 409, 412, 500)
    // -------------------------------------------------------------------------
    if matches_filter(filter, "mock_error_403_forbidden", "mock_gcs", "ls") {
        // Native Python without .boto credentials prints a generic auth prompt on 403,
        // while Rust (with ADC) prints AccessDeniedException: 403; verify both exit 1 and Rust error class.
        let opts = mk_opts(vec!["ls".into(), "gs://fault-403".into()]);
        results.push(runner.run_rust_contract(
            "mock_error_403_forbidden",
            "mock_gcs",
            "ls",
            &opts,
            1,
            "",
            &CompareRule::Exact,
            "AccessDeniedException: 403",
            &CompareRule::ErrorClass {
                required_substrings: vec!["403".into()],
            },
            &base_ctx,
        ));
    }
    run_pair(
        &mut results,
        "mock_error_404_not_found",
        "ls",
        &["ls", "gs://fault-404"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["404".into()],
        },
    );
    run_pair(
        &mut results,
        "mock_error_409_conflict",
        "mb",
        &["mb", "gs://fault-409"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["409".into()],
        },
    );
    run_pair(
        &mut results,
        "mock_error_412_precondition",
        "ls",
        &["ls", "gs://fault-412"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["412".into()],
        },
    );
    run_pair(
        &mut results,
        "mock_error_500_backend",
        "ls",
        &["ls", "gs://fault-500"],
        CompareRule::Exact,
        CompareRule::ErrorClass {
            required_substrings: vec!["500".into()],
        },
    );

    // -------------------------------------------------------------------------
    // 5. >1,000-Object Pagination Boundary (`nextPageToken`)
    // -------------------------------------------------------------------------
    if matches_filter(filter, "mock_ls_pagination_1050_objects", "mock_gcs", "ls") {
        let ref_opts = mk_opts(vec!["ls".into(), "gs://py-page".into()]);
        let rust_opts = mk_opts(vec!["ls".into(), "gs://rs-page".into()]);
        let mut res = runner.run_diff(
            "mock_ls_pagination_1050_objects",
            "mock_gcs",
            "ls",
            &ref_opts,
            &rust_opts,
            &CompareRule::Normalized,
            &CompareRule::Normalized,
            &base_ctx,
        );
        if !res.skipped && res.passed {
            let lines = res
                .rust_output
                .as_ref()
                .map(|o| o.stdout.lines().count())
                .unwrap_or(0);
            if lines != 1050 {
                res.passed = false;
                res.side_effect_error = Some(format!("expected 1050 paginated lines, got {lines}"));
            }
        }
        results.push(res);
    }

    // -------------------------------------------------------------------------
    // 6. Execution Parity for Deprecated Aliases (`OLD_ALIAS_MAP`) + XML/`s3://`
    // -------------------------------------------------------------------------
    for (alias, extra_args) in [
        ("getcors", &["gs://{BKT}"][..]),
        ("getlogging", &["gs://{BKT}"][..]),
        ("getversioning", &["gs://{BKT}"][..]),
        ("getwebcfg", &["gs://{BKT}"][..]),
        ("getdefacl", &["gs://{BKT}"][..]),
        ("getacl", &["gs://{BKT}"][..]),
    ] {
        let id = format!("mock_deprecated_alias_{alias}");
        let mut args = vec![alias];
        args.extend_from_slice(extra_args);
        run_pair(
            &mut results,
            &id,
            alias,
            &args,
            CompareRule::ContainsAll(vec![]),
            CompareRule::ContainsAll(vec!["deprecated".into()]),
        );
    }
    // Verify CLI `-o GSUtil:prefer_api=xml` hits Mock XML endpoint cleanly
    if matches_filter(filter, "mock_xml_prefer_api_ls", "mock_gcs", "ls") {
        let opts = mk_opts(vec![
            "-o".into(),
            "GSUtil:prefer_api=xml".into(),
            "ls".into(),
            "gs://rs-bkt".into(),
        ]);
        results.push(runner.run_rust_contract(
            "mock_xml_prefer_api_ls",
            "mock_gcs",
            "ls",
            &opts,
            0,
            "gs://<TEST_BUCKET>/hello.txt",
            &CompareRule::ContainsAll(vec!["gs://<TEST_BUCKET>/hello.txt".into()]),
            "",
            &CompareRule::Ignore,
            &base_ctx,
        ));
    }

    results
}
