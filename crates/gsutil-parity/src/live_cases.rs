//! True differential Live GCS test suite (`--mode live`) comparing
//! `/usr/bin/gsutil -o GSUtil:use_gcloud_storage=True` against Rust `gsutil`
//! across multi-topology buckets configured via `GSUTIL_TEST_PROJECT` /
//! `GSUTIL_TEST_BUCKET`.
//!
//! Uses isolated per-run prefixes (`py-<run_id>/` vs `rs-<run_id>/`) and
//! realistic payloads (0-byte, 1 B, 64 KiB random binary, 9 MiB resumable,
//! gzip `-Z`, Unicode/spaces, `dir/` placeholder) with post-op verification.

use crate::cases::{matches_filter, seeded_random_bytes};
use crate::normalize::{CompareRule, NormalizeContext};
use crate::runner::{CaseResult, GsutilRunner, RunOptions};
use std::path::PathBuf;
use tempfile::TempDir;

struct LiveTopology {
    project: String,
    ubla_bucket: String,
    acl_bucket: Option<String>,
    versioned_bucket: String,
    dual_bucket: String,
    rp_bucket: String,
    ret_bucket: String,
    pubsub_topic: String,
    kms_key: String,
    hmac_sa: String,
    sa_key_path: Option<String>,
}

impl LiveTopology {
    fn from_env(primary_bucket: &str) -> Self {
        let ubla = primary_bucket
            .trim_start_matches("gs://")
            .trim_end_matches('/')
            .to_string();
        let project = std::env::var("GSUTIL_TEST_PROJECT")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| ubla.strip_suffix("-bucket").unwrap_or(&ubla).to_string());
        let env_or = |var: &str, default: String| {
            std::env::var(var)
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(|s| {
                    s.trim_start_matches("gs://")
                        .trim_end_matches('/')
                        .to_string()
                })
                .unwrap_or(default)
        };
        let acl_bucket = std::env::var("GSUTIL_TEST_ACL_BUCKET")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                s.trim_start_matches("gs://")
                    .trim_end_matches('/')
                    .to_string()
            });
        let sa_key_path = std::env::var("GSUTIL_TEST_SA_KEY")
            .ok()
            .filter(|s| !s.trim().is_empty());
        Self {
            ubla_bucket: ubla,
            acl_bucket,
            versioned_bucket: env_or(
                "GSUTIL_TEST_VERSIONED_BUCKET",
                format!("{project}-ver"),
            ),
            dual_bucket: env_or("GSUTIL_TEST_DUAL_BUCKET", format!("{project}-dual")),
            rp_bucket: env_or("GSUTIL_TEST_RP_BUCKET", format!("{project}-rp")),
            ret_bucket: env_or("GSUTIL_TEST_RET_BUCKET", format!("{project}-ret")),
            pubsub_topic: std::env::var("GSUTIL_TEST_PUBSUB_TOPIC").unwrap_or_else(|_| {
                format!("projects/{project}/topics/gsutil-rs-notif-topic")
            }),
            kms_key: std::env::var("GSUTIL_TEST_KMS_KEY").unwrap_or_else(|_| {
                format!("projects/{project}/locations/us/keyRings/gsutil-rs-kr/cryptoKeys/gsutil-rs-key")
            }),
            hmac_sa: std::env::var("GSUTIL_TEST_HMAC_SA")
                .unwrap_or_else(|_| format!("gsutil-rs-tester@{project}.iam.gserviceaccount.com")),
            sa_key_path,
            project,
        }
    }
}

/// Run true differential live GCS tests across all provisioned bucket topologies.
pub fn run_live_gcs_suite(
    runner: &GsutilRunner,
    bucket: &str,
    filter: Option<&str>,
) -> Vec<CaseResult> {
    let topo = LiveTopology::from_env(bucket);
    let mut results = Vec::new();
    let run_id = chrono::Utc::now().format("%Y%m%d%H%M%S").to_string();
    let py_pfx = format!("py-{run_id}");
    let rs_pfx = format!("rs-{run_id}");

    let tmp = TempDir::new().expect("temp dir");

    // Realistic payloads: 0-byte, 1 B, 64 KiB random binary, 9 MiB (>8 MiB resumable!), gzip text
    let p_empty: &[u8] = b"";
    let p_one: &[u8] = b"X";
    let p_text1 = b"gsutil-rs live differential payload 0123456789\n";
    let p_text2 = b"second-compose-segment-abcdefghij\n";
    let p_rand64k = seeded_random_bytes(0xDEAD_BEEF, 64 * 1024);
    let p_rand9m = seeded_random_bytes(0xCAFE_BABE, 9 * 1024 * 1024);
    let p_gzip = b"compressible live gzip verification payload 0123456789\n".repeat(128);

    let f_empty = tmp.path().join("empty.bin");
    let f_one = tmp.path().join("one.bin");
    let f_text1 = tmp.path().join("obj1.txt");
    let f_text2 = tmp.path().join("obj2.txt");
    let f_rand64k = tmp.path().join("rand64k.bin");
    let f_rand9m = tmp.path().join("rand9m.bin");
    let f_gzip = tmp.path().join("gzipped.txt");
    std::fs::write(&f_empty, p_empty).unwrap();
    std::fs::write(&f_one, p_one).unwrap();
    std::fs::write(&f_text1, p_text1).unwrap();
    std::fs::write(&f_text2, p_text2).unwrap();
    std::fs::write(&f_rand64k, &p_rand64k).unwrap();
    std::fs::write(&f_rand9m, &p_rand9m).unwrap();
    std::fs::write(&f_gzip, &p_gzip).unwrap();

    let ctx = NormalizeContext::default()
        .with_temp_path(tmp.path().to_string_lossy())
        .with_replacement(&py_pfx, "<PFX>")
        .with_replacement(&rs_pfx, "<PFX>")
        .strip_ui();

    // Helper: runs Python with `-o GSUtil:use_gcloud_storage=True` on `py-<id>` vs Rust on `rs-<id>`.
    let run_diff_live = |results: &mut Vec<CaseResult>,
                         id: &str,
                         cmd: &str,
                         ref_args: Vec<String>,
                         rust_args: Vec<String>,
                         stdout_rule: CompareRule,
                         stderr_rule: CompareRule| {
        if !matches_filter(filter, id, "live_gcs", cmd) {
            return;
        }
        let mut full_ref = vec![
            "-o".to_string(),
            "GSUtil:use_gcloud_storage=True".to_string(),
        ];
        full_ref.extend(ref_args);
        let ref_opts = RunOptions::new(full_ref);
        let rust_opts = RunOptions::new(rust_args);
        results.push(runner.run_diff(
            id,
            "live_gcs",
            cmd,
            &ref_opts,
            &rust_opts,
            &stdout_rule,
            &stderr_rule,
            &ctx,
        ));
    };

    let py_base = format!("gs://{}/{}", topo.ubla_bucket, py_pfx);
    let rs_base = format!("gs://{}/{}", topo.ubla_bucket, rs_pfx);

    // -------------------------------------------------------------------------
    // 1. Standard UBLA Bucket: Realistic Payloads (0B, 1B, 64KiB, 9MiB, gzip -Z, Unicode)
    // -------------------------------------------------------------------------
    for (id, file, obj_name) in [
        ("live_cp_upload_0b", &f_empty, "empty.bin"),
        ("live_cp_upload_1b", &f_one, "one.bin"),
        ("live_cp_upload_text1", &f_text1, "obj1.txt"),
        ("live_cp_upload_text2", &f_text2, "obj2.txt"),
        ("live_cp_upload_64k_binary", &f_rand64k, "rand64k.bin"),
        ("live_cp_upload_9m_resumable", &f_rand9m, "rand9m.bin"),
        (
            "live_cp_upload_unicode_spaces",
            &f_text1,
            "café résumé file.txt",
        ),
    ] {
        let f_s = file.to_string_lossy().into_owned();
        run_diff_live(
            &mut results,
            id,
            "cp",
            vec!["cp".into(), f_s.clone(), format!("{py_base}/{obj_name}")],
            vec!["cp".into(), f_s, format!("{rs_base}/{obj_name}")],
            CompareRule::Exact,
            CompareRule::Ignore,
        );
    }

    // Gzip -Z upload + download byte-for-byte verification (isolated `-gz` prefix so du sizes stay identical)
    let py_gz = format!("gs://{}/{}-gz/gzipped.txt", topo.ubla_bucket, py_pfx);
    let rs_gz = format!("gs://{}/{}-gz/gzipped.txt", topo.ubla_bucket, rs_pfx);
    run_diff_live(
        &mut results,
        "live_cp_gzip_upload",
        "cp",
        vec![
            "cp".into(),
            "-Z".into(),
            f_gzip.to_string_lossy().into_owned(),
            py_gz.clone(),
        ],
        vec![
            "cp".into(),
            "-Z".into(),
            f_gzip.to_string_lossy().into_owned(),
            rs_gz.clone(),
        ],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    if matches_filter(filter, "live_cp_gzip_download", "live_gcs", "cp") {
        let py_dl: PathBuf = tmp.path().join("live_gz_py.txt");
        let rs_dl: PathBuf = tmp.path().join("live_gz_rs.txt");
        let ref_opts = RunOptions::new([
            "-o",
            "GSUtil:use_gcloud_storage=True",
            "cp",
            &py_gz,
            &py_dl.to_string_lossy(),
        ]);
        let rust_opts = RunOptions::new(["cp", &rs_gz, &rs_dl.to_string_lossy()]);
        let mut res = runner.run_diff(
            "live_cp_gzip_download",
            "live_gcs",
            "cp",
            &ref_opts,
            &rust_opts,
            &CompareRule::Exact,
            &CompareRule::Ignore,
            &ctx,
        );
        if !res.skipped && res.passed {
            let py_b = std::fs::read(&py_dl).ok();
            let rs_b = std::fs::read(&rs_dl).ok();
            if py_b.as_deref() != Some(p_gzip.as_slice())
                || rs_b.as_deref() != Some(p_gzip.as_slice())
            {
                res.passed = false;
                res.side_effect_error =
                    Some("live gzip download bytes do not match original".into());
            }
        }
        results.push(res);
    }

    // Download 9 MiB binary and verify exact byte parity!
    if matches_filter(filter, "live_cp_download_9m_resumable", "live_gcs", "cp") {
        let py_dl: PathBuf = tmp.path().join("dl_9m_py.bin");
        let rs_dl: PathBuf = tmp.path().join("dl_9m_rs.bin");
        let ref_opts = RunOptions::new([
            "-o",
            "GSUtil:use_gcloud_storage=True",
            "cp",
            &format!("{py_base}/rand9m.bin"),
            &py_dl.to_string_lossy(),
        ]);
        let rust_opts = RunOptions::new([
            "cp",
            &format!("{rs_base}/rand9m.bin"),
            &rs_dl.to_string_lossy(),
        ]);
        let mut res = runner.run_diff(
            "live_cp_download_9m_resumable",
            "live_gcs",
            "cp",
            &ref_opts,
            &rust_opts,
            &CompareRule::Exact,
            &CompareRule::Ignore,
            &ctx,
        );
        if !res.skipped && res.passed {
            let py_b = std::fs::read(&py_dl).ok();
            let rs_b = std::fs::read(&rs_dl).ok();
            if py_b.as_deref() != Some(p_rand9m.as_slice())
                || rs_b.as_deref() != Some(p_rand9m.as_slice())
            {
                res.passed = false;
                res.side_effect_error =
                    Some("live 9 MiB download bytes do not match uploaded bytes".into());
            }
        }
        results.push(res);
    }

    // Parallel composite upload (>5M threshold) + sliced download (>5M threshold) on 9 MiB binary!
    let comp_obj = format!(
        "gs://{}/{}-comp/rand9m_composite.bin",
        topo.ubla_bucket, rs_pfx
    );
    if matches_filter(
        filter,
        "live_cp_parallel_composite_and_sliced_9m",
        "live_gcs",
        "cp",
    ) {
        let comp_dl: PathBuf = tmp.path().join("dl_9m_sliced_rs.bin");
        let up_opts = RunOptions::new([
            "-o",
            "GSUtil:parallel_composite_upload_threshold=5M",
            "cp",
            &f_rand9m.to_string_lossy(),
            &comp_obj,
        ]);
        let up_res = runner.run_rust_contract(
            "live_cp_parallel_composite_upload_9m",
            "live_gcs",
            "cp",
            &up_opts,
            0,
            "",
            &CompareRule::Exact,
            "",
            &CompareRule::Ignore,
            &ctx,
        );
        let up_ok = up_res.passed;
        results.push(up_res);

        let dl_opts = RunOptions::new([
            "-o",
            "GSUtil:sliced_object_download_threshold=5M",
            "cp",
            &comp_obj,
            &comp_dl.to_string_lossy(),
        ]);
        let mut dl_res = runner.run_rust_contract(
            "live_cp_sliced_download_9m",
            "live_gcs",
            "cp",
            &dl_opts,
            0,
            "",
            &CompareRule::Exact,
            "",
            &CompareRule::Ignore,
            &ctx,
        );
        if up_ok && !dl_res.skipped && dl_res.passed {
            let got = std::fs::read(&comp_dl).ok();
            if got.as_deref() != Some(p_rand9m.as_slice()) {
                dl_res.passed = false;
                dl_res.side_effect_error =
                    Some("9 MiB composite/sliced roundtrip bytes do not match!".into());
            }
        }
        results.push(dl_res);
    }

    // Listing, stat, cat (incl. multi-object -r), hash (-c, -m, -h), du
    run_diff_live(
        &mut results,
        "live_ls_prefix",
        "ls",
        vec!["ls".into(), format!("{py_base}/")],
        vec!["ls".into(), format!("{rs_base}/")],
        CompareRule::Normalized,
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_ls_long",
        "ls",
        vec!["ls".into(), "-l".into(), format!("{py_base}/obj1.txt")],
        vec!["ls".into(), "-l".into(), format!("{rs_base}/obj1.txt")],
        CompareRule::Normalized,
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_cat_full",
        "cat",
        vec!["cat".into(), format!("{py_base}/obj1.txt")],
        vec!["cat".into(), format!("{rs_base}/obj1.txt")],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_cat_range_multi_object",
        "cat",
        vec![
            "cat".into(),
            "-r".into(),
            "0-4".into(),
            format!("{py_base}/obj1.txt"),
            format!("{py_base}/obj2.txt"),
        ],
        vec![
            "cat".into(),
            "-r".into(),
            "0-4".into(),
            format!("{rs_base}/obj1.txt"),
            format!("{rs_base}/obj2.txt"),
        ],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_hash_base64",
        "hash",
        vec!["hash".into(), format!("{py_base}/obj1.txt")],
        vec!["hash".into(), format!("{rs_base}/obj1.txt")],
        CompareRule::ContainsAll(vec!["Hash (md5):".into(), "Hash (crc32c):".into()]),
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_hash_crc32c_only",
        "hash",
        vec!["hash".into(), "-c".into(), format!("{py_base}/obj1.txt")],
        vec!["hash".into(), "-c".into(), format!("{rs_base}/obj1.txt")],
        CompareRule::ContainsAll(vec!["Hash (crc32c):".into()]),
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_hash_md5_only",
        "hash",
        vec!["hash".into(), "-m".into(), format!("{py_base}/obj1.txt")],
        vec!["hash".into(), "-m".into(), format!("{rs_base}/obj1.txt")],
        CompareRule::ContainsAll(vec!["Hash (md5):".into()]),
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_du_prefix",
        "du",
        vec!["du".into(), format!("{py_base}/")],
        vec!["du".into(), format!("{rs_base}/")],
        CompareRule::ContainsAll(vec![
            "0            gs://".into(),
            "65536        gs://".into(),
            "9437184      gs://".into(),
        ]),
        CompareRule::Ignore,
    );

    // Compose + setmeta set/remove + mv + cloud rsync
    run_diff_live(
        &mut results,
        "live_compose",
        "compose",
        vec![
            "compose".into(),
            format!("{py_base}/obj1.txt"),
            format!("{py_base}/obj2.txt"),
            format!("{py_base}/composed.txt"),
        ],
        vec![
            "compose".into(),
            format!("{rs_base}/obj1.txt"),
            format!("{rs_base}/obj2.txt"),
            format!("{rs_base}/composed.txt"),
        ],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_cat_composed",
        "cat",
        vec!["cat".into(), format!("{py_base}/composed.txt")],
        vec!["cat".into(), format!("{rs_base}/composed.txt")],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_setmeta_set",
        "setmeta",
        vec![
            "setmeta".into(),
            "-h".into(),
            "x-goog-meta-parity:v1".into(),
            format!("{py_base}/obj1.txt"),
        ],
        vec![
            "setmeta".into(),
            "-h".into(),
            "x-goog-meta-parity:v1".into(),
            format!("{rs_base}/obj1.txt"),
        ],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_setmeta_remove",
        "setmeta",
        vec![
            "setmeta".into(),
            "-h".into(),
            "x-goog-meta-parity".into(),
            format!("{py_base}/obj1.txt"),
        ],
        vec![
            "setmeta".into(),
            "-h".into(),
            "x-goog-meta-parity".into(),
            format!("{rs_base}/obj1.txt"),
        ],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_stat_after_setmeta_remove",
        "stat",
        vec!["stat".into(), format!("{py_base}/obj1.txt")],
        vec!["stat".into(), format!("{rs_base}/obj1.txt")],
        CompareRule::ContainsAll(vec!["Content-Length:".into()]),
        CompareRule::Ignore,
    );

    // Cloud rsync: local tree -> GCS prefix, then GCS -> GCS
    let rsync_src = tmp.path().join("rsync_src");
    std::fs::create_dir_all(rsync_src.join("sub")).unwrap();
    std::fs::write(rsync_src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(rsync_src.join("sub/b.txt"), b"beta").unwrap();
    std::fs::write(rsync_src.join("skip.tmp"), b"ignored").unwrap();
    let rsync_src_s = rsync_src.to_string_lossy().into_owned();

    run_diff_live(
        &mut results,
        "live_rsync_local_to_gcs",
        "rsync",
        vec![
            "rsync".into(),
            "-r".into(),
            "-d".into(),
            "-x".into(),
            r".*\.tmp$".into(),
            rsync_src_s.clone(),
            format!("{py_base}/synced"),
        ],
        vec![
            "rsync".into(),
            "-r".into(),
            "-d".into(),
            "-x".into(),
            r".*\.tmp$".into(),
            rsync_src_s,
            format!("{rs_base}/synced"),
        ],
        CompareRule::Exact,
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_ls_after_rsync",
        "ls",
        vec!["ls".into(), "-r".into(), format!("{py_base}/synced/")],
        vec!["ls".into(), "-r".into(), format!("{rs_base}/synced/")],
        CompareRule::Normalized,
        CompareRule::Ignore,
    );

    // Bucket config getters on UBLA bucket (Bug #7 live verification!)
    let ubla_uri = format!("gs://{}", topo.ubla_bucket);
    for (id, cmd, args) in [
        (
            "live_defstorageclass_get",
            "defstorageclass",
            vec!["defstorageclass".into(), "get".into(), ubla_uri.clone()],
        ),
        (
            "live_ubla_get",
            "ubla",
            vec!["ubla".into(), "get".into(), ubla_uri.clone()],
        ),
        (
            "live_pap_get",
            "pap",
            vec!["pap".into(), "get".into(), ubla_uri.clone()],
        ),
        (
            "live_iam_get",
            "iam",
            vec!["iam".into(), "get".into(), ubla_uri.clone()],
        ),
    ] {
        let rule = if id == "live_ubla_get" {
            CompareRule::ContainsAll(vec!["Enabled: True".into(), "LockedTime:".into()])
        } else {
            CompareRule::Normalized
        };
        run_diff_live(
            &mut results,
            id,
            cmd,
            args.clone(),
            args,
            rule,
            CompareRule::Ignore,
        );
    }
    // Verify acl get fails under UBLA
    run_diff_live(
        &mut results,
        "live_acl_ubla_rejected",
        "acl",
        vec!["acl".into(), "get".into(), ubla_uri.clone()],
        vec!["acl".into(), "get".into(), ubla_uri.clone()],
        CompareRule::Exact,
        CompareRule::Ignore,
    );

    // -------------------------------------------------------------------------
    // 2. Versioned Bucket (`<project>-ver`): ls -a, du -a, rm -a
    // -------------------------------------------------------------------------
    let ver_py = format!("gs://{}/{}", topo.versioned_bucket, py_pfx);
    let ver_rs = format!("gs://{}/{}", topo.versioned_bucket, rs_pfx);
    for (id, file) in [
        ("live_ver_upload_v1", &f_text1),
        ("live_ver_upload_v2", &f_text2),
    ] {
        let f_s = file.to_string_lossy().into_owned();
        run_diff_live(
            &mut results,
            id,
            "cp",
            vec!["cp".into(), f_s.clone(), format!("{ver_py}/v.txt")],
            vec!["cp".into(), f_s, format!("{ver_rs}/v.txt")],
            CompareRule::Exact,
            CompareRule::Ignore,
        );
    }
    run_diff_live(
        &mut results,
        "live_ver_ls_all_versions",
        "ls",
        vec!["ls".into(), "-a".into(), format!("{ver_py}/v.txt")],
        vec!["ls".into(), "-a".into(), format!("{ver_rs}/v.txt")],
        CompareRule::Normalized,
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_ver_rm_all_versions",
        "rm",
        vec!["rm".into(), "-a".into(), format!("{ver_py}/v.txt")],
        vec!["rm".into(), "-a".into(), format!("{ver_rs}/v.txt")],
        CompareRule::Exact,
        CompareRule::Ignore,
    );

    // -------------------------------------------------------------------------
    // 3. Dual-Region Bucket (`<project>-dual`): rpo get/set
    // -------------------------------------------------------------------------
    let dual_uri = format!("gs://{}", topo.dual_bucket);
    run_diff_live(
        &mut results,
        "live_dual_rpo_get",
        "rpo",
        vec!["rpo".into(), "get".into(), dual_uri.clone()],
        vec!["rpo".into(), "get".into(), dual_uri.clone()],
        CompareRule::Normalized,
        CompareRule::Ignore,
    );

    // -------------------------------------------------------------------------
    // 4. Requester Pays Bucket (`<project>-rp`): -u succeeds, no -u fails in Rust
    // -------------------------------------------------------------------------
    let rp_uri = format!("gs://{}", topo.rp_bucket);
    if matches_filter(filter, "live_rp_ls_without_u_fails", "live_gcs", "ls") {
        let opts = RunOptions::new(["ls", "-b", &rp_uri]);
        results.push(runner.run_rust_contract(
            "live_rp_ls_without_u_fails",
            "live_gcs",
            "ls",
            &opts,
            1,
            "",
            &CompareRule::Exact,
            "BadRequestException: 400",
            &CompareRule::ErrorClass {
                required_substrings: vec!["400".into()],
            },
            &ctx,
        ));
    }
    run_diff_live(
        &mut results,
        "live_rp_ls_with_u_succeeds",
        "ls",
        vec![
            "-u".into(),
            topo.project.clone(),
            "ls".into(),
            "-b".into(),
            rp_uri.clone(),
        ],
        vec![
            "-u".into(),
            topo.project.clone(),
            "ls".into(),
            "-b".into(),
            rp_uri.clone(),
        ],
        CompareRule::Normalized,
        CompareRule::Ignore,
    );

    // -------------------------------------------------------------------------
    // 5. Retention Bucket (`<project>-ret`): exact native gsutil format
    // -------------------------------------------------------------------------
    let ret_uri = format!("gs://{}", topo.ret_bucket);
    if matches_filter(filter, "live_ret_get_initial", "live_gcs", "retention") {
        let opts = RunOptions::new(["retention", "get", &ret_uri]);
        results.push(runner.run_rust_contract(
            "live_ret_get_initial",
            "live_gcs",
            "retention",
            &opts,
            0,
            &format!("{ret_uri}/ has no Retention Policy.\n"),
            &CompareRule::Exact,
            "",
            &CompareRule::Exact,
            &ctx,
        ));
    }

    // -------------------------------------------------------------------------
    // 6. KMS, Pub/Sub Notification, HMAC (live read/list checks)
    // -------------------------------------------------------------------------
    run_diff_live(
        &mut results,
        "live_kms_serviceaccount",
        "kms",
        vec![
            "kms".into(),
            "serviceaccount".into(),
            "-p".into(),
            topo.project.clone(),
        ],
        vec![
            "kms".into(),
            "serviceaccount".into(),
            "-p".into(),
            topo.project.clone(),
        ],
        CompareRule::ContainsAll(vec!["@gs-project-accounts.iam.gserviceaccount.com".into()]),
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_notification_list",
        "notification",
        vec!["notification".into(), "list".into(), ubla_uri.clone()],
        vec!["notification".into(), "list".into(), ubla_uri.clone()],
        CompareRule::Normalized,
        CompareRule::Ignore,
    );
    run_diff_live(
        &mut results,
        "live_hmac_list",
        "hmac",
        vec![
            "hmac".into(),
            "list".into(),
            "-p".into(),
            topo.project.clone(),
            "-u".into(),
            topo.hmac_sa.clone(),
        ],
        vec![
            "hmac".into(),
            "list".into(),
            "-p".into(),
            topo.project.clone(),
            "-u".into(),
            topo.hmac_sa.clone(),
        ],
        CompareRule::Normalized,
        CompareRule::Ignore,
    );
    // 6b. Real Cloud KMS / CMEK lifecycle (authorize, bucket default key, CMEK cp/stat/rewrite)
    if matches_filter(filter, "live_kms_authorize", "live_gcs", "kms") {
        let opts = RunOptions::new(["kms", "authorize", "-p", &topo.project, "-k", &topo.kms_key]);
        results.push(runner.run_rust_contract(
            "live_kms_authorize",
            "live_gcs",
            "kms",
            &opts,
            0,
            "",
            &CompareRule::Ignore,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
    }
    if matches_filter(filter, "live_kms_encryption_lifecycle", "live_gcs", "kms") {
        let set_opts = RunOptions::new(["kms", "encryption", "-k", &topo.kms_key, &ret_uri]);
        results.push(runner.run_rust_contract(
            "live_kms_encryption_set",
            "live_gcs",
            "kms",
            &set_opts,
            0,
            "",
            &CompareRule::Ignore,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let get_opts = RunOptions::new(["kms", "encryption", &ret_uri]);
        results.push(runner.run_rust_contract(
            "live_kms_encryption_get",
            "live_gcs",
            "kms",
            &get_opts,
            0,
            &topo.kms_key,
            &CompareRule::ContainsAll(vec![topo.kms_key.clone()]),
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let clr_opts = RunOptions::new(["kms", "encryption", "-d", &ret_uri]);
        results.push(runner.run_rust_contract(
            "live_kms_encryption_clear",
            "live_gcs",
            "kms",
            &clr_opts,
            0,
            "",
            &CompareRule::Ignore,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
    }
    if matches_filter(filter, "live_cmek_cp_stat_rewrite", "live_gcs", "cp") {
        let cmek_obj = format!("{rs_base}/cmek.bin");
        let cmek_dl = tmp.path().join("cmek_dl.bin");
        let up_opts = RunOptions::new([
            "-o",
            &format!("GSUtil:encryption_key={}", topo.kms_key),
            "cp",
            f_text1.to_str().unwrap(),
            &cmek_obj,
        ]);
        results.push(runner.run_rust_contract(
            "live_cmek_cp_upload",
            "live_gcs",
            "cp",
            &up_opts,
            0,
            "",
            &CompareRule::Ignore,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let st_opts = RunOptions::new(["stat", &cmek_obj]);
        let expected_stat = format!("KMS key: {}", topo.kms_key);
        results.push(runner.run_rust_contract(
            "live_cmek_stat",
            "live_gcs",
            "stat",
            &st_opts,
            0,
            &expected_stat,
            &CompareRule::ContainsAll(vec!["KMS key:".into(), topo.kms_key.clone()]),
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let dl_opts = RunOptions::new(["cp", &cmek_obj, cmek_dl.to_str().unwrap()]);
        results.push(runner.run_rust_contract(
            "live_cmek_cp_download",
            "live_gcs",
            "cp",
            &dl_opts,
            0,
            "",
            &CompareRule::Ignore,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let rw_opts = RunOptions::new(["rewrite", "-k", &cmek_obj]);
        results.push(runner.run_rust_contract(
            "live_cmek_rewrite_decrypt",
            "live_gcs",
            "rewrite",
            &rw_opts,
            0,
            "",
            &CompareRule::Ignore,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
    }
    // 6c. Real Pub/Sub Notification create / list / delete lifecycle
    if matches_filter(
        filter,
        "live_notification_lifecycle",
        "live_gcs",
        "notification",
    ) {
        let cr_opts = RunOptions::new([
            "notification",
            "create",
            "-t",
            &topo.pubsub_topic,
            "-f",
            "json",
            &ret_uri,
        ]);
        results.push(runner.run_rust_contract(
            "live_notification_create",
            "live_gcs",
            "notification",
            &cr_opts,
            0,
            "",
            &CompareRule::Ignore,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let ls_opts = RunOptions::new(["notification", "list", &ret_uri]);
        results.push(runner.run_rust_contract(
            "live_notification_list_after_create",
            "live_gcs",
            "notification",
            &ls_opts,
            0,
            &topo.pubsub_topic,
            &CompareRule::ContainsAll(vec![topo.pubsub_topic.clone()]),
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let del_opts = RunOptions::new(["notification", "delete", &ret_uri]);
        results.push(runner.run_rust_contract(
            "live_notification_delete",
            "live_gcs",
            "notification",
            &del_opts,
            0,
            "",
            &CompareRule::Ignore,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
    }

    // -------------------------------------------------------------------------
    // 6d. Live Non-UBLA Fine-Grained ACLs (requires GSUTIL_TEST_ACL_BUCKET)
    // -------------------------------------------------------------------------
    if let Some(ref acl_bkt) = topo.acl_bucket {
        let acl_uri = format!("gs://{acl_bkt}");
        if matches_filter(filter, "live_acl_lifecycle", "live_gcs", "acl") {
            let get_opts = RunOptions::new(["acl", "get", &acl_uri]);
            results.push(runner.run_rust_contract(
                "live_acl_get",
                "live_gcs",
                "acl",
                &get_opts,
                0,
                "\"role\"",
                &CompareRule::ContainsAll(vec!["\"role\"".into()]),
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let set_opts = RunOptions::new(["acl", "set", "private", &acl_uri]);
            results.push(runner.run_rust_contract(
                "live_acl_set_private",
                "live_gcs",
                "acl",
                &set_opts,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let grant_spec = format!("{}:R", topo.hmac_sa);
            let ch_add = RunOptions::new(["acl", "ch", "-u", &grant_spec, &acl_uri]);
            results.push(runner.run_rust_contract(
                "live_acl_ch_grant",
                "live_gcs",
                "acl",
                &ch_add,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let verify_add = RunOptions::new(["acl", "get", &acl_uri]);
            results.push(runner.run_rust_contract(
                "live_acl_get_after_grant",
                "live_gcs",
                "acl",
                &verify_add,
                0,
                &topo.hmac_sa,
                &CompareRule::ContainsAll(vec![topo.hmac_sa.clone()]),
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let ch_del = RunOptions::new(["acl", "ch", "-d", &topo.hmac_sa, &acl_uri]);
            results.push(runner.run_rust_contract(
                "live_acl_ch_remove",
                "live_gcs",
                "acl",
                &ch_del,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
        }
        if matches_filter(filter, "live_defacl_lifecycle", "live_gcs", "defacl") {
            let def_get = RunOptions::new(["defacl", "get", &acl_uri]);
            results.push(runner.run_rust_contract(
                "live_defacl_get",
                "live_gcs",
                "defacl",
                &def_get,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let def_set = RunOptions::new(["defacl", "set", "private", &acl_uri]);
            results.push(runner.run_rust_contract(
                "live_defacl_set_private",
                "live_gcs",
                "defacl",
                &def_set,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let grant_spec = format!("{}:R", topo.hmac_sa);
            let def_ch_add = RunOptions::new(["defacl", "ch", "-u", &grant_spec, &acl_uri]);
            results.push(runner.run_rust_contract(
                "live_defacl_ch_grant",
                "live_gcs",
                "defacl",
                &def_ch_add,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let def_ch_del = RunOptions::new(["defacl", "ch", "-d", &topo.hmac_sa, &acl_uri]);
            results.push(runner.run_rust_contract(
                "live_defacl_ch_remove",
                "live_gcs",
                "defacl",
                &def_ch_del,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
        }
        if matches_filter(filter, "live_cp_acl_preserve", "live_gcs", "cp") {
            let acl_obj = format!("gs://{acl_bkt}/{rs_pfx}/acl_obj.txt");
            let acl_obj2 = format!("gs://{acl_bkt}/{rs_pfx}/acl_obj_copy.txt");
            let up_a =
                RunOptions::new(["cp", "-a", "private", f_text1.to_str().unwrap(), &acl_obj]);
            results.push(runner.run_rust_contract(
                "live_cp_canned_acl_private",
                "live_gcs",
                "cp",
                &up_a,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let cp_p = RunOptions::new(["cp", "-p", &acl_obj, &acl_obj2]);
            results.push(runner.run_rust_contract(
                "live_cp_preserve_acl",
                "live_gcs",
                "cp",
                &cp_p,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let _ = runner.run_rust(&RunOptions::new(["rm", "-f", &acl_obj, &acl_obj2]));
        }
    }

    // -------------------------------------------------------------------------
    // 6e. Live HMAC CRUD + Real Live GCS XML (-o GSUtil:prefer_api=xml)
    // -------------------------------------------------------------------------
    if topo.sa_key_path.is_some()
        && matches_filter(filter, "live_hmac_xml_lifecycle", "live_gcs", "hmac")
    {
        let create_out = runner
            .run_rust(&RunOptions::new([
                "hmac",
                "create",
                "-p",
                &topo.project,
                &topo.hmac_sa,
            ]))
            .expect("run rust hmac create");
        let access_id = create_out
            .stdout
            .lines()
            .find_map(|l| l.strip_prefix("Access ID:"))
            .map(|s| s.trim().to_string());
        let secret = create_out
            .stdout
            .lines()
            .find_map(|l| l.strip_prefix("Secret:"))
            .map(|s| s.trim().to_string());
        let mut diffs = Vec::new();
        if create_out.exit_code != 0 || access_id.is_none() || secret.is_none() {
            diffs.push(format!(
                "hmac create failed (exit={}): stdout={} stderr={}",
                create_out.exit_code, create_out.stdout, create_out.stderr
            ));
        }
        results.push(CaseResult {
            id: "live_hmac_create".into(),
            category: "live_gcs".into(),
            command: "hmac".into(),
            args: vec!["hmac".into(), "create".into()],
            passed: diffs.is_empty(),
            skipped: false,
            skip_reason: None,
            exit_code_match: create_out.exit_code == 0,
            ref_output: None,
            rust_output: Some(create_out),
            stdout_cmp: None,
            stderr_cmp: None,
            side_effect_error: if diffs.is_empty() {
                None
            } else {
                Some(diffs.join("; "))
            },
        });

        if let (Some(aid), Some(sec)) = (access_id, secret) {
            let get_opts = RunOptions::new(["hmac", "get", "-p", &topo.project, &aid]);
            let expected_hmac_get = format!("{aid} ACTIVE");
            results.push(runner.run_rust_contract(
                "live_hmac_get",
                "live_gcs",
                "hmac",
                &get_opts,
                0,
                &expected_hmac_get,
                &CompareRule::ContainsAll(vec![aid.clone(), "ACTIVE".into()]),
                "",
                &CompareRule::Ignore,
                &ctx,
            ));

            // Real live GCS XML API roundtrip using the newly created HMAC key!
            let xml_boto = tmp.path().join("hmac_xml.boto");
            let boto_txt = format!(
                "[Credentials]\ngs_access_key_id = {aid}\ngs_secret_access_key = {sec}\n\
                 [GSUtil]\nprefer_api = xml\ndefault_project_id = {}\n",
                topo.project
            );
            std::fs::write(&xml_boto, boto_txt).expect("write xml boto");
            let xml_obj = format!("{rs_base}/xml_hmac_test.txt");

            let xml_cp = RunOptions::new(["cp", f_text1.to_str().unwrap(), &xml_obj])
                .with_boto_config(&xml_boto);
            results.push(runner.run_rust_contract(
                "live_xml_hmac_cp_upload",
                "live_gcs",
                "cp",
                &xml_cp,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let xml_ls = RunOptions::new(["ls", &xml_obj]).with_boto_config(&xml_boto);
            results.push(runner.run_rust_contract(
                "live_xml_hmac_ls",
                "live_gcs",
                "ls",
                &xml_ls,
                0,
                "xml_hmac_test.txt",
                &CompareRule::ContainsAll(vec!["xml_hmac_test.txt".into()]),
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let xml_cat = RunOptions::new(["cat", &xml_obj]).with_boto_config(&xml_boto);
            let expected_text1 = String::from_utf8_lossy(p_text1).into_owned();
            results.push(runner.run_rust_contract(
                "live_xml_hmac_cat",
                "live_gcs",
                "cat",
                &xml_cat,
                0,
                &expected_text1,
                &CompareRule::Exact,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let xml_rm = RunOptions::new(["rm", &xml_obj]).with_boto_config(&xml_boto);
            results.push(runner.run_rust_contract(
                "live_xml_hmac_rm",
                "live_gcs",
                "rm",
                &xml_rm,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));

            // Always deactivate and delete the HMAC key!
            let deact = RunOptions::new([
                "hmac",
                "update",
                "-p",
                &topo.project,
                "-s",
                "INACTIVE",
                &aid,
            ]);
            results.push(runner.run_rust_contract(
                "live_hmac_deactivate",
                "live_gcs",
                "hmac",
                &deact,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
            let del = RunOptions::new(["hmac", "delete", "-p", &topo.project, &aid]);
            results.push(runner.run_rust_contract(
                "live_hmac_delete",
                "live_gcs",
                "hmac",
                &del,
                0,
                "",
                &CompareRule::Ignore,
                "",
                &CompareRule::Ignore,
                &ctx,
            ));
        }
    }

    // -------------------------------------------------------------------------
    // 6f. Live `signurl` V4 & V2 with REAL HTTP PUT & GET against storage.googleapis.com
    // -------------------------------------------------------------------------
    if let Some(ref sa_key) = topo.sa_key_path {
        if matches_filter(filter, "live_signurl_http_v4_v2", "live_gcs", "signurl") {
            let signed_obj = format!("{rs_base}/signed_v4_live.txt");
            let payload = b"gsutil-rs live signed URL PUT/GET verification 0123456789\n";
            let payload_file = tmp.path().join("signed_payload.txt");
            std::fs::write(&payload_file, payload).expect("write signed payload");

            let extract_https_url = |stdout: &str| -> Option<String> {
                stdout.split_whitespace().find_map(|tok| {
                    if tok.starts_with("https://storage.googleapis.com/") {
                        Some(tok.to_string())
                    } else {
                        None
                    }
                })
            };

            // V4 PUT + real HTTP PUT
            let put_sign = runner
                .run_rust(&RunOptions::new([
                    "signurl",
                    "-v",
                    "4",
                    "-m",
                    "PUT",
                    "-d",
                    "10m",
                    "-c",
                    "text/plain",
                    sa_key,
                    &signed_obj,
                ]))
                .expect("run signurl v4 put");
            let mut put_diffs = Vec::new();
            if put_sign.exit_code != 0 {
                put_diffs.push(format!(
                    "signurl v4 PUT exited {}: {}",
                    put_sign.exit_code, put_sign.stderr
                ));
            } else if let Some(url) = extract_https_url(&put_sign.stdout) {
                let curl = std::process::Command::new("curl")
                    .args([
                        "-sS",
                        "-o",
                        "/dev/null",
                        "-w",
                        "%{http_code}",
                        "-X",
                        "PUT",
                        "-H",
                        "Content-Type: text/plain",
                        "--data-binary",
                        &format!("@{}", payload_file.display()),
                        &url,
                    ])
                    .output()
                    .expect("curl PUT");
                let code = String::from_utf8_lossy(&curl.stdout).trim().to_string();
                if code != "200" {
                    put_diffs.push(format!(
                        "V4 signed PUT HTTP status={code} (expected 200), stderr={}",
                        String::from_utf8_lossy(&curl.stderr)
                    ));
                }
            } else {
                put_diffs.push(format!(
                    "no https URL in signurl output: {}",
                    put_sign.stdout
                ));
            }
            results.push(CaseResult {
                id: "live_signurl_v4_http_put".into(),
                category: "live_gcs".into(),
                command: "signurl".into(),
                args: vec![
                    "signurl".into(),
                    "-v".into(),
                    "4".into(),
                    "-m".into(),
                    "PUT".into(),
                ],
                passed: put_diffs.is_empty(),
                skipped: false,
                skip_reason: None,
                exit_code_match: put_sign.exit_code == 0,
                ref_output: None,
                rust_output: Some(put_sign),
                stdout_cmp: None,
                stderr_cmp: None,
                side_effect_error: if put_diffs.is_empty() {
                    None
                } else {
                    Some(put_diffs.join("; "))
                },
            });

            // V4 GET + V2 GET with real HTTP GET & exact byte verification
            for (ver, case_id) in [
                ("4", "live_signurl_v4_http_get"),
                ("2", "live_signurl_v2_http_get"),
            ] {
                let get_sign = runner
                    .run_rust(&RunOptions::new([
                        "signurl",
                        "-v",
                        ver,
                        "-m",
                        "GET",
                        "-d",
                        "10m",
                        sa_key,
                        &signed_obj,
                    ]))
                    .expect("run signurl get");
                let mut get_diffs = Vec::new();
                if get_sign.exit_code != 0 {
                    get_diffs.push(format!(
                        "signurl v{ver} GET exited {}: {}",
                        get_sign.exit_code, get_sign.stderr
                    ));
                } else if let Some(url) = extract_https_url(&get_sign.stdout) {
                    let dl_out = tmp.path().join(format!("signed_dl_v{ver}.txt"));
                    let curl = std::process::Command::new("curl")
                        .args([
                            "-sS",
                            "-o",
                            dl_out.to_str().unwrap(),
                            "-w",
                            "%{http_code}",
                            &url,
                        ])
                        .output()
                        .expect("curl GET");
                    let code = String::from_utf8_lossy(&curl.stdout).trim().to_string();
                    if code != "200" {
                        get_diffs.push(format!(
                            "V{ver} signed GET HTTP status={code} (expected 200)"
                        ));
                    } else {
                        let got = std::fs::read(&dl_out).unwrap_or_default();
                        if got != payload {
                            get_diffs.push(format!(
                                "V{ver} signed GET payload mismatch: got {} bytes vs expected {} bytes",
                                got.len(),
                                payload.len()
                            ));
                        }
                    }
                } else {
                    get_diffs.push(format!(
                        "no https URL in signurl v{ver} output: {}",
                        get_sign.stdout
                    ));
                }
                results.push(CaseResult {
                    id: case_id.into(),
                    category: "live_gcs".into(),
                    command: "signurl".into(),
                    args: vec![
                        "signurl".into(),
                        "-v".into(),
                        ver.into(),
                        "-m".into(),
                        "GET".into(),
                    ],
                    passed: get_diffs.is_empty(),
                    skipped: false,
                    skip_reason: None,
                    exit_code_match: get_sign.exit_code == 0,
                    ref_output: None,
                    rust_output: Some(get_sign),
                    stdout_cmp: None,
                    stderr_cmp: None,
                    side_effect_error: if get_diffs.is_empty() {
                        None
                    } else {
                        Some(get_diffs.join("; "))
                    },
                });
            }
            let _ = runner.run_rust(&RunOptions::new(["rm", "-f", &signed_obj]));
        }
    }

    // -------------------------------------------------------------------------
    // 6g. Live `-i` Service Account Impersonation
    // -------------------------------------------------------------------------
    if topo.sa_key_path.is_some() && matches_filter(filter, "live_impersonation", "live_gcs", "ls")
    {
        let imp_ls = RunOptions::new(["-i", &topo.hmac_sa, "ls", "-b", &ubla_uri]);
        results.push(runner.run_rust_contract(
            "live_impersonation_ls_bucket",
            "live_gcs",
            "ls",
            &imp_ls,
            0,
            &ubla_uri,
            &CompareRule::ContainsAll(vec![ubla_uri.clone()]),
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let imp_obj = format!("{rs_base}/impersonated.txt");
        let imp_cp = RunOptions::new([
            "-i",
            &topo.hmac_sa,
            "cp",
            f_text1.to_str().unwrap(),
            &imp_obj,
        ]);
        results.push(runner.run_rust_contract(
            "live_impersonation_cp_upload",
            "live_gcs",
            "cp",
            &imp_cp,
            0,
            "",
            &CompareRule::Ignore,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let imp_cat = RunOptions::new(["-i", &topo.hmac_sa, "cat", &imp_obj]);
        let expected_text1 = String::from_utf8_lossy(p_text1).into_owned();
        results.push(runner.run_rust_contract(
            "live_impersonation_cat",
            "live_gcs",
            "cat",
            &imp_cat,
            0,
            &expected_text1,
            &CompareRule::Exact,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let imp_rm = RunOptions::new(["-i", &topo.hmac_sa, "rm", &imp_obj]);
        results.push(runner.run_rust_contract(
            "live_impersonation_rm",
            "live_gcs",
            "rm",
            &imp_rm,
            0,
            "",
            &CompareRule::Ignore,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
    }

    // -------------------------------------------------------------------------
    // 6h. Live `iam` Policy Roundtrip
    // -------------------------------------------------------------------------
    if matches_filter(filter, "live_iam_roundtrip", "live_gcs", "iam") {
        let iam_get = RunOptions::new(["iam", "get", &ubla_uri]);
        results.push(runner.run_rust_contract(
            "live_iam_get",
            "live_gcs",
            "iam",
            &iam_get,
            0,
            "\"bindings\"",
            &CompareRule::ContainsAll(vec!["\"bindings\"".into()]),
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let spec = format!("serviceAccount:{}:objectViewer", topo.hmac_sa);
        let iam_add = RunOptions::new(["iam", "ch", &spec, &ubla_uri]);
        results.push(runner.run_rust_contract(
            "live_iam_ch_grant",
            "live_gcs",
            "iam",
            &iam_add,
            0,
            "",
            &CompareRule::Ignore,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let iam_verify = RunOptions::new(["iam", "get", &ubla_uri]);
        results.push(runner.run_rust_contract(
            "live_iam_get_after_grant",
            "live_gcs",
            "iam",
            &iam_verify,
            0,
            &topo.hmac_sa,
            &CompareRule::ContainsAll(vec![topo.hmac_sa.clone()]),
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
        let iam_del = RunOptions::new(["iam", "ch", "-d", &spec, &ubla_uri]);
        results.push(runner.run_rust_contract(
            "live_iam_ch_remove",
            "live_gcs",
            "iam",
            &iam_del,
            0,
            "",
            &CompareRule::Ignore,
            "",
            &CompareRule::Ignore,
            &ctx,
        ));
    }

    // -------------------------------------------------------------------------
    // 7. Cleanup all per-run prefixes (`py-*`, `rs-*`, `-gz`, `-comp`)
    // -------------------------------------------------------------------------
    let _ = runner.run_rust(&RunOptions::new([
        "-m", "rm", "-f", &py_gz, &rs_gz, &comp_obj,
    ]));
    run_diff_live(
        &mut results,
        "live_rm_cleanup",
        "rm",
        vec!["-m".into(), "rm".into(), "-r".into(), py_base],
        vec!["-m".into(), "rm".into(), "-r".into(), rs_base],
        CompareRule::Exact,
        CompareRule::Ignore,
    );

    results
}
