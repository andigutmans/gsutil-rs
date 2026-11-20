//! Unit & smoke tests for the gsutil-parity harness itself.

use gsutil_parity::mock_gcs::MockGcsServer;
use gsutil_parity::normalize::{
    compare_stream, extract_error_class, normalize_output, CompareRule, NormalizeContext,
};
use gsutil_parity::runner::{CaseResult, GsutilRunner, InvocationOutput, RunOptions};
use gsutil_parity::scorecard::ParityScorecard;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[test]
fn test_normalizer_replaces_dynamic_tokens() {
    let ctx = NormalizeContext::default()
        .with_temp_path("/tmp/xyz123")
        .with_test_bucket("my-test-bucket-99")
        .strip_ui();
    let sample = "gs://my-test-bucket-99/foo#1700000000123456\n\
                  Creation time: Mon, 01 Jan 2024 12:34:56 GMT\n\
                  Updated: 2024-01-01T12:34:56.789Z\n\
                  Generation:     1700000000123456\n\
                  File: /tmp/xyz123/a.txt\n\
                  Operation completed over 1 objects/10.0 B.\n";
    let norm = normalize_output(sample, &ctx);
    assert!(norm.contains("gs://<TEST_BUCKET>/foo#<GEN>"));
    assert!(norm.contains("Creation time: <TIMESTAMP>"));
    assert!(norm.contains("Updated: <TIMESTAMP>"));
    assert!(norm.contains("Generation:     <GEN>"));
    assert!(norm.contains("File: <TMPDIR>/a.txt"));
    assert!(!norm.contains("Operation completed over"));
}

#[test]
fn test_extract_error_class() {
    assert_eq!(
        extract_error_class("CommandException: Invalid command \"foo\".\n"),
        Some("CommandException:".into())
    );
    assert_eq!(
        extract_error_class("AccessDeniedException: 403 Forbidden\n"),
        Some("AccessDeniedException:".into())
    );
    assert_eq!(
        extract_error_class("No URLs matched: gs://b/o\n"),
        Some("No URLs matched".into())
    );
    assert_eq!(extract_error_class("all good\n"), None);
}

#[test]
fn test_compare_stream_error_class() {
    let ctx = NormalizeContext::default();
    let rule = CompareRule::ErrorClass {
        required_substrings: vec!["403".into()],
    };
    let ok = compare_stream(
        "stderr",
        "AccessDeniedException: 403 Caller does not have access",
        "AccessDeniedException: 403 Forbidden",
        &rule,
        &ctx,
    );
    assert!(ok.matched);

    let bad = compare_stream(
        "stderr",
        "AccessDeniedException: 403 Forbidden",
        "NotFoundException: 404 Not Found",
        &rule,
        &ctx,
    );
    assert!(!bad.matched);
}

async fn raw_http(addr: std::net::SocketAddr, req: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read");
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn test_mock_gcs_server_crud_range_and_faults() {
    let server = MockGcsServer::start().await.expect("start mock server");
    server.seed_bucket("bkt1");
    server.seed_object("bkt1", "hello.txt", b"0123456789");

    // 1. List objects -> 200
    let resp = raw_http(
        server.addr,
        "GET /storage/v1/b/bkt1/o HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200 OK"));
    assert!(resp.contains("\"name\":\"hello.txt\""));

    // 2. Range download -> 206 Partial Content
    let resp = raw_http(
        server.addr,
        "GET /storage/v1/b/bkt1/o/hello.txt?alt=media HTTP/1.1\r\nHost: localhost\r\nRange: bytes=1-3\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 206 Partial Content"));
    assert!(resp.ends_with("\r\n\r\n123"));

    // 3. Deterministic fault codes: 403, 404, 409, 412, 500
    for (bucket, code) in [
        ("fault-403", "403"),
        ("fault-404", "404"),
        ("fault-409", "409"),
        ("fault-412", "412"),
        ("fault-500", "500"),
    ] {
        let req = format!("GET /storage/v1/b/{bucket} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let resp = raw_http(server.addr, &req).await;
        assert!(
            resp.starts_with(&format!("HTTP/1.1 {code}")),
            "expected {code} for {bucket}, got: {resp}"
        );
    }

    // 4. Delete non-empty bucket -> 409
    let resp = raw_http(
        server.addr,
        "DELETE /storage/v1/b/bkt1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 409 Conflict"));

    // 5. Delete object -> 204, then delete bucket -> 204
    let resp = raw_http(
        server.addr,
        "DELETE /storage/v1/b/bkt1/o/hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 204 No Content"));

    let resp = raw_http(
        server.addr,
        "DELETE /storage/v1/b/bkt1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 204 No Content"));
}

#[test]
fn test_scorecard_markdown_and_json() {
    let sample = vec![CaseResult {
        id: "version_cmd".into(),
        category: "cli_dispatch".into(),
        command: "version".into(),
        args: vec!["version".into()],
        passed: true,
        skipped: false,
        skip_reason: None,
        exit_code_match: true,
        ref_output: Some(InvocationOutput {
            exit_code: 0,
            stdout: "gsutil version: 5.38\n".into(),
            stderr: String::new(),
            duration_ms: 420,
        }),
        rust_output: Some(InvocationOutput {
            exit_code: 0,
            stdout: "gsutil version: 5.38\n".into(),
            stderr: String::new(),
            duration_ms: 4,
        }),
        stdout_cmp: None,
        stderr_cmp: None,
        side_effect_error: None,
    }];
    let sc = ParityScorecard::from_results(sample);
    let md = sc.to_markdown();
    assert!(md.contains("1/1 passed (100.0%)"));
    assert!(md.contains("105.0x"));
    let json = sc.to_json_pretty().expect("json");
    assert!(json.contains("\"version_cmd\""));
}

#[test]
fn test_reference_gsutil_smoke() {
    let runner = GsutilRunner::discover();
    if !runner.ref_available() {
        return;
    }
    let out = runner
        .run_ref(&RunOptions::new(["version"]))
        .expect("run /usr/bin/gsutil version");
    assert_eq!(out.exit_code, 0);
    assert!(out.stdout.starts_with("gsutil version: "));
}
