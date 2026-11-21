use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use gsutil_auth::{AccessToken, CredentialType, HmacCredentials, NoOpCredentials, TokenProvider};
use gsutil_core::api::{
    Bucket, CloudApi, ComposeSourceObject, CopyOptions, CreateNotificationOptions,
    CsObjectOrPrefix, DownloadOptions, DownloadStrategy, EncryptionKey, IamBinding, IamPolicy,
    KmsApi, ListObjectsOptions, Object, Preconditions, PubsubApi, UploadOptions,
};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result, ServiceErrorKind};
use gsutil_gcs::client::{GcsJsonClient, GcsJsonClientConfig};
use gsutil_gcs::error_translation::{
    create_not_found_for_object_write, translate_http_error, translate_resumable_upload_error,
    ErrorContext,
};
use gsutil_gcs::iamcredentials::IamCredentialsClient;
use gsutil_gcs::kms::KmsClient;
use gsutil_gcs::pubsub::PubsubClient;
use gsutil_gcs::retry::RetryPolicy;
use gsutil_gcs::xml::XmlApiClient;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

struct StaticTokenProvider {
    token: String,
}

#[async_trait]
impl TokenProvider for StaticTokenProvider {
    async fn token(&self) -> Result<Option<AccessToken>> {
        Ok(Some(AccessToken::from_expires_in(self.token.clone(), 3600)))
    }

    fn credential_type(&self) -> CredentialType {
        CredentialType::OAuth2UserAccount
    }
}

fn mock_client(server: &MockServer) -> GcsJsonClient {
    let cfg = GcsJsonClientConfig::for_mock_server(server.uri());
    let creds = Arc::new(StaticTokenProvider {
        token: "test-bearer-token".to_string(),
    });
    GcsJsonClient::new(cfg, creds).unwrap()
}

#[tokio::test]
async fn test_list_buckets_pagination() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/storage/v1/b"))
        .and(query_param("project", "my-proj"))
        .and(header("authorization", "Bearer test-bearer-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [{ "name": "bucket-1" }],
            "nextPageToken": "page-2"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/storage/v1/b"))
        .and(query_param("project", "my-proj"))
        .and(query_param("pageToken", "page-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [{ "name": "bucket-2" }]
        })))
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let buckets = client.list_buckets(Some("my-proj"), None).await.unwrap();
    let names: Vec<_> = buckets.iter().filter_map(|b| b.name.as_deref()).collect();
    assert_eq!(names, vec!["bucket-1", "bucket-2"]);
}

#[tokio::test]
async fn test_list_objects_pagination_and_ordering() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/storage/v1/b/my-bkt/o"))
        .and(query_param("delimiter", "/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [{ "bucket": "my-bkt", "name": "a.txt", "size": "10" }],
            "prefixes": ["dir1/"],
            "nextPageToken": "tok-2"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/storage/v1/b/my-bkt/o"))
        .and(query_param("pageToken", "tok-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [{ "bucket": "my-bkt", "name": "b.txt", "size": "20" }],
            "prefixes": ["dir2/"]
        })))
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let opts = ListObjectsOptions {
        delimiter: Some("/".to_string()),
        ..Default::default()
    };
    let items = client.list_objects("my-bkt", &opts).await.unwrap();
    assert_eq!(items.len(), 4);
    // Objects come before prefixes within each page.
    assert!(matches!(&items[0], CsObjectOrPrefix::Object(o) if o.name.as_deref() == Some("a.txt")));
    assert!(matches!(&items[1], CsObjectOrPrefix::Prefix(p) if p == "dir1/"));
    assert!(matches!(&items[2], CsObjectOrPrefix::Object(o) if o.name.as_deref() == Some("b.txt")));
    assert!(matches!(&items[3], CsObjectOrPrefix::Prefix(p) if p == "dir2/"));
}

#[tokio::test]
async fn test_bucket_crud_and_versioned_not_empty() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/storage/v1/b"))
        .and(query_param("project", "test-project"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "new-bkt",
            "location": "us",
            "storageClass": "standard"
        })))
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path("/storage/v1/b/new-bkt"))
        .and(query_param("predefinedAcl", "publicRead"))
        .and(query_param("ifMetagenerationMatch", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "new-bkt",
            "metageneration": "3"
        })))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/storage/v1/b/ver-bkt"))
        .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
            "error": { "message": "The bucket you tried to delete is not empty." }
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/storage/v1/b/ver-bkt"))
        .and(query_param("fields", "versioning"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "ver-bkt",
            "versioning": { "enabled": true }
        })))
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let meta = Bucket {
        location: Some("US".to_string()),
        storage_class: Some("STANDARD".to_string()),
        ..Default::default()
    };
    let created = client
        .create_bucket("new-bkt", None, Some(&meta), None)
        .await
        .unwrap();
    assert_eq!(created.name.as_deref(), Some("new-bkt"));

    let patched = client
        .patch_bucket(
            "new-bkt",
            &Bucket::default(),
            Some("public-read"),
            None,
            Some(&Preconditions::new(None, Some(2))),
            None,
        )
        .await
        .unwrap();
    assert_eq!(patched.metageneration.as_deref(), Some("3"));

    let del_err = client.delete_bucket("ver-bkt", None).await.unwrap_err();
    match del_err {
        GsutilError::Service(se) => {
            assert_eq!(se.kind, ServiceErrorKind::NotEmpty);
            assert_eq!(se.reason, "VersionedBucketNotEmpty");
        }
        other => panic!("expected VersionedBucketNotEmpty, got {other}"),
    }
}

#[tokio::test]
async fn test_download_range_and_csek_headers() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/storage/v1/b/my-bkt/o/dir%2Ffile.bin"))
        .and(query_param("alt", "media"))
        .and(header("range", "bytes=2-5"))
        .and(header("x-goog-encryption-algorithm", "AES256"))
        .and(header("x-goog-encryption-key", "base64key=="))
        .and(header("x-goog-encryption-key-sha256", "base64sha=="))
        .respond_with(ResponseTemplate::new(206).set_body_bytes(b"2345".to_vec()))
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let opts = DownloadOptions {
        start_byte: Some(2),
        end_byte: Some(5),
        strategy: DownloadStrategy::Resumable,
        decryption_key: Some(EncryptionKey::Csek {
            key_b64: "base64key==".to_string(),
            key_sha256_b64: "base64sha==".to_string(),
        }),
        ..Default::default()
    };
    let data = client
        .get_object_media("my-bkt", "dir/file.bin", &opts)
        .await
        .unwrap();
    assert_eq!(data.as_ref(), b"2345");
}

#[tokio::test]
async fn test_multipart_upload_and_resumable_upload() {
    let server = MockServer::start().await;

    // Multipart upload
    Mock::given(method("POST"))
        .and(path("/upload/storage/v1/b/my-bkt/o"))
        .and(query_param("uploadType", "multipart"))
        .and(query_param("ifGenerationMatch", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "bucket": "my-bkt",
            "name": "small.txt",
            "size": "5",
            "generation": "101"
        })))
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let obj_meta = Object {
        bucket: Some("my-bkt".to_string()),
        name: Some("small.txt".to_string()),
        content_type: Some("text/plain".to_string()),
        ..Default::default()
    };
    let uploaded = client
        .upload_object(
            Bytes::from_static(b"hello"),
            &obj_meta,
            &UploadOptions {
                preconditions: Some(Preconditions::new(Some(0), None)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(uploaded.generation.as_deref(), Some("101"));

    // Resumable upload (2 chunks: 256KiB + remainder)
    let session_url = format!("{}/upload/session/abc123", server.uri());
    Mock::given(method("POST"))
        .and(path("/upload/storage/v1/b/my-bkt/o"))
        .and(query_param("uploadType", "resumable"))
        .respond_with(ResponseTemplate::new(200).insert_header("location", session_url.as_str()))
        .mount(&server)
        .await;

    let total_size = 262_144 + 100;
    Mock::given(method("PUT"))
        .and(path("/upload/session/abc123"))
        .and(header(
            "content-range",
            format!("bytes 0-262143/{total_size}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(308).insert_header("range", "bytes=0-262143"))
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/upload/session/abc123"))
        .and(header(
            "content-range",
            format!("bytes 262144-{}/{total_size}", total_size - 1).as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "bucket": "my-bkt",
            "name": "big.bin",
            "size": total_size.to_string(),
            "generation": "202"
        })))
        .mount(&server)
        .await;

    let big_meta = Object {
        bucket: Some("my-bkt".to_string()),
        name: Some("big.bin".to_string()),
        ..Default::default()
    };
    let payload = Bytes::from(vec![0xABu8; total_size]);
    let res = client
        .upload_object_resumable(payload, &big_meta, &UploadOptions::default())
        .await
        .unwrap();
    assert_eq!(res.generation.as_deref(), Some("202"));
}

#[tokio::test]
async fn test_copy_object_multi_step_rewrite_and_compose() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/storage/v1/b/src-bkt/o/src.bin/rewriteTo/b/dst-bkt/o/dst.bin",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "done": false,
            "rewriteToken": "rw-tok-1",
            "totalBytesRewritten": "1048576",
            "objectSize": "2097152"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(
            "/storage/v1/b/src-bkt/o/src.bin/rewriteTo/b/dst-bkt/o/dst.bin",
        ))
        .and(query_param("rewriteToken", "rw-tok-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "done": true,
            "resource": {
                "bucket": "dst-bkt",
                "name": "dst.bin",
                "generation": "303"
            }
        })))
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let src = Object {
        bucket: Some("src-bkt".to_string()),
        name: Some("src.bin".to_string()),
        ..Default::default()
    };
    let dst = Object {
        bucket: Some("dst-bkt".to_string()),
        name: Some("dst.bin".to_string()),
        ..Default::default()
    };
    let copied = client
        .copy_object(&src, &dst, &CopyOptions::default())
        .await
        .unwrap();
    assert_eq!(copied.generation.as_deref(), Some("303"));

    // Compose
    Mock::given(method("POST"))
        .and(path("/storage/v1/b/dst-bkt/o/composed.bin/compose"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "bucket": "dst-bkt",
            "name": "composed.bin",
            "componentCount": 2
        })))
        .mount(&server)
        .await;

    let compose_dst = Object {
        bucket: Some("dst-bkt".to_string()),
        name: Some("composed.bin".to_string()),
        ..Default::default()
    };
    let composed = client
        .compose_object(
            &[
                ComposeSourceObject {
                    name: "p1".to_string(),
                    ..Default::default()
                },
                ComposeSourceObject {
                    name: "p2".to_string(),
                    ..Default::default()
                },
            ],
            &compose_dst,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(composed.component_count, Some(2));
}

#[tokio::test]
async fn test_retries_on_503_and_429() {
    struct FlakyResponder {
        count: AtomicUsize,
    }
    impl Respond for FlakyResponder {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            let n = self.count.fetch_add(1, Ordering::SeqCst);
            match n {
                0 => ResponseTemplate::new(503).set_body_string("backend error"),
                1 => ResponseTemplate::new(429).set_body_string("rate limited"),
                _ => ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "name": "retry-bkt"
                })),
            }
        }
    }

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/storage/v1/b/retry-bkt"))
        .respond_with(FlakyResponder {
            count: AtomicUsize::new(0),
        })
        .expect(3)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let bkt = client.get_bucket("retry-bkt", None).await.unwrap();
    assert_eq!(bkt.name.as_deref(), Some("retry-bkt"));
}

#[tokio::test]
async fn test_notifications_and_hmac_keys() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/storage/v1/b/my-bkt/notificationConfigs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "1",
            "topic": "//pubsub.googleapis.com/projects/p/topics/t",
            "payload_format": "JSON_API_V1"
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/storage/v1/projects/my-proj/hmacKeys"))
        .and(query_param(
            "serviceAccountEmail",
            "sa@my-proj.iam.gserviceaccount.com",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "secret": "supersecret",
            "metadata": {
                "accessId": "GOOG1E123",
                "state": "ACTIVE"
            }
        })))
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let notif = client
        .create_notification_config(
            "my-bkt",
            &CreateNotificationOptions {
                pubsub_topic: "//pubsub.googleapis.com/projects/p/topics/t".to_string(),
                payload_format: "JSON_API_V1".to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(notif.id.as_deref(), Some("1"));

    let hmac = client
        .create_hmac_key("my-proj", "sa@my-proj.iam.gserviceaccount.com")
        .await
        .unwrap();
    assert_eq!(hmac.secret, "supersecret");
    assert_eq!(hmac.metadata.access_id.as_deref(), Some("GOOG1E123"));
}

#[test]
fn test_all_http_error_translation_branches() {
    let ctx_bkt = ErrorContext::bucket("my-bkt");
    let ctx_obj = ErrorContext::object("my-bkt", "foo.txt", Some("42"));

    // 400
    let e = translate_http_error(
        400,
        r#"{"error":{"message":"Invalid arg"}}"#,
        None,
        &ctx_bkt,
    );
    assert_eq!(e.to_string(), "BadRequestException: 400 Invalid arg");

    // 401 Login Required
    let e = translate_http_error(
        401,
        r#"{"error":{"message":"Login Required"}}"#,
        None,
        &ctx_bkt,
    );
    assert_eq!(e.to_string(), "AccessDeniedException: 401 Login Required");

    // 401 insufficient_scope
    let e = translate_http_error(
        401,
        "insufficient_scope",
        Some(
            r#"Bearer realm="https://oauth2.googleapis.com/", error=insufficient_scope, scope="https://www.googleapis.com/auth/devstorage.full_control""#,
        ),
        &ctx_bkt,
    );
    assert!(e.to_string().contains("Insufficient OAuth2 scope"));
    assert!(e
        .to_string()
        .contains("Acceptable scopes: https://www.googleapis.com/auth/devstorage.full_control"));

    // 403 branches
    let e = translate_http_error(
        403,
        r#"{"error":{"message":"The account for the specified project has been disabled"}}"#,
        None,
        &ctx_bkt,
    );
    assert!(e.is_access_denied());

    let e = translate_http_error(
        403,
        "Daily Limit for Unauthenticated Use Exceeded",
        None,
        &ctx_bkt,
    );
    assert!(e.to_string().contains("quota exceeded"));

    let e = translate_http_error(
        403,
        "The bucket you tried to delete was not empty.",
        None,
        &ctx_bkt,
    );
    assert_eq!(
        e.to_string(),
        "NotEmptyException: 403 BucketNotEmpty (my-bkt)"
    );

    let e = translate_http_error(
        403,
        "The bucket you tried to create requires domain ownership verification.",
        None,
        &ctx_bkt,
    );
    assert!(e.to_string().contains("domain ownership verification"));

    let e = translate_http_error(403, "User Rate Limit Exceeded", None, &ctx_bkt);
    assert!(e.to_string().contains("Rate limit exceeded"));

    let e = translate_http_error(403, "Access Not Configured", None, &ctx_bkt);
    assert!(e.to_string().contains("Google Cloud Storage JSON API"));

    let e = translate_http_error(
        403,
        r#"{"error":{"message":"Service account does not have permission to publish messages"}}"#,
        None,
        &ctx_bkt,
    );
    assert!(e
        .to_string()
        .starts_with("PublishPermissionDeniedException: 403"));

    // 404 bucket vs object vs write override
    let e = translate_http_error(404, "{}", None, &ctx_bkt);
    assert_eq!(
        e.to_string(),
        "BucketNotFoundException: 404 gs://my-bkt bucket does not exist."
    );

    let e = translate_http_error(404, "{}", None, &ctx_obj);
    assert_eq!(
        e.to_string(),
        "NotFoundException: 404 gs://my-bkt/foo.txt#42 does not exist."
    );

    let ctx_override = ErrorContext {
        provider: "gs",
        bucket_name: Some("dst"),
        object_name: Some("o"),
        generation: None,
        not_found_override: Some(create_not_found_for_object_write(
            "gs",
            "dst",
            Some("src"),
            Some("s"),
            None,
        )),
    };
    let e = translate_http_error(404, "{}", None, &ctx_override);
    assert_eq!(
        e.to_string(),
        "NotFoundException: 404 The source object gs://src/s or the destination bucket gs://dst does not exist."
    );

    // 409 not empty vs already exists
    let e = translate_http_error(
        409,
        "The bucket you tried to delete is not empty.",
        None,
        &ctx_bkt,
    );
    assert_eq!(
        e.to_string(),
        "NotEmptyException: 409 BucketNotEmpty (my-bkt)"
    );

    let e = translate_http_error(409, "You already own this bucket", None, &ctx_bkt);
    assert!(e
        .to_string()
        .contains("A Cloud Storage bucket named 'my-bkt' already exists."));

    // 412
    let e = translate_http_error(
        412,
        r#"{"error":{"message":"Precondition Failed"}}"#,
        None,
        &ctx_obj,
    );
    assert_eq!(
        e.to_string(),
        "PreconditionException: 412 Precondition Failed"
    );

    // 429 / 503 retryable
    let e = translate_http_error(429, "{}", None, &ctx_bkt);
    assert!(matches!(e, GsutilError::Service(se) if se.is_retryable()));

    let e = translate_http_error(503, "{}", None, &ctx_bkt);
    assert!(matches!(e, GsutilError::Service(se) if se.is_retryable()));

    // Resumable upload errors
    let r500 = translate_resumable_upload_error(500, "{}");
    assert!(
        matches!(r500, GsutilError::Service(se) if se.kind == ServiceErrorKind::ResumableUpload)
    );

    let r429 = translate_resumable_upload_error(429, "{}");
    assert!(
        matches!(r429, GsutilError::Service(se) if se.kind == ServiceErrorKind::ResumableUpload)
    );

    let r410 = translate_resumable_upload_error(410, "{}");
    assert!(
        matches!(r410, GsutilError::Service(se) if se.kind == ServiceErrorKind::ResumableUploadStartOver)
    );

    let r404 = translate_resumable_upload_error(404, "{}");
    assert!(
        matches!(r404, GsutilError::Service(se) if se.kind == ServiceErrorKind::ResumableUploadStartOver)
    );

    let r403 = translate_resumable_upload_error(403, "{}");
    assert!(
        matches!(r403, GsutilError::Service(se) if se.kind == ServiceErrorKind::ResumableUploadAbort)
    );
}

#[tokio::test]
async fn test_auxiliary_clients_kms_pubsub_iam_and_xml() {
    let server = MockServer::start().await;
    let creds = Arc::new(StaticTokenProvider {
        token: "aux-token".to_string(),
    });

    // KMS: CreateKeyRing (409 treated as success) + GetKeyIamPolicy
    Mock::given(method("POST"))
        .and(path("/v1/projects/p1/locations/global/keyRings"))
        .and(query_param("keyRingId", "kr1"))
        .respond_with(ResponseTemplate::new(409).set_body_string("already exists"))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(
            "/v1/projects/p1/locations/global/keyRings/kr1/cryptoKeys/k1:getIamPolicy",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "version": 1,
            "bindings": [{
                "role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
                "members": ["serviceAccount:gs@gs-project-accounts.iam.gserviceaccount.com"]
            }]
        })))
        .mount(&server)
        .await;

    let kms = KmsClient::with_base_url(server.uri(), creds.clone(), RetryPolicy::fast_for_tests(2));
    let kr = kms.create_key_ring("p1", "kr1", "global").await.unwrap();
    assert_eq!(kr, "projects/p1/locations/global/keyRings/kr1");
    let policy = kms
        .get_key_iam_policy("projects/p1/locations/global/keyRings/kr1/cryptoKeys/k1")
        .await
        .unwrap();
    assert_eq!(policy.bindings.len(), 1);

    // Pub/Sub: CreateTopic + SetTopicIamPolicy
    Mock::given(method("PUT"))
        .and(path("/v1/projects/p1/topics/t1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "projects/p1/topics/t1"
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/projects/p1/topics/t1:setIamPolicy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "version": 1,
            "bindings": [{ "role": "roles/pubsub.publisher", "members": ["allUsers"] }]
        })))
        .mount(&server)
        .await;

    let pubsub =
        PubsubClient::with_base_url(server.uri(), creds.clone(), RetryPolicy::fast_for_tests(2));
    let topic = pubsub.create_topic("projects/p1/topics/t1").await.unwrap();
    assert_eq!(topic.name, "projects/p1/topics/t1");
    let new_pol = IamPolicy {
        version: Some(1),
        bindings: vec![IamBinding {
            role: "roles/pubsub.publisher".to_string(),
            members: vec!["allUsers".to_string()],
            condition: None,
        }],
        ..Default::default()
    };
    let set_pol = pubsub
        .set_topic_iam_policy("projects/p1/topics/t1", &new_pol)
        .await
        .unwrap();
    assert_eq!(set_pol.bindings[0].role, "roles/pubsub.publisher");

    // IAMCredentials: GenerateAccessToken
    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/sa@p1.iam.gserviceaccount.com:generateAccessToken",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "mock-token-gen-tok",
            "expireTime": "2099-01-01T00:00:00Z"
        })))
        .mount(&server)
        .await;

    let iam =
        IamCredentialsClient::with_base_url(server.uri(), creds, RetryPolicy::fast_for_tests(2));
    let gen_tok = iam
        .generate_access_token(
            "sa@p1.iam.gserviceaccount.com",
            &["https://www.googleapis.com/auth/cloud-platform".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(gen_tok.access_token, "mock-token-gen-tok");

    // XML/S3 client scaffolding + SigV4 key derivation
    let mut cfg = BotoConfig::new();
    cfg.set("Credentials", "s3_host", "s3.us-west-2.amazonaws.com");
    let hmac = Arc::new(HmacCredentials::new(
        "TESTKEY0000000000001",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        gsutil_auth::hmac::HmacProvider::Aws,
    ));
    let xml = XmlApiClient::new("s3", &cfg, hmac);
    assert_eq!(xml.config().endpoint, "https://s3.us-west-2.amazonaws.com");
    assert!(xml.require_hmac().is_ok());

    let signing_key = XmlApiClient::derive_sigv4_signing_key(
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "20130524",
        "us-east-1",
        "s3",
    );
    // Known AWS SigV4 test vector for signing key derivation:
    assert_eq!(
        hex::encode(signing_key),
        "dbb893acc010964918f1fd433add87c70e8b0db6be30c1fbeafefa5ec6ba8378"
    );

    // Anonymous XML client fails require_hmac()
    let anon_xml = XmlApiClient::new("s3", &cfg, Arc::new(NoOpCredentials));
    assert!(anon_xml.require_hmac().is_err());
}

#[test]
fn test_mtls_falls_back_to_default_host_without_client_cert() {
    let mut cfg = BotoConfig::new();
    cfg.set("Credentials", "use_client_certificate", "True");
    let client_cfg = GcsJsonClientConfig::from_boto_config(&cfg).unwrap();
    assert_eq!(
        client_cfg.storage_base_url,
        "https://storage.googleapis.com/storage/v1"
    );

    // Explicit gs_json_host + use_client_certificate still raises ArgumentException.
    cfg.set("Credentials", "gs_json_host", "custom.example.com");
    let err = GcsJsonClientConfig::from_boto_config(&cfg).unwrap_err();
    assert!(err.to_string().contains("ArgumentException:"));
}

#[tokio::test]
async fn test_ecp_proxy_port_routing_and_target_host_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/storage/v1/b/ecp-bkt"))
        .and(header(
            "x-goog-ecpproxy-target-host",
            "storage.mtls.googleapis.com",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "ecp-bkt"
        })))
        .mount(&server)
        .await;

    let port = server.address().port();
    std::env::set_var("GSUTIL_ECP_PROXY_PORT", port.to_string());
    let cfg = BotoConfig::new();
    let client = GcsJsonClient::from_boto_config(
        &cfg,
        Arc::new(StaticTokenProvider {
            token: "ecp-token".to_string(),
        }),
    )
    .unwrap();
    std::env::remove_var("GSUTIL_ECP_PROXY_PORT");

    let bkt = client.get_bucket("ecp-bkt", None).await.unwrap();
    assert_eq!(bkt.name.as_deref(), Some("ecp-bkt"));
}

#[tokio::test]
async fn test_list_objects_normalizes_raw_fields_to_items_prefix() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/storage/v1/b/fields-bkt/o"))
        .and(query_param(
            "fields",
            "items/generation,items/name,items/size,nextPageToken,prefixes",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": [{ "name": "f.txt", "size": "10", "generation": "1" }]
        })))
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let opts = ListObjectsOptions {
        fields: Some(vec![
            "name".to_string(),
            "size".to_string(),
            "items/generation".to_string(),
        ]),
        ..Default::default()
    };
    let items = client.list_objects("fields-bkt", &opts).await.unwrap();
    assert_eq!(items.len(), 1);
}

#[tokio::test]
async fn test_patch_bucket_and_object_explicit_null_tombstones() {
    let server = MockServer::start().await;

    Mock::given(method("PATCH"))
        .and(path("/storage/v1/b/tomb-bkt"))
        .and(body_json(serde_json::json!({
            "labels": { "keep": "yes", "drop": null },
            "logging": null,
            "encryption": null
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "tomb-bkt"
        })))
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path("/storage/v1/b/tomb-bkt/o/obj.txt"))
        .and(body_json(serde_json::json!({
            "metadata": { "k1": "v1", "old_key": null },
            "cacheControl": null
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "bucket": "tomb-bkt",
            "name": "obj.txt"
        })))
        .mount(&server)
        .await;

    let client = mock_client(&server);

    let mut labels = std::collections::BTreeMap::new();
    labels.insert("keep".to_string(), "yes".to_string());
    let bkt_patch = Bucket {
        labels: Some(labels),
        label_removals: vec!["drop".to_string()],
        clear_fields: vec!["logging".to_string(), "encryption".to_string()],
        ..Default::default()
    };
    let res_b = client
        .patch_bucket("tomb-bkt", &bkt_patch, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(res_b.name.as_deref(), Some("tomb-bkt"));

    let mut meta_map = std::collections::BTreeMap::new();
    meta_map.insert("k1".to_string(), "v1".to_string());
    let obj_patch = Object {
        metadata: Some(meta_map),
        metadata_removals: vec!["old_key".to_string()],
        clear_fields: vec!["cacheControl".to_string()],
        ..Default::default()
    };
    let res_o = client
        .patch_object_metadata("tomb-bkt", "obj.txt", &obj_patch, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(res_o.name.as_deref(), Some("obj.txt"));
}

#[tokio::test]
async fn test_get_object_media_gzip_preserves_raw_compressed_bytes() {
    let server = MockServer::start().await;
    // Valid minimal gzip payload (magic bytes 0x1f 0x8b ...)
    let raw_gzip: Vec<u8> = vec![
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x07, 0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00, 0x00,
    ];

    Mock::given(method("GET"))
        .and(path("/storage/v1/b/gz-bkt/o/hello.txt"))
        .and(query_param("alt", "media"))
        .and(header("accept-encoding", "gzip"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .set_body_bytes(raw_gzip.clone()),
        )
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let data = client
        .get_object_media(
            "gz-bkt",
            "hello.txt",
            &DownloadOptions {
                compressed_encoding: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(data.as_ref(), raw_gzip.as_slice());
}

#[tokio::test]
async fn test_kms_api_and_pubsub_api_trait_impls() {
    let server = MockServer::start().await;
    let creds = Arc::new(StaticTokenProvider {
        token: "trait-tok".to_string(),
    });

    // KMS authorize_service_account: GET returns empty policy -> POST sets binding -> returns true
    Mock::given(method("GET"))
        .and(path(
            "/v1/projects/p/locations/us/keyRings/kr/cryptoKeys/k:getIamPolicy",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "version": 1,
            "bindings": []
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/p/locations/us/keyRings/kr/cryptoKeys/k:setIamPolicy",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "version": 1,
            "bindings": [{
                "role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
                "members": ["serviceAccount:gs-sa@gs-project-accounts.iam.gserviceaccount.com"]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let kms: Arc<dyn KmsApi> = Arc::new(KmsClient::with_base_url(
        server.uri(),
        creds.clone(),
        RetryPolicy::fast_for_tests(1),
    ));
    let changed = kms
        .authorize_service_account(
            "projects/p/locations/us/keyRings/kr/cryptoKeys/k",
            "gs-sa@gs-project-accounts.iam.gserviceaccount.com",
        )
        .await
        .unwrap();
    assert!(changed);

    // PubSub create_topic treats 409 as Ok(()), authorize_publisher sets roles/pubsub.publisher
    Mock::given(method("PUT"))
        .and(path("/v1/projects/p/topics/t-exist"))
        .respond_with(ResponseTemplate::new(409).set_body_string("already exists"))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/projects/p/topics/t-exist:getIamPolicy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "version": 1,
            "bindings": []
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/projects/p/topics/t-exist:setIamPolicy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "version": 1,
            "bindings": [{
                "role": "roles/pubsub.publisher",
                "members": ["serviceAccount:gs-sa@gs-project-accounts.iam.gserviceaccount.com"]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let pubsub: Arc<dyn PubsubApi> = Arc::new(PubsubClient::with_base_url(
        server.uri(),
        creds,
        RetryPolicy::fast_for_tests(1),
    ));
    pubsub
        .create_topic("projects/p/topics/t-exist")
        .await
        .unwrap();
    pubsub
        .authorize_publisher(
            "projects/p/topics/t-exist",
            "gs-sa@gs-project-accounts.iam.gserviceaccount.com",
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn test_get_object_media_stream_and_progress_callback() {
    use futures::StreamExt;
    use std::sync::atomic::AtomicU64;

    let server = MockServer::start().await;
    let payload = vec![0x5Au8; 65_536];

    Mock::given(method("GET"))
        .and(path("/storage/v1/b/stream-bkt/o/blob.bin"))
        .and(query_param("alt", "media"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(payload.clone()))
        .mount(&server)
        .await;

    let last_reported = Arc::new(AtomicU64::new(0));
    let cb_ref = Arc::clone(&last_reported);
    let client = mock_client(&server);
    let mut stream = client
        .get_object_media_stream(
            "stream-bkt",
            "blob.bin",
            &DownloadOptions {
                progress_callback: Some(Arc::new(move |done, _total| {
                    cb_ref.store(done, Ordering::SeqCst);
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut collected = Vec::new();
    while let Some(chunk) = stream.next().await {
        collected.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(collected, payload);
    assert_eq!(last_reported.load(Ordering::SeqCst), 65_536);
}

#[tokio::test]
async fn test_upload_object_resumable_file_session_callback_and_308_resume() {
    use std::sync::Mutex;

    let server = MockServer::start().await;
    let total_size = 524_288u64; // 512 KiB = 2 x 256 KiB chunks
    let mut data = vec![0u8; total_size as usize];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let tmp_path =
        std::env::temp_dir().join(format!("gsutil_gcs_resume_test_{}.bin", std::process::id()));
    std::fs::write(&tmp_path, &data).unwrap();

    // Case 1: Resume an existing session at byte 262144 (308 Range -> upload only second chunk).
    let existing_session = format!("{}/upload/session/resume-1", server.uri());
    Mock::given(method("PUT"))
        .and(path("/upload/session/resume-1"))
        .and(header("content-range", "bytes */524288"))
        .respond_with(ResponseTemplate::new(308).insert_header("range", "bytes=0-262143"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/upload/session/resume-1"))
        .and(header("content-range", "bytes 262144-524287/524288"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "bucket": "res-bkt",
            "name": "resumed.bin",
            "size": "524288",
            "generation": "777"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let obj_meta = Object {
        bucket: Some("res-bkt".to_string()),
        name: Some("resumed.bin".to_string()),
        ..Default::default()
    };
    let resumed_obj = client
        .upload_object_resumable_file(
            &tmp_path,
            0,
            total_size,
            &obj_meta,
            &UploadOptions {
                resumable_session_uri: Some(existing_session),
                chunk_size: Some(262_144),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(resumed_obj.generation.as_deref(), Some("777"));

    // Case 2: Expired existing session (410) -> initiates new session + fires session_uri_callback.
    let expired_session = format!("{}/upload/session/expired-1", server.uri());
    let fresh_session = format!("{}/upload/session/fresh-2", server.uri());
    Mock::given(method("PUT"))
        .and(path("/upload/session/expired-1"))
        .and(header("content-range", "bytes */524288"))
        .respond_with(ResponseTemplate::new(410))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/upload/storage/v1/b/res-bkt/o"))
        .and(query_param("uploadType", "resumable"))
        .respond_with(ResponseTemplate::new(200).insert_header("location", fresh_session.as_str()))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/upload/session/fresh-2"))
        .and(header("content-range", "bytes 0-262143/524288"))
        .respond_with(ResponseTemplate::new(308).insert_header("range", "bytes=0-262143"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/upload/session/fresh-2"))
        .and(header("content-range", "bytes 262144-524287/524288"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "bucket": "res-bkt",
            "name": "resumed.bin",
            "size": "524288",
            "generation": "888"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let captured_uri = Arc::new(Mutex::new(None::<String>));
    let cap_clone = Arc::clone(&captured_uri);
    let fresh_obj = client
        .upload_object_resumable_file(
            &tmp_path,
            0,
            total_size,
            &obj_meta,
            &UploadOptions {
                resumable_session_uri: Some(expired_session),
                session_uri_callback: Some(Arc::new(move |uri| {
                    *cap_clone.lock().unwrap() = Some(uri.to_string());
                })),
                chunk_size: Some(262_144),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(fresh_obj.generation.as_deref(), Some("888"));
    assert_eq!(
        captured_uri.lock().unwrap().as_deref(),
        Some(fresh_session.as_str())
    );

    let _ = std::fs::remove_file(&tmp_path);
}

#[tokio::test]
async fn test_upload_object_streaming_chunked_async_read() {
    let server = MockServer::start().await;
    let total_size = 262_144 + 4096;
    let payload = vec![0x33u8; total_size];

    let session_url = format!("{}/upload/session/stream-1", server.uri());
    Mock::given(method("POST"))
        .and(path("/upload/storage/v1/b/str-bkt/o"))
        .and(query_param("uploadType", "resumable"))
        .respond_with(ResponseTemplate::new(200).insert_header("location", session_url.as_str()))
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/upload/session/stream-1"))
        .and(header("content-range", "bytes 0-262143/*"))
        .respond_with(ResponseTemplate::new(308).insert_header("range", "bytes=0-262143"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/upload/session/stream-1"))
        .and(header(
            "content-range",
            format!("bytes 262144-{}/{total_size}", total_size - 1).as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "bucket": "str-bkt",
            "name": "stdin.bin",
            "size": total_size.to_string(),
            "generation": "909"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = mock_client(&server);
    let obj_meta = Object {
        bucket: Some("str-bkt".to_string()),
        name: Some("stdin.bin".to_string()),
        ..Default::default()
    };
    let reader = Box::new(std::io::Cursor::new(payload));
    let obj = client
        .upload_object_streaming(
            reader,
            &obj_meta,
            &UploadOptions {
                chunk_size: Some(262_144),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(obj.generation.as_deref(), Some("909"));
}
