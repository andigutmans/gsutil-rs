use std::sync::Arc;

use bytes::Bytes;
use gsutil_auth::hmac::HmacProvider;
use gsutil_auth::{HmacCredentials, NoOpCredentials};
use gsutil_core::api::{
    Bucket, BucketCors, BucketLifecycle, BucketVersioning, CloudApi, ComposeSourceObject,
    CopyOptions, CsObjectOrPrefix, DownloadOptions, LifecycleAction, LifecycleCondition,
    LifecycleRule, ListObjectsOptions, Object, UploadOptions,
};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, ServiceErrorKind};
use gsutil_gcs::client::{GcsJsonClient, GcsJsonClientConfig};
use gsutil_gcs::delegator::{ApiSelector, CloudApiDelegator};
use gsutil_gcs::error_translation::ErrorContext;
use gsutil_gcs::xml::{
    parse_acl_xml, parse_lifecycle_xml, serialize_cors_xml, serialize_lifecycle_xml,
    translate_xml_error, XmlApiClient, XmlClientConfig,
};
use wiremock::matchers::{header, header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn s3_hmac_creds() -> Arc<HmacCredentials> {
    Arc::new(HmacCredentials::new(
        "TESTKEY0000000000001",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        HmacProvider::Aws,
    ))
}

#[tokio::test]
async fn test_xml_s3_list_buckets_and_sigv4_headers() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .and(header_exists("authorization"))
        .and(header_exists("x-amz-date"))
        .and(header_exists("x-amz-content-sha256"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<?xml version="1.0" encoding="UTF-8"?>
            <ListAllMyBucketsResult>
                <Buckets>
                    <Bucket><Name>alpha-bkt</Name><CreationDate>2025-01-01T00:00:00Z</CreationDate></Bucket>
                    <Bucket><Name>beta-bkt</Name><CreationDate>2025-01-02T00:00:00Z</CreationDate></Bucket>
                </Buckets>
            </ListAllMyBucketsResult>"#,
        ))
        .mount(&server)
        .await;

    let cfg = XmlClientConfig::for_mock_server("s3", server.uri());
    let client = XmlApiClient::with_config(cfg, s3_hmac_creds());
    let buckets = client.list_buckets(None, None).await.unwrap();
    let names: Vec<_> = buckets.iter().filter_map(|b| b.name.as_deref()).collect();
    assert_eq!(names, vec!["alpha-bkt", "beta-bkt"]);
}

#[tokio::test]
async fn test_xml_list_objects_pagination_and_metadata() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/my-xml-bkt"))
        .and(query_param("delimiter", "/"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<ListBucketResult>
                <IsTruncated>true</IsTruncated>
                <NextMarker>a.txt</NextMarker>
                <Contents>
                    <Key>a.txt</Key>
                    <Size>12</Size>
                    <ETag>"abc123"</ETag>
                    <StorageClass>STANDARD</StorageClass>
                </Contents>
                <CommonPrefixes><Prefix>sub/</Prefix></CommonPrefixes>
            </ListBucketResult>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/my-xml-bkt"))
        .and(query_param("marker", "a.txt"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<ListBucketResult>
                <IsTruncated>false</IsTruncated>
                <Contents>
                    <Key>b.txt</Key>
                    <Size>34</Size>
                </Contents>
            </ListBucketResult>"#,
        ))
        .mount(&server)
        .await;

    Mock::given(method("HEAD"))
        .and(path("/my-xml-bkt/dir/file.txt"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-length", "42")
                .insert_header("content-type", "text/plain")
                .insert_header("etag", "\"deadbeef\"")
                .insert_header("x-goog-generation", "12345")
                .insert_header(
                    "x-goog-hash",
                    "crc32c=mnG7TA==, md5=XUFAKrxLKna5cZ2REBfFkg==",
                )
                .insert_header("x-goog-meta-env", "staging"),
        )
        .mount(&server)
        .await;

    let cfg = XmlClientConfig::for_mock_server("gs", server.uri());
    let client = XmlApiClient::with_config(cfg, Arc::new(NoOpCredentials));

    let items = client
        .list_objects(
            "my-xml-bkt",
            &ListObjectsOptions {
                delimiter: Some("/".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(items.len(), 3);
    assert!(matches!(&items[0], CsObjectOrPrefix::Object(o) if o.name.as_deref() == Some("a.txt")));
    assert!(matches!(&items[1], CsObjectOrPrefix::Prefix(p) if p == "sub/"));
    assert!(matches!(&items[2], CsObjectOrPrefix::Object(o) if o.name.as_deref() == Some("b.txt")));

    let meta = client
        .get_object_metadata("my-xml-bkt", "dir/file.txt", None, None)
        .await
        .unwrap();
    assert_eq!(meta.generation.as_deref(), Some("12345"));
    assert_eq!(meta.crc32c.as_deref(), Some("mnG7TA=="));
    assert_eq!(meta.md5_hash.as_deref(), Some("XUFAKrxLKna5cZ2REBfFkg=="));
    assert_eq!(
        meta.metadata
            .as_ref()
            .and_then(|m| m.get("env"))
            .map(String::as_str),
        Some("staging")
    );
}

#[tokio::test]
async fn test_xml_upload_download_copy_compose_and_patch() {
    let server = MockServer::start().await;

    Mock::given(method("PUT"))
        .and(path("/bkt/obj.txt"))
        .and(header("x-goog-acl", "public-read"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-goog-generation", "999")
                .insert_header("etag", "\"etag1\""),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/bkt/obj.txt"))
        .and(header("range", "bytes=1-3"))
        .respond_with(ResponseTemplate::new(206).set_body_bytes(b"ell".to_vec()))
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/bkt/copy.txt"))
        .and(header("x-goog-copy-source", "/bkt/obj.txt"))
        .respond_with(ResponseTemplate::new(200).insert_header("x-goog-generation", "1000"))
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/bkt/composed.txt"))
        .and(query_param("compose", ""))
        .respond_with(ResponseTemplate::new(200).insert_header("x-goog-generation", "1001"))
        .mount(&server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/bkt"))
        .and(query_param("versioning", ""))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let cfg = XmlClientConfig::for_mock_server("gs", server.uri());
    let client = XmlApiClient::with_config(cfg, Arc::new(NoOpCredentials));

    let obj = Object {
        bucket: Some("bkt".to_string()),
        name: Some("obj.txt".to_string()),
        ..Default::default()
    };
    let uploaded = client
        .upload_object(
            Bytes::from_static(b"hello"),
            &obj,
            &UploadOptions {
                canned_acl: Some("public-read".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(uploaded.generation.as_deref(), Some("999"));

    let range = client
        .get_object_media(
            "bkt",
            "obj.txt",
            &DownloadOptions {
                start_byte: Some(1),
                end_byte: Some(3),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(range.as_ref(), b"ell");

    let dst = Object {
        bucket: Some("bkt".to_string()),
        name: Some("copy.txt".to_string()),
        ..Default::default()
    };
    let copied = client
        .copy_object(&obj, &dst, &CopyOptions::default())
        .await
        .unwrap();
    assert_eq!(copied.generation.as_deref(), Some("1000"));

    let comp_dst = Object {
        bucket: Some("bkt".to_string()),
        name: Some("composed.txt".to_string()),
        ..Default::default()
    };
    let composed = client
        .compose_object(
            &[ComposeSourceObject {
                name: "obj.txt".to_string(),
                ..Default::default()
            }],
            &comp_dst,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(composed.generation.as_deref(), Some("1001"));

    let patched = client
        .patch_bucket(
            "bkt",
            &Bucket {
                versioning: Some(BucketVersioning {
                    enabled: Some(true),
                }),
                ..Default::default()
            },
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(patched.versioning.and_then(|v| v.enabled), Some(true));
}

#[test]
fn test_xml_cors_lifecycle_acl_and_error_translation() {
    let cors_xml = serialize_cors_xml(
        &[BucketCors {
            origin: Some(vec!["https://example.com".to_string()]),
            method: Some(vec!["GET".to_string()]),
            response_header: Some(vec!["Content-Type".to_string()]),
            max_age_seconds: Some(3600),
        }],
        "s3",
    );
    assert!(cors_xml.contains("<CORSConfiguration>"));
    assert!(cors_xml.contains("<AllowedOrigin>https://example.com</AllowedOrigin>"));

    let lc = BucketLifecycle {
        rule: Some(vec![LifecycleRule {
            action: Some(LifecycleAction {
                action_type: Some("Delete".to_string()),
                storage_class: None,
            }),
            condition: Some(LifecycleCondition {
                age: Some(30),
                is_live: Some(true),
                ..Default::default()
            }),
        }]),
    };
    let lc_xml = serialize_lifecycle_xml(&lc);
    let parsed_lc = parse_lifecycle_xml(&lc_xml);
    assert_eq!(
        parsed_lc.rule.as_ref().unwrap()[0]
            .condition
            .as_ref()
            .unwrap()
            .age,
        Some(30)
    );

    let acl_xml = r#"<AccessControlList><Entries>
        <Entry><Scope type="AllUsers"/><Permission>READ</Permission></Entry>
        <Entry><Scope type="UserByEmail"><EmailAddress>a@b.com</EmailAddress></Scope><Permission>FULL_CONTROL</Permission></Entry>
    </Entries></AccessControlList>"#;
    let acl = parse_acl_xml(acl_xml);
    assert_eq!(acl.len(), 2);
    assert_eq!(acl[0].entity.as_deref(), Some("allUsers"));
    assert_eq!(acl[0].role.as_deref(), Some("READER"));
    assert_eq!(acl[1].entity.as_deref(), Some("user-a@b.com"));
    assert_eq!(acl[1].role.as_deref(), Some("OWNER"));

    // Error translation parity
    let ctx_s3 = ErrorContext {
        provider: "s3",
        bucket_name: Some("s3-bkt"),
        object_name: Some("k"),
        generation: None,
        not_found_override: None,
    };
    let e404 = translate_xml_error(404, "<Error><Code>NoSuchKey</Code></Error>", &ctx_s3);
    assert_eq!(
        e404.to_string(),
        "NotFoundException: 404 s3://s3-bkt/k does not exist."
    );

    let ctx_bkt = ErrorContext::bucket("my-bkt");
    let e409_ne = translate_xml_error(409, "<Error><Code>BucketNotEmpty</Code></Error>", &ctx_bkt);
    assert!(matches!(e409_ne, GsutilError::Service(se) if se.kind == ServiceErrorKind::NotEmpty));

    let e409_exists = translate_xml_error(
        409,
        "<Error><Code>BucketAlreadyExists</Code></Error>",
        &ctx_bkt,
    );
    assert!(e409_exists.to_string().contains("Bucket already exists."));

    let e410 = translate_xml_error(410, "<Error><Message>expired</Message></Error>", &ctx_bkt);
    assert!(matches!(
        e410,
        GsutilError::Service(se) if se.kind == ServiceErrorKind::ResumableUploadStartOver
    ));

    let e412 = translate_xml_error(
        412,
        "<Error><Code>PreconditionFailed</Code></Error>",
        &ctx_bkt,
    );
    assert!(matches!(e412, GsutilError::Service(se) if se.kind == ServiceErrorKind::Precondition));
}

#[tokio::test]
async fn test_cloud_api_delegator_routing_rules() {
    let json_server = MockServer::start().await;
    let xml_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/storage/v1/b/json-bkt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "json-bkt"
        })))
        .mount(&json_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/s3-bkt"))
        .and(query_param("max-keys", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ListBucketResult/>"))
        .mount(&xml_server)
        .await;

    let gs_json: Arc<dyn CloudApi> = Arc::new(
        GcsJsonClient::new(
            GcsJsonClientConfig::for_mock_server(json_server.uri()),
            Arc::new(NoOpCredentials),
        )
        .unwrap(),
    );
    let gs_xml: Arc<dyn CloudApi> = Arc::new(XmlApiClient::with_config(
        XmlClientConfig::for_mock_server("gs", xml_server.uri()),
        Arc::new(NoOpCredentials),
    ));
    let s3_xml: Arc<dyn CloudApi> = Arc::new(XmlApiClient::with_config(
        XmlClientConfig::for_mock_server("s3", xml_server.uri()),
        s3_hmac_creds(),
    ));

    // Default: gs -> JSON, s3 -> XML
    let cfg = BotoConfig::new();
    let delegator = CloudApiDelegator::from_clients(
        &cfg,
        "gs",
        gs_json.clone(),
        gs_xml.clone(),
        s3_xml.clone(),
    );
    assert_eq!(
        delegator.get_api_selector(Some("gs")).unwrap(),
        ApiSelector::Json
    );
    assert_eq!(
        delegator.get_api_selector(Some("s3")).unwrap(),
        ApiSelector::Xml
    );

    let b_gs = delegator.get_bucket("json-bkt", None).await.unwrap();
    assert_eq!(b_gs.name.as_deref(), Some("json-bkt"));

    let b_s3 = delegator
        .api_for_provider(Some("s3"))
        .unwrap()
        .get_bucket("s3-bkt", None)
        .await
        .unwrap();
    assert_eq!(b_s3.name.as_deref(), Some("s3-bkt"));

    // Verify dynamic dispatch through `Arc<dyn CloudApi>` routes s3:// via `for_provider("s3")`.
    let dyn_api: Arc<dyn CloudApi> = Arc::new(delegator.clone());
    let b_s3_dyn = dyn_api
        .for_provider("s3")
        .unwrap()
        .get_bucket("s3-bkt", None)
        .await
        .unwrap();
    assert_eq!(b_s3_dyn.name.as_deref(), Some("s3-bkt"));

    // prefer_api = xml -> gs routes to XML
    let mut cfg_xml = BotoConfig::new();
    cfg_xml.set("GSUtil", "prefer_api", "xml");
    let del_xml = CloudApiDelegator::from_clients(
        &cfg_xml,
        "gs",
        gs_json.clone(),
        gs_xml.clone(),
        s3_xml.clone(),
    );
    assert_eq!(
        del_xml.get_api_selector(Some("gs")).unwrap(),
        ApiSelector::Xml
    );

    // encryption_key overrides prefer_api=xml and forces JSON
    cfg_xml.set(
        "GSUtil",
        "encryption_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    );
    let del_enc = CloudApiDelegator::from_clients(
        &cfg_xml,
        "gs",
        gs_json.clone(),
        gs_xml.clone(),
        s3_xml.clone(),
    );
    assert_eq!(
        del_enc.get_api_selector(Some("gs")).unwrap(),
        ApiSelector::Json
    );

    // HMAC + encryption_key raises CommandException
    let mut cfg_hmac_enc = BotoConfig::new();
    cfg_hmac_enc.set("Credentials", "gs_access_key_id", "GOOG123");
    cfg_hmac_enc.set("Credentials", "gs_secret_access_key", "SECRET");
    cfg_hmac_enc.set(
        "GSUtil",
        "encryption_key",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    );
    let del_hmac_enc = CloudApiDelegator::from_clients(
        &cfg_hmac_enc,
        "gs",
        gs_json.clone(),
        gs_xml.clone(),
        s3_xml.clone(),
    );
    let err = del_hmac_enc.get_api_selector(Some("gs")).unwrap_err();
    assert!(err
        .to_string()
        .contains("does not support HMAC credentials"));

    // mTLS + XML raises ArgumentException
    let mut cfg_mtls = BotoConfig::new();
    cfg_mtls.set("GSUtil", "prefer_api", "xml");
    cfg_mtls.set("Credentials", "use_client_certificate", "True");
    let del_mtls = CloudApiDelegator::from_clients(&cfg_mtls, "gs", gs_json, gs_xml, s3_xml);
    let err = del_mtls.get_api_selector(Some("gs")).unwrap_err();
    assert!(err
        .to_string()
        .contains("mTLS is not supported for the selected XML API"));
}

#[tokio::test]
async fn test_xml_gs_hmac_uses_goog4_without_x_amz_headers() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/gs-xml-bkt"))
        .respond_with(|req: &wiremock::Request| {
            for (k, _) in &req.headers {
                let lower = k.as_str().to_ascii_lowercase();
                assert!(
                    !lower.starts_with("x-amz-"),
                    "GCS XML HMAC request must not mix x-amz-* headers with x-goog-*: found {lower}"
                );
            }
            let auth = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            assert!(
                auth.starts_with("GOOG4-HMAC-SHA256 "),
                "Expected GOOG4-HMAC-SHA256 auth header, got: {auth}"
            );
            assert!(
                auth.contains("/auto/storage/goog4_request"),
                "Expected /auto/storage/goog4_request scope, got: {auth}"
            );
            assert!(req.headers.get("x-goog-date").is_some());
            assert!(req.headers.get("x-goog-content-sha256").is_some());

            ResponseTemplate::new(200).set_body_string(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>gs-xml-bkt</Name>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>hello.txt</Key>
    <Size>5</Size>
  </Contents>
</ListBucketResult>"#,
            )
        })
        .expect(1)
        .mount(&server)
        .await;

    let gs_hmac: Arc<dyn gsutil_auth::TokenProvider> = Arc::new(HmacCredentials::new(
        "GOOG1ETESTKEY00000001",
        "mock-secret-key-for-gs-xml-test",
        HmacProvider::Gcs,
    ));
    let client = XmlApiClient::with_config(
        XmlClientConfig::for_mock_server("gs", server.uri()),
        gs_hmac,
    );
    let items = client
        .list_objects("gs-xml-bkt", &ListObjectsOptions::default())
        .await
        .unwrap();
    assert_eq!(items.len(), 1);
}
