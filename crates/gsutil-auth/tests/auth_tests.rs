use std::sync::Arc;

use gsutil_auth::adc::AdcCredentials;
use gsutil_auth::gce::GceMetadataCredentials;
use gsutil_auth::hmac::{HmacCredentials, HmacProvider};
use gsutil_auth::impersonation::ImpersonationCredentials;
use gsutil_auth::oauth2::OAuth2UserCredentials;
use gsutil_auth::resolver::{resolve_credentials_with_options, AuthOptions};
use gsutil_auth::service_account::ServiceAccountCredentials;
use gsutil_auth::{AccessToken, CredentialType, NoOpCredentials, TokenProvider};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, ServiceErrorKind};
use pkcs8::EncodePrivateKey;
use reqwest::Client;
use rsa::rand_core::OsRng;
use rsa::RsaPrivateKey;
use tempfile::NamedTempFile;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn offline_options() -> AuthOptions {
    AuthOptions {
        impersonate_service_account: None,
        allow_gcloud_fallback: false,
        allow_gce_metadata: false,
        allow_adc: false,
        gce_metadata_url: "http://127.0.0.1:1".to_string(),
        iamcredentials_base_url: None,
        adc_path_override: None,
    }
}

#[test]
fn test_debug_redacts_secrets() {
    let tok = AccessToken::from_expires_in("mock-token-super_secret_token_value", 3600);
    let dbg = format!("{tok:?}");
    assert!(!dbg.contains("super_secret_token_value"));
    assert!(dbg.contains("REDACTED"));

    let hmac = HmacCredentials::new(
        "GOOG1EACCESSKEY",
        "super_secret_hmac_key",
        HmacProvider::Gcs,
    );
    let hmac_dbg = format!("{hmac:?}");
    assert!(hmac_dbg.contains("GOOG1EACCESSKEY"));
    assert!(!hmac_dbg.contains("super_secret_hmac_key"));
    assert!(hmac_dbg.contains("REDACTED"));

    let oauth = OAuth2UserCredentials::new(
        "cid",
        "my_client_secret",
        "my_refresh_token",
        "https://oauth2.googleapis.com/token",
        None,
        CredentialType::OAuth2UserAccount,
        Client::new(),
    );
    let oauth_dbg = format!("{oauth:?}");
    assert!(!oauth_dbg.contains("my_client_secret"));
    assert!(!oauth_dbg.contains("my_refresh_token"));
    assert!(oauth_dbg.contains("REDACTED"));
}

#[tokio::test]
async fn test_oauth2_user_refresh_and_cache() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock-token-mock-user-token",
            "expires_in": 3600,
            "token_type": "Bearer"
        })))
        .expect(1) // Must be cached on second call!
        .mount(&server)
        .await;

    let mut cfg = BotoConfig::new();
    cfg.set("Credentials", "gs_oauth2_refresh_token", "1//refresh-xyz");
    cfg.set(
        "OAuth2",
        "provider_token_uri",
        format!("{}/token", server.uri()),
    );

    let creds = resolve_credentials_with_options(&cfg, &offline_options())
        .await
        .unwrap();
    assert_eq!(creds.credential_type(), CredentialType::OAuth2UserAccount);
    assert!(!creds.is_anonymous());

    let tok1 = creds.token().await.unwrap().unwrap();
    assert_eq!(tok1.token, "mock-token-mock-user-token");

    // Second call uses cache (wiremock expects exactly 1 POST).
    let tok2 = creds.token().await.unwrap().unwrap();
    assert_eq!(tok2.token, "mock-token-mock-user-token");
}

#[tokio::test]
async fn test_conflicting_boto_credentials_rejected() {
    let mut cfg = BotoConfig::new();
    cfg.set("Credentials", "gs_oauth2_refresh_token", "1//refresh-xyz");
    cfg.set(
        "Credentials",
        "gs_service_key_file",
        "/tmp/nonexistent.json",
    );

    let err = resolve_credentials_with_options(&cfg, &offline_options())
        .await
        .err()
        .expect("should reject multiple configured credential types");
    let msg = err.to_string();
    assert!(msg.contains("CommandException: You have multiple types of configured credentials"));
}

#[tokio::test]
async fn test_service_account_json_jwt_exchange_and_sign_blob() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock-token-mock-sa-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut rng = OsRng;
    let rsa_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pem = rsa_key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();

    let key_json = serde_json::json!({
        "type": "service_account",
        "project_id": "demo-proj",
        "private_key_id": "key-id-123",
        "private_key": pem,
        "client_email": "bot@demo-proj.iam.gserviceaccount.com",
        "client_id": "1234567890",
        "token_uri": format!("{}/token", server.uri())
    });

    let tmp = NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), serde_json::to_string(&key_json).unwrap()).unwrap();

    let mut cfg = BotoConfig::new();
    cfg.set(
        "Credentials",
        "gs_service_key_file",
        tmp.path().display().to_string(),
    );

    let creds = resolve_credentials_with_options(&cfg, &offline_options())
        .await
        .unwrap();
    assert_eq!(
        creds.credential_type(),
        CredentialType::OAuth2ServiceAccount
    );
    assert_eq!(
        creds.service_account_email(),
        Some("bot@demo-proj.iam.gserviceaccount.com")
    );

    let tok = creds.token().await.unwrap().unwrap();
    assert_eq!(tok.token, "mock-token-mock-sa-token");

    let (kid, sig) = creds.sign_blob(b"hello-world").await.unwrap();
    assert_eq!(kid, "key-id-123");
    assert_eq!(sig.len(), 256); // 2048-bit RSA signature
}

#[test]
fn test_service_account_json_missing_field_error() {
    let bad = r#"{"client_id": "1", "client_email": "a@b.com"}"#;
    let err = ServiceAccountCredentials::from_json_str(bad, "bad.json", None, Client::new())
        .err()
        .unwrap();
    assert!(err
        .to_string()
        .contains("did not contain the required entry: private_key_id"));
}

#[tokio::test]
async fn test_adc_authorized_user_loading() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock-token-adc-token",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    let adc_json = serde_json::json!({
        "type": "authorized_user",
        "client_id": "adc-cid",
        "client_secret": "adc-secret",
        "refresh_token": "1//adc-refresh",
        "quota_project_id": "my-quota-proj"
    });
    let tmp = NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), serde_json::to_string(&adc_json).unwrap()).unwrap();

    let mut cfg = BotoConfig::new();
    cfg.set(
        "OAuth2",
        "provider_token_uri",
        format!("{}/token", server.uri()),
    );

    let mut opts = offline_options();
    opts.allow_adc = true;
    opts.adc_path_override = Some(tmp.path().to_path_buf());

    let creds = resolve_credentials_with_options(&cfg, &opts).await.unwrap();
    assert_eq!(creds.credential_type(), CredentialType::ApplicationDefault);
    assert_eq!(creds.quota_project_id(), Some("my-quota-proj"));
    let tok = creds.token().await.unwrap().unwrap();
    assert_eq!(tok.token, "mock-token-adc-token");

    // Verify unsupported ADC type returns a clear error.
    let err = AdcCredentials::from_json_str(
        r#"{"type": "unknown_type"}"#,
        "adc.json",
        None,
        Client::new(),
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("Unsupported ADC credential type"));
}

#[tokio::test]
async fn test_gce_metadata_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/computeMetadata/v1/instance/service-accounts/default/token",
        ))
        .and(header("Metadata-Flavor", "Google"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock-token-gce-meta-token",
            "expires_in": 1800,
            "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let gce = GceMetadataCredentials::with_base_url(server.uri(), "default", Client::new());
    let tok = gce.token().await.unwrap().unwrap();
    assert_eq!(tok.token, "mock-token-gce-meta-token");
    assert_eq!(gce.credential_type(), CredentialType::Gce);
}

#[tokio::test]
async fn test_impersonation_credentials_token_and_sign_and_403() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock-token-source-token",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/target@proj.iam.gserviceaccount.com:generateAccessToken",
        ))
        .and(header("authorization", "Bearer mock-token-source-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "mock-token-impersonated-token",
            "expireTime": "2099-01-01T00:00:00Z"
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/target@proj.iam.gserviceaccount.com:signBlob",
        ))
        .and(header("authorization", "Bearer mock-token-source-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keyId": "imp-key-1",
            "signedBlob": "c2lnbmVkLWJ5dGVz"
        })))
        .mount(&server)
        .await;

    let mut cfg = BotoConfig::new();
    cfg.set("Credentials", "gs_oauth2_refresh_token", "1//src");
    cfg.set(
        "OAuth2",
        "provider_token_uri",
        format!("{}/token", server.uri()),
    );

    let mut opts = offline_options();
    opts.impersonate_service_account = Some("target@proj.iam.gserviceaccount.com".to_string());
    opts.iamcredentials_base_url = Some(server.uri());

    let creds = resolve_credentials_with_options(&cfg, &opts).await.unwrap();
    assert_eq!(creds.credential_type(), CredentialType::Impersonation);
    assert_eq!(
        creds.service_account_email(),
        Some("target@proj.iam.gserviceaccount.com")
    );
    let tok = creds.token().await.unwrap().unwrap();
    assert_eq!(tok.token, "mock-token-impersonated-token");

    let (kid, sig) = creds.sign_blob(b"payload").await.unwrap();
    assert_eq!(kid, "imp-key-1");
    assert_eq!(sig, b"signed-bytes");

    // Verify 403 "The caller does not have permission" translation.
    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/denied@proj.iam.gserviceaccount.com:generateAccessToken",
        ))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": {
                "code": 403,
                "message": "The caller does not have permission"
            }
        })))
        .mount(&server)
        .await;

    let src = Arc::new(OAuth2UserCredentials::new(
        "cid",
        "sec",
        "ref",
        format!("{}/token", server.uri()),
        None,
        CredentialType::OAuth2UserAccount,
        Client::new(),
    ));
    let imp_denied = ImpersonationCredentials::with_base_url(
        "denied@proj.iam.gserviceaccount.com",
        vec!["https://www.googleapis.com/auth/cloud-platform".to_string()],
        src,
        server.uri(),
        Client::new(),
    );
    let err = imp_denied.token().await.unwrap_err();
    match err {
        GsutilError::Service(se) => {
            assert_eq!(se.kind, ServiceErrorKind::AccessDenied);
            assert!(se.reason.contains("Service Account Token Creator"));
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[tokio::test]
async fn test_hmac_and_anonymous_fallback() {
    let mut cfg = BotoConfig::new();
    cfg.set("Credentials", "gs_access_key_id", "GOOG123");
    cfg.set("Credentials", "gs_secret_access_key", "SECRET456");

    let creds = resolve_credentials_with_options(&cfg, &offline_options())
        .await
        .unwrap();
    assert_eq!(creds.credential_type(), CredentialType::Hmac);
    assert_eq!(creds.hmac_credentials().unwrap().access_key_id, "GOOG123");
    assert!(creds.token().await.unwrap().is_none());

    // Empty config -> NoOpCredentials.
    let empty_cfg = BotoConfig::new();
    let anon = resolve_credentials_with_options(&empty_cfg, &offline_options())
        .await
        .unwrap();
    assert!(anon.is_anonymous());
    assert_eq!(anon.credential_type(), CredentialType::Anonymous);

    let noop = NoOpCredentials;
    assert!(noop.is_anonymous());
    assert!(noop.token().await.unwrap().is_none());
}

#[tokio::test]
async fn test_gcloud_disk_token_cache_hit_skips_subprocess() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("gcloud_token_cache.json");

    // Pre-populate cache with a valid non-expired token matching current env key.
    let cfg = std::env::var("CLOUDSDK_CONFIG").unwrap_or_default();
    let active = std::env::var("CLOUDSDK_ACTIVE_CONFIG_NAME").unwrap_or_default();
    let acct = std::env::var("CLOUDSDK_CORE_ACCOUNT").unwrap_or_default();
    let cache_key = format!("{cfg}|{active}|{acct}");
    let entry = serde_json::json!({
        "cache_key": cache_key,
        "access_token": "mock-token-cached-disk-token",
        "expires_at": "2099-01-01T00:00:00Z"
    });
    std::fs::write(&cache_path, serde_json::to_vec(&entry).unwrap()).unwrap();

    let gcloud = gsutil_auth::GcloudCredentials::with_cache_dir(dir.path().to_path_buf());
    let tok = gcloud.try_fetch_initial().await.unwrap();
    assert_eq!(tok.token, "mock-token-cached-disk-token");
    let tok2 = gcloud.token().await.unwrap().unwrap();
    assert_eq!(tok2.token, "mock-token-cached-disk-token");
}
