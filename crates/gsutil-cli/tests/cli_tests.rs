//! Integration tests for `gsutil-cli` covering CLI dispatch, global options,
//! error formatting, and all Phase 1 commands (`version`, `help`, `hash`, `mb`,
//! `rb`, `ls`, `stat`, `du`, `rm`, `cat`, `setmeta`) against an in-memory `CloudApi`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;

use gsutil_cli::context::CommandContext;
use gsutil_cli::dispatch::run_named_command;
use gsutil_cli::global_opts::GlobalOptions;
use gsutil_cli::run_cli_captured;
use gsutil_core::api::{
    Bucket, Channel, CloudApi, ComposeSourceObject, CopyOptions, CreateNotificationOptions,
    CsObjectOrPrefix, DownloadOptions, HmacKeyCreateResponse, HmacKeyMetadata, IamPolicy,
    ListObjectsOptions, Notification, Object, Preconditions, ServiceAccount, SignUrlOptions,
    UploadOptions,
};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result, ServiceError};
use gsutil_core::hash::{crc32c_base64, md5_base64};

#[derive(Default)]
struct MockState {
    buckets: BTreeMap<String, Bucket>,
    objects: BTreeMap<(String, String), (Object, Bytes)>,
}

#[derive(Clone, Default)]
struct MockCloudApi {
    state: Arc<Mutex<MockState>>,
}

impl MockCloudApi {
    fn seed_object(&self, bucket: &str, name: &str, data: &[u8]) {
        let mut st = self.state.lock().unwrap();
        let obj = Object {
            id: Some(format!("{bucket}/{name}/1")),
            bucket: Some(bucket.to_string()),
            name: Some(name.to_string()),
            size: Some(data.len().to_string()),
            generation: Some("1000".to_string()),
            metageneration: Some("1".to_string()),
            content_type: Some("text/plain".to_string()),
            storage_class: Some("STANDARD".to_string()),
            etag: Some("etag-123".to_string()),
            crc32c: Some(crc32c_base64(data)),
            md5_hash: Some(md5_base64(data)),
            time_created: Some("2024-01-01T12:00:00Z".to_string()),
            updated: Some("2024-01-01T12:00:00Z".to_string()),
            ..Default::default()
        };
        st.objects.insert(
            (bucket.to_string(), name.to_string()),
            (obj, Bytes::copy_from_slice(data)),
        );
    }
}

#[async_trait]
impl CloudApi for MockCloudApi {
    async fn get_service_account_id(&self) -> Result<String> {
        Ok("sa@test.iam.gserviceaccount.com".to_string())
    }

    async fn get_bucket(&self, bucket_name: &str, _fields: Option<&[String]>) -> Result<Bucket> {
        let st = self.state.lock().unwrap();
        st.buckets.get(bucket_name).cloned().ok_or_else(|| {
            ServiceError::bucket_not_found("Not Found", bucket_name, Some(404), None).into()
        })
    }

    async fn list_buckets(
        &self,
        _project_id: Option<&str>,
        _fields: Option<&[String]>,
    ) -> Result<Vec<Bucket>> {
        let st = self.state.lock().unwrap();
        Ok(st.buckets.values().cloned().collect())
    }

    async fn create_bucket(
        &self,
        bucket_name: &str,
        _project_id: Option<&str>,
        metadata: Option<&Bucket>,
        _fields: Option<&[String]>,
    ) -> Result<Bucket> {
        let mut st = self.state.lock().unwrap();
        if st.buckets.contains_key(bucket_name) {
            return Err(ServiceError::service("Bucket already exists", Some(409), None).into());
        }
        let mut b = metadata.cloned().unwrap_or_default();
        b.id = Some(bucket_name.to_string());
        b.name = Some(bucket_name.to_string());
        st.buckets.insert(bucket_name.to_string(), b.clone());
        Ok(b)
    }

    async fn patch_bucket(
        &self,
        bucket_name: &str,
        metadata: &Bucket,
        _canned_acl: Option<&str>,
        _canned_def_acl: Option<&str>,
        _preconditions: Option<&Preconditions>,
        _fields: Option<&[String]>,
    ) -> Result<Bucket> {
        let mut st = self.state.lock().unwrap();
        if !st.buckets.contains_key(bucket_name) {
            return Err(
                ServiceError::bucket_not_found("Not Found", bucket_name, Some(404), None).into(),
            );
        }
        st.buckets.insert(bucket_name.to_string(), metadata.clone());
        Ok(metadata.clone())
    }

    async fn delete_bucket(
        &self,
        bucket_name: &str,
        _preconditions: Option<&Preconditions>,
    ) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        if !st.buckets.contains_key(bucket_name) {
            return Err(
                ServiceError::bucket_not_found("Not Found", bucket_name, Some(404), None).into(),
            );
        }
        if st.objects.keys().any(|(b, _)| b == bucket_name) {
            return Err(ServiceError::not_empty(
                "The bucket you tried to delete is not empty.",
                Some(409),
                None,
            )
            .into());
        }
        st.buckets.remove(bucket_name);
        Ok(())
    }

    async fn lock_retention_policy(
        &self,
        _bucket_name: &str,
        _metageneration: i64,
    ) -> Result<Bucket> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn get_bucket_iam_policy(
        &self,
        _bucket_name: &str,
        _fields: Option<&[String]>,
    ) -> Result<IamPolicy> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn set_bucket_iam_policy(
        &self,
        _bucket_name: &str,
        _policy: &IamPolicy,
    ) -> Result<IamPolicy> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn list_objects(
        &self,
        bucket_name: &str,
        options: &ListObjectsOptions,
    ) -> Result<Vec<CsObjectOrPrefix>> {
        let st = self.state.lock().unwrap();
        if !st.buckets.contains_key(bucket_name) {
            return Err(
                ServiceError::bucket_not_found("Not Found", bucket_name, Some(404), None).into(),
            );
        }
        let prefix = options.prefix.as_deref().unwrap_or("");
        let delim = options.delimiter.as_deref();
        let mut results = Vec::new();
        let mut seen_prefixes = std::collections::BTreeSet::new();

        for ((b, name), (obj, _)) in &st.objects {
            if b != bucket_name || !name.starts_with(prefix) {
                continue;
            }
            if let Some(d) = delim {
                let rest = &name[prefix.len()..];
                if let Some(pos) = rest.find(d) {
                    let pref = format!("{}{}", prefix, &rest[..=pos]);
                    if seen_prefixes.insert(pref.clone()) {
                        results.push(CsObjectOrPrefix::Prefix(pref));
                    }
                    continue;
                }
            }
            results.push(CsObjectOrPrefix::Object(Box::new(obj.clone())));
        }
        Ok(results)
    }

    async fn get_object_metadata(
        &self,
        bucket_name: &str,
        object_name: &str,
        _generation: Option<&str>,
        _fields: Option<&[String]>,
    ) -> Result<Object> {
        let st = self.state.lock().unwrap();
        st.objects
            .get(&(bucket_name.to_string(), object_name.to_string()))
            .map(|(obj, _)| obj.clone())
            .ok_or_else(|| ServiceError::not_found("No such object", Some(404), None).into())
    }

    async fn patch_object_metadata(
        &self,
        bucket_name: &str,
        object_name: &str,
        metadata: &Object,
        _canned_acl: Option<&str>,
        _generation: Option<&str>,
        _preconditions: Option<&Preconditions>,
        _fields: Option<&[String]>,
    ) -> Result<Object> {
        let mut st = self.state.lock().unwrap();
        let entry = st
            .objects
            .get_mut(&(bucket_name.to_string(), object_name.to_string()))
            .ok_or_else(|| ServiceError::not_found("No such object", Some(404), None))?;
        if metadata.cache_control.is_some() {
            entry.0.cache_control = metadata.cache_control.clone();
        }
        if metadata.clear_fields.iter().any(|f| f == "cacheControl") {
            entry.0.cache_control = None;
        }
        if metadata.content_type.is_some() {
            entry.0.content_type = metadata.content_type.clone();
        }
        if metadata.clear_fields.iter().any(|f| f == "contentType") {
            entry.0.content_type = None;
        }
        if let Some(ref m) = metadata.metadata {
            let map = entry.0.metadata.get_or_insert_with(BTreeMap::new);
            for (k, v) in m {
                map.insert(k.clone(), v.clone());
            }
        }
        for removed in &metadata.metadata_removals {
            if let Some(ref mut map) = entry.0.metadata {
                map.remove(removed);
            }
        }
        Ok(entry.0.clone())
    }

    async fn get_object_iam_policy(
        &self,
        _bucket_name: &str,
        _object_name: &str,
        _generation: Option<&str>,
        _fields: Option<&[String]>,
    ) -> Result<IamPolicy> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn set_object_iam_policy(
        &self,
        _bucket_name: &str,
        _object_name: &str,
        _policy: &IamPolicy,
        _generation: Option<&str>,
    ) -> Result<IamPolicy> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn get_object_media(
        &self,
        bucket_name: &str,
        object_name: &str,
        options: &DownloadOptions,
    ) -> Result<Bytes> {
        let st = self.state.lock().unwrap();
        let (_, data) = st
            .objects
            .get(&(bucket_name.to_string(), object_name.to_string()))
            .ok_or_else(|| ServiceError::not_found("No such object", Some(404), None))?;
        let len = data.len();
        let start = match options.start_byte {
            Some(s) if s < 0 => len.saturating_sub((-s) as usize),
            Some(s) => (s as usize).min(len),
            None => 0,
        };
        let end = match options.end_byte {
            Some(e) => ((e as usize) + 1).min(len),
            None => len,
        };
        if start >= end {
            return Ok(Bytes::new());
        }
        Ok(data.slice(start..end))
    }

    async fn upload_object(
        &self,
        _data: Bytes,
        _object_metadata: &Object,
        _options: &UploadOptions,
    ) -> Result<Object> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn upload_object_resumable(
        &self,
        _data: Bytes,
        _object_metadata: &Object,
        _options: &UploadOptions,
    ) -> Result<Object> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn copy_object(
        &self,
        _src_obj_metadata: &Object,
        _dst_obj_metadata: &Object,
        _options: &CopyOptions,
    ) -> Result<Object> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn compose_object(
        &self,
        _src_objs: &[ComposeSourceObject],
        _dst_obj_metadata: &Object,
        _preconditions: Option<&Preconditions>,
        _encryption_key: Option<&gsutil_core::api::EncryptionKey>,
        _fields: Option<&[String]>,
    ) -> Result<Object> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn delete_object(
        &self,
        bucket_name: &str,
        object_name: &str,
        _generation: Option<&str>,
        _preconditions: Option<&Preconditions>,
    ) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        st.objects
            .remove(&(bucket_name.to_string(), object_name.to_string()))
            .ok_or_else(|| ServiceError::not_found("No such object", Some(404), None))?;
        Ok(())
    }

    async fn watch_bucket(
        &self,
        _bucket_name: &str,
        _address: &str,
        _channel_id: &str,
        _token: Option<&str>,
    ) -> Result<Channel> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn stop_channel(&self, _channel_id: &str, _resource_id: &str) -> Result<()> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn get_project_service_account(&self, _project_id: &str) -> Result<ServiceAccount> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn create_notification_config(
        &self,
        _bucket_name: &str,
        _options: &CreateNotificationOptions,
    ) -> Result<Notification> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn delete_notification_config(
        &self,
        _bucket_name: &str,
        _notification_id: &str,
    ) -> Result<()> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn list_notification_configs(&self, _bucket_name: &str) -> Result<Vec<Notification>> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn create_hmac_key(
        &self,
        _project_id: &str,
        _service_account_email: &str,
    ) -> Result<HmacKeyCreateResponse> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn delete_hmac_key(&self, _project_id: &str, _access_id: &str) -> Result<()> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn get_hmac_key(&self, _project_id: &str, _access_id: &str) -> Result<HmacKeyMetadata> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn list_hmac_keys(
        &self,
        _project_id: &str,
        _service_account_email: Option<&str>,
        _show_deleted_keys: bool,
    ) -> Result<Vec<HmacKeyMetadata>> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn update_hmac_key(
        &self,
        _project_id: &str,
        _access_id: &str,
        _state: &str,
        _etag: Option<&str>,
    ) -> Result<HmacKeyMetadata> {
        Err(GsutilError::command("unimplemented"))
    }

    async fn sign_url(&self, _options: &SignUrlOptions) -> Result<String> {
        Err(GsutilError::command("unimplemented"))
    }
}

fn s(items: &[&str]) -> Vec<String> {
    items.iter().map(|x| (*x).to_string()).collect()
}

#[tokio::test]
async fn test_cli_exit_codes_no_args_vs_help_flag() {
    let r = run_cli_captured(&s(&["gsutil"]), None).await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("Available commands:"));

    let r = run_cli_captured(&s(&["gsutil", "-?"]), None).await;
    assert_eq!(r.exit_code, 1);
    assert!(r.stdout.contains("Usage: gsutil"));

    let r = run_cli_captured(&s(&["gsutil", "--help"]), None).await;
    assert_eq!(r.exit_code, 1);
    assert!(r.stdout.contains("Usage: gsutil"));

    let r = run_cli_captured(&s(&["gsutil", "-v"]), None).await;
    assert_eq!(r.exit_code, 0);
    assert_eq!(r.stdout.trim(), "gsutil version: 5.38");

    let r = run_cli_captured(&s(&["gsutil", "version", "-l"]), None).await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("gsutil version: 5.38"));
    assert!(r.stdout.contains("compiled crcmod: True"));

    let r = run_cli_captured(&s(&["gsutil", "unknowncmd"]), None).await;
    assert_eq!(r.exit_code, 1);
    assert!(r
        .stderr
        .contains("CommandException: Invalid command \"unknowncmd\"."));
}

#[tokio::test]
async fn test_hash_local_and_cloud_filtering() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("hello.txt");
    std::fs::write(&f, b"hello").unwrap();
    let path_str = f.to_string_lossy().to_string();

    let r = run_cli_captured(&s(&["gsutil", "hash", &path_str]), None).await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("Hash (crc32c):\t\tmnG7TA=="));
    assert!(r.stdout.contains("Hash (md5):\t\tXUFAKrxLKna5cZ2REBfFkg=="));

    let r = run_cli_captured(&s(&["gsutil", "hash", "-c", "-h", &path_str]), None).await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("Hash (crc32c):\t\t9A71BB4C"));
    assert!(!r.stdout.contains("Hash (md5):"));

    let r = run_cli_captured(&s(&["gsutil", "hash", "/nonexistent/file/xyz"]), None).await;
    assert_eq!(r.exit_code, 1);
    assert!(r.stderr.contains("CommandException: No files matched"));

    // Cloud object hash filtering (-c only vs -m only)
    let mock = Arc::new(MockCloudApi::default());
    let api: Arc<dyn CloudApi> = mock.clone();
    assert_eq!(
        run_cli_captured(&s(&["gsutil", "mb", "gs://hash-bkt"]), Some(api.clone()))
            .await
            .exit_code,
        0
    );
    mock.seed_object("hash-bkt", "hello.txt", b"hello");

    let r_c = run_cli_captured(
        &s(&["gsutil", "hash", "-c", "gs://hash-bkt/hello.txt"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r_c.exit_code, 0);
    assert!(r_c.stdout.contains("Hash (crc32c):\t\tmnG7TA=="));
    assert!(!r_c.stdout.contains("Hash (md5):"));

    let r_m = run_cli_captured(
        &s(&["gsutil", "hash", "-m", "gs://hash-bkt/hello.txt"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r_m.exit_code, 0);
    assert!(r_m
        .stdout
        .contains("Hash (md5):\t\tXUFAKrxLKna5cZ2REBfFkg=="));
    assert!(!r_m.stdout.contains("Hash (crc32c):"));
}

#[tokio::test]
async fn test_mb_ls_stat_du_cat_setmeta_rm_rb_lifecycle() {
    let mock = Arc::new(MockCloudApi::default());
    let api: Arc<dyn CloudApi> = mock.clone();

    // mb
    let r = run_cli_captured(
        &s(&[
            "gsutil",
            "mb",
            "-l",
            "us-central1",
            "-c",
            "nearline",
            "gs://my-test-bkt",
        ]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stderr.contains("Creating gs://my-test-bkt/..."));
    assert!(mock
        .state
        .lock()
        .unwrap()
        .buckets
        .contains_key("my-test-bkt"));

    // Seed objects
    mock.seed_object("my-test-bkt", "a.txt", b"hello world");
    mock.seed_object("my-test-bkt", "sub/b.txt", b"goodbye");
    mock.seed_object("my-test-bkt", "long.txt", b"0123456789abcdefghij");

    // ls variants
    let r = run_cli_captured(&s(&["gsutil", "ls"]), Some(api.clone())).await;
    assert_eq!(r.exit_code, 0);
    assert_eq!(r.stdout.trim(), "gs://my-test-bkt/");

    let r = run_cli_captured(
        &s(&["gsutil", "ls", "-l", "-h", "gs://my-test-bkt"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("gs://my-test-bkt/a.txt"));
    assert!(r.stdout.contains("TOTAL: 2 objects, 31 bytes"));

    let r = run_cli_captured(
        &s(&["gsutil", "ls", "-L", "-b", "gs://my-test-bkt"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("Storage class:\t\t\tNEARLINE"));
    assert!(r.stdout.contains("Location constraint:\t\tus-central1"));

    let r = run_cli_captured(
        &s(&["gsutil", "ls", "-r", "gs://my-test-bkt"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("gs://my-test-bkt/sub/:"));
    assert!(r.stdout.contains("gs://my-test-bkt/sub/b.txt"));

    let r = run_cli_captured(
        &s(&["gsutil", "ls", "gs://my-test-bkt/sub/"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    assert_eq!(r.stdout.trim(), "gs://my-test-bkt/sub/b.txt");

    // stat existing & missing
    let r = run_cli_captured(
        &s(&["gsutil", "stat", "gs://my-test-bkt/a.txt"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("Content-Length:         11"));

    let r = run_cli_captured(
        &s(&["gsutil", "-q", "stat", "gs://my-test-bkt/missing.txt"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 1);
    assert!(r.stdout.is_empty());
    assert!(r.stderr.is_empty());

    // du
    let r = run_cli_captured(
        &s(&["gsutil", "du", "-s", "-h", "-c", "gs://my-test-bkt"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("38 B         gs://my-test-bkt"));
    assert!(r.stdout.contains("38 B         total"));

    let r = run_cli_captured(&s(&["gsutil", "du", "gs://my-test-bkt"]), Some(api.clone())).await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("7            gs://my-test-bkt/sub/b.txt"));
    assert!(r.stdout.contains("7            gs://my-test-bkt/sub/"));

    let r = run_cli_captured(
        &s(&["gsutil", "du", "gs://my-test-bkt/sub/"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    assert_eq!(r.stdout.trim(), "7            gs://my-test-bkt/sub/b.txt");

    // cat with range + multi-object range continuation past short object
    let r = run_cli_captured(
        &s(&["gsutil", "cat", "-r", "0-4", "gs://my-test-bkt/a.txt"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    assert_eq!(r.stdout, "hello");

    let r = run_cli_captured(
        &s(&[
            "gsutil",
            "cat",
            "-r",
            "15-19",
            "gs://my-test-bkt/a.txt",
            "gs://my-test-bkt/long.txt",
        ]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    assert_eq!(r.stdout, "fghij");

    // setmeta set + parallel -m + remove (null tombstones)
    let r = run_cli_captured(
        &s(&[
            "gsutil",
            "-m",
            "setmeta",
            "-h",
            "Cache-Control:public, max-age=60",
            "-h",
            "x-goog-meta-color:blue",
            "gs://my-test-bkt/a.txt",
        ]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    {
        let st = mock.state.lock().unwrap();
        let (obj, _) = st
            .objects
            .get(&("my-test-bkt".to_string(), "a.txt".to_string()))
            .unwrap();
        assert_eq!(obj.cache_control.as_deref(), Some("public, max-age=60"));
        assert_eq!(
            obj.metadata
                .as_ref()
                .and_then(|m| m.get("color"))
                .map(String::as_str),
            Some("blue")
        );
    }

    let r = run_cli_captured(
        &s(&[
            "gsutil",
            "setmeta",
            "-h",
            "Cache-Control",
            "-h",
            "x-goog-meta-color",
            "gs://my-test-bkt/a.txt",
        ]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    {
        let st = mock.state.lock().unwrap();
        let (obj, _) = st
            .objects
            .get(&("my-test-bkt".to_string(), "a.txt".to_string()))
            .unwrap();
        assert_eq!(obj.cache_control, None);
        assert_eq!(obj.metadata.as_ref().and_then(|m| m.get("color")), None);
    }

    // rb on non-empty bucket should fail (409 NotEmpty)
    let r = run_cli_captured(&s(&["gsutil", "rb", "gs://my-test-bkt"]), Some(api.clone())).await;
    assert_eq!(r.exit_code, 1);
    assert!(r.stderr.contains("NotEmptyException: 409"));

    // rm single object
    let r = run_cli_captured(
        &s(&["gsutil", "rm", "gs://my-test-bkt/a.txt"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stderr.contains("Removing gs://my-test-bkt/a.txt..."));

    // rm -r remaining bucket + objects
    let r = run_cli_captured(
        &s(&["gsutil", "rm", "-r", "gs://my-test-bkt"]),
        Some(api.clone()),
    )
    .await;
    assert_eq!(r.exit_code, 0);
    assert!(!mock
        .state
        .lock()
        .unwrap()
        .buckets
        .contains_key("my-test-bkt"));
}

#[tokio::test]
async fn test_help_subcommands_and_deprecated_alias_warning() {
    let r = run_cli_captured(&s(&["gsutil", "help", "acl", "set"]), None).await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("acl set"));

    let r = run_cli_captured(&s(&["gsutil", "help", "crc32c"]), None).await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("CRC32C"));

    let r = run_cli_captured(&s(&["gsutil", "help", "getacl"]), None).await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("DEPRECATION WARNING"));

    let r = run_cli_captured(&s(&["gsutil", "help", "nonexistent"]), None).await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("No help available for \"nonexistent\""));

    // Executing a deprecated OLD_ALIAS_MAP alias emits the deprecation warning on stderr.
    let mock = Arc::new(MockCloudApi::default());
    let api: Arc<dyn CloudApi> = mock.clone();
    let r = run_cli_captured(&s(&["gsutil", "getversioning", "gs://missing"]), Some(api)).await;
    assert!(r.stderr.contains(
        "You are using a deprecated alias, \"getversioning\", for the \"versioning\" command."
    ));
}

#[tokio::test]
async fn test_rsync_offline_flag_validation() {
    let mut ctx = CommandContext::new(BotoConfig::new(), GlobalOptions::default(), None);

    let e1 = run_named_command(&mut ctx, "rsync", &s(&["-x", "", "gs://b1", "gs://b2"]))
        .await
        .unwrap_err();
    assert_eq!(
        e1.to_string(),
        "CommandException: Invalid blank exclude filter"
    );

    let e2 = run_named_command(&mut ctx, "rsync", &s(&["-x", "[", "gs://b1", "gs://b2"]))
        .await
        .unwrap_err();
    assert_eq!(
        e2.to_string(),
        "CommandException: Invalid exclude filter ([)"
    );

    let e3 = run_named_command(
        &mut ctx,
        "rsync",
        &s(&["-p", "-a", "public-read", "gs://b1", "gs://b2"]),
    )
    .await
    .unwrap_err();
    assert_eq!(
        e3.to_string(),
        "CommandException: Specifying both the -p and -a options together is invalid."
    );

    let e4 = run_named_command(
        &mut ctx,
        "rsync",
        &s(&["-j", "html", "-J", "gs://b1", "gs://b2"]),
    )
    .await
    .unwrap_err();
    assert_eq!(
        e4.to_string(),
        "CommandException: Specifying both the -j and -J options together is invalid."
    );
}

#[tokio::test]
async fn test_config_and_test_commands() {
    let dir = tempfile::tempdir().unwrap();
    let boto_path = dir.path().join("test.boto");
    let path_str = boto_path.to_string_lossy().to_string();

    let r = run_cli_captured(&s(&["gsutil", "config", "-n", "-o", &path_str]), None).await;
    assert_eq!(r.exit_code, 0);
    let content = std::fs::read_to_string(&boto_path).unwrap();
    assert!(content.contains("[Credentials]"));
    assert!(content.contains("[GSUtil]"));

    let r = run_cli_captured(&s(&["gsutil", "test", "-l"]), None).await;
    assert_eq!(r.exit_code, 0);
    assert!(r.stdout.contains("cargo test --workspace"));
}
