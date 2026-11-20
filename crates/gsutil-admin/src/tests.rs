//! Comprehensive unit tests for all 21 `gsutil-admin` commands using an in-memory `MockCloudApi`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;

use gsutil_core::api::{
    Bucket, BucketAccessControl, Channel, CloudApi, ComposeSourceObject, CopyOptions,
    CreateNotificationOptions, CsObjectOrPrefix, DownloadOptions, EncryptionKey,
    HmacKeyCreateResponse, HmacKeyMetadata, IamBinding, IamCondition, IamPolicy,
    ListObjectsOptions, Notification, Object, Preconditions, ServiceAccount, SignUrlOptions,
    UploadOptions,
};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result, ServiceError};

use crate::{dispatch_admin_command, is_admin_command, parse_duration_secs, AdminContext};

#[derive(Default)]
struct MockState {
    buckets: BTreeMap<String, Bucket>,
    objects: BTreeMap<(String, String), Object>,
    bucket_iam: BTreeMap<String, IamPolicy>,
    object_iam: BTreeMap<(String, String), IamPolicy>,
    notifications: BTreeMap<String, Vec<Notification>>,
    hmac_keys: BTreeMap<String, HmacKeyMetadata>,
    next_id: u64,
}

#[derive(Default)]
struct MockCloudApi {
    state: Mutex<MockState>,
}

impl MockCloudApi {
    fn with_bucket(name: &str) -> Self {
        let api = Self::default();
        {
            let mut st = api.state.lock().unwrap();
            st.buckets.insert(
                name.to_string(),
                Bucket {
                    id: Some(name.to_string()),
                    name: Some(name.to_string()),
                    metageneration: Some("1".to_string()),
                    storage_class: Some("STANDARD".to_string()),
                    acl: Some(vec![BucketAccessControl {
                        entity: Some("project-owners-123".to_string()),
                        role: Some("OWNER".to_string()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
            );
            st.objects.insert(
                (name.to_string(), "file.txt".to_string()),
                Object {
                    bucket: Some(name.to_string()),
                    name: Some("file.txt".to_string()),
                    generation: Some("1001".to_string()),
                    ..Default::default()
                },
            );
        }
        api
    }
}

#[async_trait]
impl CloudApi for MockCloudApi {
    async fn get_service_account_id(&self) -> Result<String> {
        Ok("sa@test-project.iam.gserviceaccount.com".to_string())
    }

    async fn get_bucket(&self, bucket_name: &str, _fields: Option<&[String]>) -> Result<Bucket> {
        let st = self.state.lock().unwrap();
        st.buckets.get(bucket_name).cloned().ok_or_else(|| {
            GsutilError::from(ServiceError::bucket_not_found(
                format!("gs://{bucket_name} does not exist."),
                bucket_name,
                Some(404),
                None,
            ))
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
        let mut b = metadata.cloned().unwrap_or_default();
        b.name = Some(bucket_name.to_string());
        b.id = Some(bucket_name.to_string());
        self.state
            .lock()
            .unwrap()
            .buckets
            .insert(bucket_name.to_string(), b.clone());
        Ok(b)
    }

    async fn patch_bucket(
        &self,
        bucket_name: &str,
        metadata: &Bucket,
        canned_acl: Option<&str>,
        canned_def_acl: Option<&str>,
        _preconditions: Option<&Preconditions>,
        _fields: Option<&[String]>,
    ) -> Result<Bucket> {
        let mut st = self.state.lock().unwrap();
        let b = st.buckets.get_mut(bucket_name).ok_or_else(|| {
            GsutilError::from(ServiceError::bucket_not_found(
                "not found",
                bucket_name,
                Some(404),
                None,
            ))
        })?;
        if metadata.versioning.is_some() {
            b.versioning = metadata.versioning.clone();
        }
        if metadata.cors.is_some() {
            b.cors = metadata.cors.clone();
        }
        if metadata.lifecycle.is_some() {
            b.lifecycle = metadata.lifecycle.clone();
        }
        if metadata.logging.is_some() {
            b.logging = metadata.logging.clone();
        }
        if metadata.website.is_some() {
            b.website = metadata.website.clone();
        }
        if metadata.labels.is_some() {
            b.labels = metadata.labels.clone();
        }
        if metadata.billing.is_some() {
            b.billing = metadata.billing.clone();
        }
        if metadata.storage_class.is_some() {
            b.storage_class = metadata.storage_class.clone();
        }
        if metadata.iam_configuration.is_some() {
            b.iam_configuration = metadata.iam_configuration.clone();
        }
        if metadata.rpo.is_some() {
            b.rpo = metadata.rpo.clone();
        }
        if metadata.autoclass.is_some() {
            b.autoclass = metadata.autoclass.clone();
        }
        if metadata.retention_policy.is_some() {
            b.retention_policy = metadata.retention_policy.clone();
        }
        if metadata.default_event_based_hold.is_some() {
            b.default_event_based_hold = metadata.default_event_based_hold;
        }
        if metadata.encryption.is_some() {
            b.encryption = metadata.encryption.clone();
        }
        if metadata.acl.is_some() {
            b.acl = metadata.acl.clone();
        } else if let Some(canned) = canned_acl {
            b.acl = Some(vec![BucketAccessControl {
                entity: Some(format!("canned:{canned}")),
                role: Some("READER".to_string()),
                ..Default::default()
            }]);
        }
        if metadata.default_object_acl.is_some() {
            b.default_object_acl = metadata.default_object_acl.clone();
        } else if let Some(canned) = canned_def_acl {
            b.default_object_acl = Some(vec![gsutil_core::api::ObjectAccessControl {
                entity: Some(format!("canned:{canned}")),
                role: Some("READER".to_string()),
                ..Default::default()
            }]);
        }
        Ok(b.clone())
    }

    async fn delete_bucket(
        &self,
        bucket_name: &str,
        _preconditions: Option<&Preconditions>,
    ) -> Result<()> {
        self.state.lock().unwrap().buckets.remove(bucket_name);
        Ok(())
    }

    async fn lock_retention_policy(
        &self,
        bucket_name: &str,
        _metageneration: i64,
    ) -> Result<Bucket> {
        let mut st = self.state.lock().unwrap();
        let b = st.buckets.get_mut(bucket_name).unwrap();
        if let Some(ref mut rp) = b.retention_policy {
            rp.is_locked = Some(true);
        }
        Ok(b.clone())
    }

    async fn get_bucket_iam_policy(
        &self,
        bucket_name: &str,
        _fields: Option<&[String]>,
    ) -> Result<IamPolicy> {
        let st = self.state.lock().unwrap();
        Ok(st
            .bucket_iam
            .get(bucket_name)
            .cloned()
            .unwrap_or_else(|| IamPolicy {
                version: Some(1),
                etag: Some("etag-1".to_string()),
                bindings: Vec::new(),
                ..Default::default()
            }))
    }

    async fn set_bucket_iam_policy(
        &self,
        bucket_name: &str,
        policy: &IamPolicy,
    ) -> Result<IamPolicy> {
        self.state
            .lock()
            .unwrap()
            .bucket_iam
            .insert(bucket_name.to_string(), policy.clone());
        Ok(policy.clone())
    }

    async fn list_objects(
        &self,
        bucket_name: &str,
        options: &ListObjectsOptions,
    ) -> Result<Vec<CsObjectOrPrefix>> {
        let st = self.state.lock().unwrap();
        let mut out = Vec::new();
        for ((b, name), obj) in &st.objects {
            if b == bucket_name {
                if let Some(ref p) = options.prefix {
                    if !name.starts_with(p) {
                        continue;
                    }
                }
                out.push(CsObjectOrPrefix::Object(Box::new(obj.clone())));
            }
        }
        Ok(out)
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
            .cloned()
            .ok_or_else(|| GsutilError::from(ServiceError::not_found("not found", Some(404), None)))
    }

    async fn patch_object_metadata(
        &self,
        bucket_name: &str,
        object_name: &str,
        metadata: &Object,
        canned_acl: Option<&str>,
        _generation: Option<&str>,
        _preconditions: Option<&Preconditions>,
        _fields: Option<&[String]>,
    ) -> Result<Object> {
        let mut st = self.state.lock().unwrap();
        let obj = st
            .objects
            .get_mut(&(bucket_name.to_string(), object_name.to_string()))
            .ok_or_else(|| {
                GsutilError::from(ServiceError::not_found("not found", Some(404), None))
            })?;
        if metadata.event_based_hold.is_some() {
            obj.event_based_hold = metadata.event_based_hold;
        }
        if metadata.temporary_hold.is_some() {
            obj.temporary_hold = metadata.temporary_hold;
        }
        if metadata.acl.is_some() {
            obj.acl = metadata.acl.clone();
        } else if let Some(canned) = canned_acl {
            obj.acl = Some(vec![gsutil_core::api::ObjectAccessControl {
                entity: Some(format!("canned:{canned}")),
                role: Some("READER".to_string()),
                ..Default::default()
            }]);
        }
        Ok(obj.clone())
    }

    async fn get_object_iam_policy(
        &self,
        bucket_name: &str,
        object_name: &str,
        _generation: Option<&str>,
        _fields: Option<&[String]>,
    ) -> Result<IamPolicy> {
        let st = self.state.lock().unwrap();
        Ok(st
            .object_iam
            .get(&(bucket_name.to_string(), object_name.to_string()))
            .cloned()
            .unwrap_or_default())
    }

    async fn set_object_iam_policy(
        &self,
        bucket_name: &str,
        object_name: &str,
        policy: &IamPolicy,
        _generation: Option<&str>,
    ) -> Result<IamPolicy> {
        self.state.lock().unwrap().object_iam.insert(
            (bucket_name.to_string(), object_name.to_string()),
            policy.clone(),
        );
        Ok(policy.clone())
    }

    async fn get_object_media(
        &self,
        _bucket_name: &str,
        _object_name: &str,
        _options: &DownloadOptions,
    ) -> Result<Bytes> {
        Ok(Bytes::new())
    }

    async fn upload_object(
        &self,
        _data: Bytes,
        object_metadata: &Object,
        _options: &UploadOptions,
    ) -> Result<Object> {
        Ok(object_metadata.clone())
    }

    async fn upload_object_resumable(
        &self,
        _data: Bytes,
        object_metadata: &Object,
        _options: &UploadOptions,
    ) -> Result<Object> {
        Ok(object_metadata.clone())
    }

    async fn copy_object(
        &self,
        _src_obj_metadata: &Object,
        dst_obj_metadata: &Object,
        _options: &CopyOptions,
    ) -> Result<Object> {
        Ok(dst_obj_metadata.clone())
    }

    async fn compose_object(
        &self,
        _src_objs: &[ComposeSourceObject],
        dst_obj_metadata: &Object,
        _preconditions: Option<&Preconditions>,
        _encryption_key: Option<&EncryptionKey>,
        _fields: Option<&[String]>,
    ) -> Result<Object> {
        Ok(dst_obj_metadata.clone())
    }

    async fn delete_object(
        &self,
        bucket_name: &str,
        object_name: &str,
        _generation: Option<&str>,
        _preconditions: Option<&Preconditions>,
    ) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .objects
            .remove(&(bucket_name.to_string(), object_name.to_string()));
        Ok(())
    }

    async fn watch_bucket(
        &self,
        _bucket_name: &str,
        address: &str,
        channel_id: &str,
        token: Option<&str>,
    ) -> Result<Channel> {
        Ok(Channel {
            id: Some(channel_id.to_string()),
            resource_id: Some("res-12345".to_string()),
            address: Some(address.to_string()),
            token: token.map(ToString::to_string),
            ..Default::default()
        })
    }

    async fn stop_channel(&self, _channel_id: &str, _resource_id: &str) -> Result<()> {
        Ok(())
    }

    async fn get_project_service_account(&self, project_id: &str) -> Result<ServiceAccount> {
        Ok(ServiceAccount {
            email_address: Some(format!(
                "service-{project_id}@gs-project-accounts.iam.gserviceaccount.com"
            )),
            ..Default::default()
        })
    }

    async fn create_notification_config(
        &self,
        bucket_name: &str,
        options: &CreateNotificationOptions,
    ) -> Result<Notification> {
        let mut st = self.state.lock().unwrap();
        st.next_id += 1;
        let id = st.next_id.to_string();
        let notif = Notification {
            id: Some(id.clone()),
            topic: Some(options.pubsub_topic.clone()),
            payload_format: Some(options.payload_format.clone()),
            event_types: options.event_types.clone(),
            custom_attributes: options.custom_attributes.clone(),
            object_name_prefix: options.object_name_prefix.clone(),
            self_link: Some(format!(
                "projects/_/buckets/{bucket_name}/notificationConfigs/{id}"
            )),
            ..Default::default()
        };
        st.notifications
            .entry(bucket_name.to_string())
            .or_default()
            .push(notif.clone());
        Ok(notif)
    }

    async fn delete_notification_config(
        &self,
        bucket_name: &str,
        notification_id: &str,
    ) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        if let Some(list) = st.notifications.get_mut(bucket_name) {
            list.retain(|n| n.id.as_deref() != Some(notification_id));
        }
        Ok(())
    }

    async fn list_notification_configs(&self, bucket_name: &str) -> Result<Vec<Notification>> {
        let st = self.state.lock().unwrap();
        Ok(st
            .notifications
            .get(bucket_name)
            .cloned()
            .unwrap_or_default())
    }

    async fn create_hmac_key(
        &self,
        project_id: &str,
        service_account_email: &str,
    ) -> Result<HmacKeyCreateResponse> {
        let mut st = self.state.lock().unwrap();
        st.next_id += 1;
        let access_id = format!("GOOG1EKEY{}", st.next_id);
        let meta = HmacKeyMetadata {
            access_id: Some(access_id.clone()),
            project_id: Some(project_id.to_string()),
            service_account_email: Some(service_account_email.to_string()),
            state: Some("ACTIVE".to_string()),
            time_created: Some("2025-01-15T12:00:00Z".to_string()),
            updated: Some("2025-01-15T12:00:00Z".to_string()),
            etag: Some("etag-hmac-1".to_string()),
            ..Default::default()
        };
        st.hmac_keys.insert(access_id, meta.clone());
        Ok(HmacKeyCreateResponse {
            kind: Some("storage#hmacKeyCreate".to_string()),
            secret: "SUPER_SECRET_KEY_MATERIAL".to_string(),
            metadata: meta,
        })
    }

    async fn delete_hmac_key(&self, _project_id: &str, access_id: &str) -> Result<()> {
        self.state.lock().unwrap().hmac_keys.remove(access_id);
        Ok(())
    }

    async fn get_hmac_key(&self, _project_id: &str, access_id: &str) -> Result<HmacKeyMetadata> {
        self.state
            .lock()
            .unwrap()
            .hmac_keys
            .get(access_id)
            .cloned()
            .ok_or_else(|| {
                GsutilError::from(ServiceError::not_found(
                    "HMAC key not found",
                    Some(404),
                    None,
                ))
            })
    }

    async fn list_hmac_keys(
        &self,
        _project_id: &str,
        service_account_email: Option<&str>,
        _show_deleted_keys: bool,
    ) -> Result<Vec<HmacKeyMetadata>> {
        let st = self.state.lock().unwrap();
        Ok(st
            .hmac_keys
            .values()
            .filter(|k| {
                service_account_email
                    .is_none_or(|sa| k.service_account_email.as_deref() == Some(sa))
            })
            .cloned()
            .collect())
    }

    async fn update_hmac_key(
        &self,
        _project_id: &str,
        access_id: &str,
        state: &str,
        _etag: Option<&str>,
    ) -> Result<HmacKeyMetadata> {
        let mut st = self.state.lock().unwrap();
        let k = st.hmac_keys.get_mut(access_id).ok_or_else(|| {
            GsutilError::from(ServiceError::not_found(
                "HMAC key not found",
                Some(404),
                None,
            ))
        })?;
        k.state = Some(state.to_string());
        Ok(k.clone())
    }

    async fn sign_url(&self, options: &SignUrlOptions) -> Result<String> {
        Ok(format!(
            "https://storage.googleapis.com/{}?x-goog-signature=iam-signed",
            options.path
        ))
    }
}

async fn run_cmd(api: &MockCloudApi, cmd: &str, args: &[&str]) -> Result<(String, String)> {
    let cfg = BotoConfig::new();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let arg_vec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let mut ctx = AdminContext {
        api,
        config: &cfg,
        project_id: Some("my-proj".to_string()),
        parallel_operations: false,
        out: &mut out,
        err: &mut err,
    };
    dispatch_admin_command(cmd, &mut ctx, &arg_vec)
        .await
        .expect("expected admin command")?;
    Ok((
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    ))
}

#[test]
fn test_is_admin_command_covers_all_21() {
    let all = [
        "versioning",
        "cors",
        "lifecycle",
        "logging",
        "web",
        "label",
        "requesterpays",
        "defstorageclass",
        "ubla",
        "bucketpolicyonly",
        "pap",
        "rpo",
        "autoclass",
        "retention",
        "acl",
        "defacl",
        "iam",
        "kms",
        "hmac",
        "notification",
        "signurl",
    ];
    assert_eq!(all.len(), 21);
    for c in all {
        assert!(is_admin_command(c), "missing admin command: {c}");
    }
    assert!(!is_admin_command("ls"));
}

#[test]
fn test_parse_duration_secs() {
    assert_eq!(parse_duration_secs("10s").unwrap(), 10);
    assert_eq!(parse_duration_secs("5m").unwrap(), 300);
    assert_eq!(parse_duration_secs("2h").unwrap(), 7200);
    assert_eq!(parse_duration_secs("1d").unwrap(), 86_400);
    assert_eq!(parse_duration_secs("1y").unwrap(), 31_557_600);
    assert!(parse_duration_secs("10x").is_err());
}

#[tokio::test]
async fn test_bucket_config_commands() {
    let api = MockCloudApi::with_bucket("test-bkt");

    // versioning
    let (out, _) = run_cmd(&api, "versioning", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert_eq!(out.trim(), "gs://test-bkt: Suspended");
    run_cmd(&api, "versioning", &["set", "on", "gs://test-bkt"])
        .await
        .unwrap();
    let (out, _) = run_cmd(&api, "versioning", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert_eq!(out.trim(), "gs://test-bkt: Enabled");

    // requesterpays
    run_cmd(&api, "requesterpays", &["set", "on", "gs://test-bkt"])
        .await
        .unwrap();
    let (out, _) = run_cmd(&api, "requesterpays", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert_eq!(out.trim(), "gs://test-bkt: Enabled");

    // defstorageclass
    run_cmd(
        &api,
        "defstorageclass",
        &["set", "nearline", "gs://test-bkt"],
    )
    .await
    .unwrap();
    let (out, _) = run_cmd(&api, "defstorageclass", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert_eq!(out.trim(), "gs://test-bkt/: NEARLINE");

    // ubla & bucketpolicyonly
    run_cmd(&api, "ubla", &["set", "on", "gs://test-bkt"])
        .await
        .unwrap();
    let (out, _) = run_cmd(&api, "ubla", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert!(out.contains("Uniform bucket-level access setting for gs://test-bkt:"));
    assert!(out.contains("Enabled: True"));
    let (out, _) = run_cmd(&api, "bucketpolicyonly", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert!(out.contains("Bucket Policy Only setting for gs://test-bkt:"));

    // pap
    run_cmd(&api, "pap", &["set", "enforced", "gs://test-bkt"])
        .await
        .unwrap();
    let (out, _) = run_cmd(&api, "pap", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert_eq!(out.trim(), "gs://test-bkt: enforced");

    // rpo
    run_cmd(&api, "rpo", &["set", "ASYNC_TURBO", "gs://test-bkt"])
        .await
        .unwrap();
    let (out, _) = run_cmd(&api, "rpo", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert_eq!(out.trim(), "gs://test-bkt: ASYNC_TURBO");

    // autoclass
    run_cmd(&api, "autoclass", &["set", "on", "gs://test-bkt"])
        .await
        .unwrap();
    let (out, _) = run_cmd(&api, "autoclass", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert!(out.contains("Enabled: True"));

    // logging
    run_cmd(
        &api,
        "logging",
        &[
            "set",
            "on",
            "-b",
            "gs://log-bkt",
            "-o",
            "pfx",
            "gs://test-bkt",
        ],
    )
    .await
    .unwrap();
    let (out, _) = run_cmd(&api, "logging", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert!(out.contains("log-bkt"));

    // web
    run_cmd(
        &api,
        "web",
        &["set", "-m", "index.html", "-e", "404.html", "gs://test-bkt"],
    )
    .await
    .unwrap();
    let (out, _) = run_cmd(&api, "web", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert!(out.contains("index.html"));

    // label ch
    run_cmd(
        &api,
        "label",
        &["ch", "-l", "env:prod", "-l", "team:core", "gs://test-bkt"],
    )
    .await
    .unwrap();
    run_cmd(&api, "label", &["ch", "-d", "team", "gs://test-bkt"])
        .await
        .unwrap();
    let (out, _) = run_cmd(&api, "label", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert!(out.contains("\"env\": \"prod\""));
    assert!(!out.contains("team"));

    // cors & lifecycle from temp JSON files
    let dir = tempfile::tempdir().unwrap();
    let cors_path = dir.path().join("cors.json");
    std::fs::write(&cors_path, r#"[{"origin": ["*"], "method": ["GET"]}]"#).unwrap();
    run_cmd(
        &api,
        "cors",
        &["set", cors_path.to_str().unwrap(), "gs://test-bkt"],
    )
    .await
    .unwrap();
    let (out, _) = run_cmd(&api, "cors", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert!(out.contains("GET"));

    let lc_path = dir.path().join("lifecycle.json");
    std::fs::write(
        &lc_path,
        r#"{"lifecycle": {"rule": [{"action": {"type": "Delete"}, "condition": {"age": 30}}]}}"#,
    )
    .unwrap();
    run_cmd(
        &api,
        "lifecycle",
        &["set", lc_path.to_str().unwrap(), "gs://test-bkt"],
    )
    .await
    .unwrap();
    let (out, _) = run_cmd(&api, "lifecycle", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert!(out.contains("Delete"));

    // retention (set, get, lock, event-default, event, temp, clear)
    run_cmd(&api, "retention", &["set", "30d", "gs://test-bkt"])
        .await
        .unwrap();
    let (out, _) = run_cmd(&api, "retention", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert!(out.contains("2592000 Second(s)"));
    assert!(out.contains("UNLOCKED"));
    run_cmd(&api, "retention", &["lock", "gs://test-bkt"])
        .await
        .unwrap();
    let (out, _) = run_cmd(&api, "retention", &["get", "gs://test-bkt"])
        .await
        .unwrap();
    assert!(out.contains("LOCKED"));
    run_cmd(
        &api,
        "retention",
        &["event-default", "set", "gs://test-bkt"],
    )
    .await
    .unwrap();
    run_cmd(
        &api,
        "retention",
        &["event", "set", "gs://test-bkt/file.txt"],
    )
    .await
    .unwrap();
    run_cmd(
        &api,
        "retention",
        &["temp", "set", "gs://test-bkt/file.txt"],
    )
    .await
    .unwrap();
    run_cmd(&api, "retention", &["clear", "gs://test-bkt"])
        .await
        .unwrap();
}

#[tokio::test]
async fn test_acl_defacl_and_iam() {
    let api = MockCloudApi::with_bucket("sec-bkt");

    // acl ch & get
    run_cmd(&api, "acl", &["ch", "-u", "AllUsers:R", "gs://sec-bkt"])
        .await
        .unwrap();
    let (out, _) = run_cmd(&api, "acl", &["get", "gs://sec-bkt"])
        .await
        .unwrap();
    assert!(out.contains("allUsers"));
    assert!(out.contains("READER"));

    // acl set canned
    run_cmd(
        &api,
        "acl",
        &["set", "public-read", "gs://sec-bkt/file.txt"],
    )
    .await
    .unwrap();
    let (out, _) = run_cmd(&api, "acl", &["get", "gs://sec-bkt/file.txt"])
        .await
        .unwrap();
    assert!(out.contains("canned:publicRead"));

    // defacl ch & get
    run_cmd(
        &api,
        "defacl",
        &["ch", "-u", "alice@example.com:O", "gs://sec-bkt"],
    )
    .await
    .unwrap();
    let (out, _) = run_cmd(&api, "defacl", &["get", "gs://sec-bkt"])
        .await
        .unwrap();
    assert!(out.contains("user-alice@example.com"));

    // iam ch & get
    run_cmd(
        &api,
        "iam",
        &["ch", "allUsers:objectViewer", "gs://sec-bkt"],
    )
    .await
    .unwrap();
    let (out, _) = run_cmd(&api, "iam", &["get", "gs://sec-bkt"])
        .await
        .unwrap();
    assert!(out.contains("roles/storage.objectViewer"));
    assert!(out.contains("allUsers"));

    // iam ch on conditional policy must fail with IamChOnResourceWithConditions
    api.state.lock().unwrap().bucket_iam.insert(
        "sec-bkt".to_string(),
        IamPolicy {
            version: Some(3),
            bindings: vec![IamBinding {
                role: "roles/storage.objectViewer".to_string(),
                members: vec!["allUsers".to_string()],
                condition: Some(IamCondition {
                    title: Some("temp".to_string()),
                    expression: Some("true".to_string()),
                    ..Default::default()
                }),
            }],
            ..Default::default()
        },
    );
    let err = run_cmd(
        &api,
        "iam",
        &["ch", "user:bob@example.com:objectAdmin", "gs://sec-bkt"],
    )
    .await
    .unwrap_err();
    assert!(matches!(err, GsutilError::IamChOnResourceWithConditions(_)));
}

#[tokio::test]
async fn test_kms_hmac_notification() {
    let api = MockCloudApi::with_bucket("ops-bkt");

    // kms
    let (out, _) = run_cmd(&api, "kms", &["serviceaccount"]).await.unwrap();
    assert!(out.contains("gs-project-accounts.iam.gserviceaccount.com"));
    run_cmd(
        &api,
        "kms",
        &[
            "encryption",
            "-k",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k",
            "gs://ops-bkt",
        ],
    )
    .await
    .unwrap();
    let (out, _) = run_cmd(&api, "kms", &["encryption", "gs://ops-bkt"])
        .await
        .unwrap();
    assert!(out.contains("cryptoKeys/k"));
    let (out, _) = run_cmd(
        &api,
        "kms",
        &[
            "authorize",
            "-k",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k",
        ],
    )
    .await
    .unwrap();
    assert!(out.contains("Authorized project my-proj"));

    // hmac
    let (out, _) = run_cmd(
        &api,
        "hmac",
        &["create", "sa@my-proj.iam.gserviceaccount.com"],
    )
    .await
    .unwrap();
    assert!(out.contains("Access ID:   GOOG1EKEY1"));
    assert!(out.contains("Secret:      SUPER_SECRET_KEY_MATERIAL"));
    let (out, _) = run_cmd(&api, "hmac", &["get", "GOOG1EKEY1"]).await.unwrap();
    assert!(out.contains("Access ID GOOG1EKEY1:"));
    assert!(out.contains("State:"));
    run_cmd(&api, "hmac", &["update", "-s", "INACTIVE", "GOOG1EKEY1"])
        .await
        .unwrap();
    let (out, _) = run_cmd(&api, "hmac", &["list"]).await.unwrap();
    assert!(out.contains("GOOG1EKEY1"));
    assert!(out.contains("INACTIVE"));
    run_cmd(&api, "hmac", &["delete", "GOOG1EKEY1"])
        .await
        .unwrap();

    // notification
    let (out, _) = run_cmd(
        &api,
        "notification",
        &[
            "create",
            "-f",
            "json",
            "-t",
            "my-topic",
            "-e",
            "OBJECT_FINALIZE",
            "gs://ops-bkt",
        ],
    )
    .await
    .unwrap();
    assert!(out.contains("Created notification config"));
    let (out, _) = run_cmd(&api, "notification", &["list", "gs://ops-bkt"])
        .await
        .unwrap();
    assert!(out.contains("my-topic"));
    assert!(out.contains("OBJECT_FINALIZE"));
    run_cmd(&api, "notification", &["delete", "gs://ops-bkt"])
        .await
        .unwrap();
    let (out, _) = run_cmd(&api, "notification", &["list", "gs://ops-bkt"])
        .await
        .unwrap();
    assert!(out.is_empty());

    // watchbucket & stopchannel
    let (out, _) = run_cmd(
        &api,
        "notification",
        &[
            "watchbucket",
            "-i",
            "chan-1",
            "https://example.com/hook",
            "gs://ops-bkt",
        ],
    )
    .await
    .unwrap();
    assert!(out.contains("chan-1"));
    run_cmd(
        &api,
        "notification",
        &["stopchannel", "chan-1", "res-12345"],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_signurl_v4_and_v2_with_real_rsa_key() {
    let api = MockCloudApi::with_bucket("sign-bkt");

    // Generate a real 2048-bit RSA key for testing V2 & V4 signing.
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pem = priv_key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();

    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("sa.json");
    let sa_json = serde_json::json!({
        "client_email": "signer@test-proj.iam.gserviceaccount.com",
        "private_key": pem,
    });
    std::fs::write(&key_path, serde_json::to_string(&sa_json).unwrap()).unwrap();

    // V4 signed URL
    let (out, _) = run_cmd(
        &api,
        "signurl",
        &[
            "-d",
            "10m",
            key_path.to_str().unwrap(),
            "gs://sign-bkt/file.txt",
        ],
    )
    .await
    .unwrap();
    assert!(out.contains("URL\tHTTP Method\tExpiration\tSigned URL"));
    assert!(out.contains("x-goog-algorithm=GOOG4-RSA-SHA256"));
    assert!(out.contains("x-goog-signature="));
    assert!(out.contains("x-goog-expires=600"));

    // V2 signed URL
    let (out, _) = run_cmd(
        &api,
        "signurl",
        &[
            "-v",
            "2",
            "-d",
            "1h",
            key_path.to_str().unwrap(),
            "gs://sign-bkt/file.txt",
        ],
    )
    .await
    .unwrap();
    assert!(out.contains("GoogleAccessId=signer%40test-proj.iam.gserviceaccount.com"));
    assert!(out.contains("Signature="));

    // -u IAM sign fallback
    let (out, _) = run_cmd(&api, "signurl", &["-u", "gs://sign-bkt/file.txt"])
        .await
        .unwrap();
    assert!(out.contains("x-goog-signature=iam-signed"));

    // Sanity check V4 payload helper determinism
    let mut hdrs = BTreeMap::new();
    hdrs.insert("host".to_string(), "storage.googleapis.com".to_string());
    let (sts, qs) = crate::signurl::build_v4_payload(
        "signer@test-proj.iam.gserviceaccount.com",
        "GET",
        600,
        "sign-bkt/file.txt",
        None,
        "auto",
        &hdrs,
        None,
        Utc::now(),
    );
    assert!(sts.starts_with("GOOG4-RSA-SHA256\n"));
    assert!(qs.contains("x-goog-signedheaders=host"));
}
