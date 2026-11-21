//! In-memory mock `CloudApi` implementation for `gsutil-transfer` unit tests.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use flate2::read::GzDecoder;
use gsutil_core::api::*;
use gsutil_core::error::{GsutilError, Result, ServiceError};
use gsutil_core::hash::{crc32c_base64, md5_base64};

#[derive(Debug, Clone)]
pub(crate) struct StoredObject {
    pub data: Bytes,
    pub metadata: Object,
}

#[derive(Debug, Default)]
struct Store {
    buckets: BTreeMap<String, Bucket>,
    /// Key: `(bucket, object_name)` -> live `StoredObject`
    objects: BTreeMap<(String, String), StoredObject>,
    /// Corrupt returned CRC32C on next upload or download for testing hash mismatch.
    corrupt_upload_crc: bool,
    corrupt_download_bytes: bool,
    /// Fail `copy_object` with an error to test fallback/failure handling.
    fail_copy: bool,
}

/// Thread-safe in-memory `CloudApi` mock with counters and fault injection.
#[derive(Debug, Default)]
pub(crate) struct MockCloudApi {
    store: Mutex<Store>,
    next_gen: AtomicU64,
    pub upload_calls: AtomicUsize,
    pub resumable_upload_calls: AtomicUsize,
    pub download_calls: AtomicUsize,
    pub range_download_calls: AtomicUsize,
    pub copy_calls: AtomicUsize,
    pub compose_calls: AtomicUsize,
    pub delete_calls: AtomicUsize,
}

impl MockCloudApi {
    pub fn new() -> Self {
        Self {
            next_gen: AtomicU64::new(1000),
            ..Default::default()
        }
    }

    pub fn create_bucket_sync(&self, name: &str) {
        let mut s = self.store.lock().unwrap();
        s.buckets.insert(
            name.to_string(),
            Bucket {
                name: Some(name.to_string()),
                storage_class: Some("STANDARD".to_string()),
                location: Some("US".to_string()),
                ..Default::default()
            },
        );
    }

    pub fn put_object(&self, bucket: &str, name: &str, data: &[u8]) -> Object {
        self.put_object_with_content_type(bucket, name, data, Some("application/octet-stream"))
    }

    pub fn put_object_with_content_type(
        &self,
        bucket: &str,
        name: &str,
        data: &[u8],
        content_type: Option<&str>,
    ) -> Object {
        let mut s = self.store.lock().unwrap();
        let gen = self.next_gen.fetch_add(1, Ordering::SeqCst).to_string();
        let meta = Object {
            bucket: Some(bucket.to_string()),
            name: Some(name.to_string()),
            generation: Some(gen.clone()),
            metageneration: Some("1".to_string()),
            size: Some(data.len().to_string()),
            crc32c: Some(crc32c_base64(data)),
            md5_hash: Some(md5_base64(data)),
            etag: Some(format!("etag-{gen}")),
            storage_class: Some("STANDARD".to_string()),
            content_type: content_type.map(ToString::to_string),
            time_created: Some("2026-01-01T00:00:00Z".to_string()),
            updated: Some("2026-01-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        s.objects.insert(
            (bucket.to_string(), name.to_string()),
            StoredObject {
                data: Bytes::copy_from_slice(data),
                metadata: meta.clone(),
            },
        );
        meta
    }

    pub fn set_corrupt_upload_crc(&self, v: bool) {
        self.store.lock().unwrap().corrupt_upload_crc = v;
    }

    pub fn set_corrupt_download_bytes(&self, v: bool) {
        self.store.lock().unwrap().corrupt_download_bytes = v;
    }

    pub fn get_stored(&self, bucket: &str, name: &str) -> Option<StoredObject> {
        self.store
            .lock()
            .unwrap()
            .objects
            .get(&(bucket.to_string(), name.to_string()))
            .cloned()
    }

    pub fn list_all_object_names(&self, bucket: &str) -> Vec<String> {
        self.store
            .lock()
            .unwrap()
            .objects
            .keys()
            .filter(|(b, _)| b == bucket)
            .map(|(_, n)| n.clone())
            .collect()
    }

    fn do_upload(
        &self,
        data: Bytes,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        let mut s = self.store.lock().unwrap();
        let bucket = object_metadata
            .bucket
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Missing bucket"))?;
        let name = object_metadata
            .name
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Missing object name"))?;
        if !s.buckets.contains_key(bucket) {
            return Err(ServiceError::bucket_not_found(
                format!("The specified bucket {bucket} does not exist."),
                bucket,
                Some(404),
                None,
            )
            .into());
        }

        let key = (bucket.to_string(), name.to_string());
        if let Some(pre) = &options.preconditions {
            if let Some(gm) = pre.gen_match {
                let current_gen = s
                    .objects
                    .get(&key)
                    .and_then(|o| o.metadata.generation.as_deref())
                    .and_then(|g| g.parse::<i64>().ok())
                    .unwrap_or(0);
                if current_gen != gm {
                    return Err(
                        ServiceError::precondition("Precondition Failed", Some(412), None).into(),
                    );
                }
            }
        }

        // Emulate real GCS HTTP transport gzip decompression when `options.gzip_encoded == true`
        // (i.e. `Content-Encoding: gzip` on the HTTP upload part, used by `-j`/`-J`).
        let stored_data = if options.gzip_encoded {
            let mut dec = GzDecoder::new(data.as_ref());
            let mut out = Vec::new();
            dec.read_to_end(&mut out).map_err(|e| {
                ServiceError::bad_request(
                    format!("Invalid gzip transport stream: {e}"),
                    Some(400),
                    None,
                )
            })?;
            Bytes::from(out)
        } else {
            data
        };

        let gen = self.next_gen.fetch_add(1, Ordering::SeqCst).to_string();
        let mut meta = object_metadata.clone();
        meta.generation = Some(gen.clone());
        meta.metageneration = Some("1".to_string());
        meta.size = Some(stored_data.len().to_string());
        meta.etag = Some(format!("etag-{gen}"));
        if meta.storage_class.is_none() {
            meta.storage_class = Some("STANDARD".to_string());
        }
        if meta.time_created.is_none() {
            meta.time_created = Some("2026-01-01T00:00:00Z".to_string());
        }
        meta.updated = Some("2026-01-01T00:00:00Z".to_string());

        let real_crc = crc32c_base64(&stored_data);
        // Emulate GCS 400 BadRequest when caller-supplied CRC32C mismatches stored bytes!
        if !s.corrupt_upload_crc {
            if let Some(ref provided) = object_metadata.crc32c {
                if provided != &real_crc {
                    return Err(ServiceError::bad_request(
                        format!(
                            "Provided CRC32C \"{provided}\" doesn't match calculated CRC32C \"{real_crc}\"."
                        ),
                        Some(400),
                        None,
                    )
                    .into());
                }
            }
        }
        meta.crc32c = Some(if s.corrupt_upload_crc {
            "AAAAAA==".to_string()
        } else {
            real_crc
        });
        meta.md5_hash = Some(md5_base64(&stored_data));

        if let Some(enc) = &options.encryption_key {
            match enc {
                EncryptionKey::Csek { key_sha256_b64, .. } => {
                    meta.customer_encryption = Some(ObjectCustomerEncryption {
                        encryption_algorithm: Some("AES256".to_string()),
                        key_sha256: Some(key_sha256_b64.clone()),
                    });
                }
                EncryptionKey::Cmek { kms_key_name } => {
                    meta.kms_key_name = Some(kms_key_name.clone());
                }
            }
        }

        s.objects.insert(
            key,
            StoredObject {
                data: stored_data,
                metadata: meta.clone(),
            },
        );
        Ok(meta)
    }
}

#[async_trait]
impl CloudApi for MockCloudApi {
    async fn get_service_account_id(&self) -> Result<String> {
        Ok("mock-sa@example.iam.gserviceaccount.com".into())
    }

    async fn get_bucket(&self, bucket_name: &str, _fields: Option<&[String]>) -> Result<Bucket> {
        let s = self.store.lock().unwrap();
        s.buckets.get(bucket_name).cloned().ok_or_else(|| {
            ServiceError::bucket_not_found("Bucket not found", bucket_name, Some(404), None).into()
        })
    }

    async fn list_buckets(
        &self,
        _project_id: Option<&str>,
        _fields: Option<&[String]>,
    ) -> Result<Vec<Bucket>> {
        let s = self.store.lock().unwrap();
        Ok(s.buckets.values().cloned().collect())
    }

    async fn create_bucket(
        &self,
        bucket_name: &str,
        _project_id: Option<&str>,
        metadata: Option<&Bucket>,
        _fields: Option<&[String]>,
    ) -> Result<Bucket> {
        let mut s = self.store.lock().unwrap();
        let mut b = metadata.cloned().unwrap_or_default();
        b.name = Some(bucket_name.to_string());
        s.buckets.insert(bucket_name.to_string(), b.clone());
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
        let mut s = self.store.lock().unwrap();
        let entry = s.buckets.get_mut(bucket_name).ok_or_else(|| {
            ServiceError::bucket_not_found("Bucket not found", bucket_name, Some(404), None)
        })?;
        *entry = metadata.clone();
        entry.name = Some(bucket_name.to_string());
        Ok(entry.clone())
    }

    async fn delete_bucket(
        &self,
        bucket_name: &str,
        _preconditions: Option<&Preconditions>,
    ) -> Result<()> {
        let mut s = self.store.lock().unwrap();
        s.buckets.remove(bucket_name);
        Ok(())
    }

    async fn lock_retention_policy(
        &self,
        bucket_name: &str,
        _metageneration: i64,
    ) -> Result<Bucket> {
        self.get_bucket(bucket_name, None).await
    }

    async fn get_bucket_iam_policy(
        &self,
        _bucket_name: &str,
        _fields: Option<&[String]>,
    ) -> Result<IamPolicy> {
        Ok(IamPolicy::default())
    }

    async fn set_bucket_iam_policy(
        &self,
        _bucket_name: &str,
        policy: &IamPolicy,
    ) -> Result<IamPolicy> {
        Ok(policy.clone())
    }

    async fn list_objects(
        &self,
        bucket_name: &str,
        options: &ListObjectsOptions,
    ) -> Result<Vec<CsObjectOrPrefix>> {
        let s = self.store.lock().unwrap();
        if !s.buckets.contains_key(bucket_name) {
            return Err(ServiceError::bucket_not_found(
                "Bucket not found",
                bucket_name,
                Some(404),
                None,
            )
            .into());
        }
        let prefix = options.prefix.as_deref().unwrap_or("");
        let mut out = Vec::new();
        let mut seen_prefixes = BTreeSet::new();

        for ((b, name), stored) in &s.objects {
            if b != bucket_name || !name.starts_with(prefix) {
                continue;
            }
            if let Some(delim) = options.delimiter.as_deref() {
                let rest = &name[prefix.len()..];
                if let Some(pos) = rest.find(delim) {
                    let sub_prefix = format!("{prefix}{}", &rest[..pos + delim.len()]);
                    if seen_prefixes.insert(sub_prefix.clone()) {
                        out.push(CsObjectOrPrefix::Prefix(sub_prefix));
                    }
                    continue;
                }
            }
            out.push(CsObjectOrPrefix::Object(Box::new(stored.metadata.clone())));
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
        let s = self.store.lock().unwrap();
        s.objects
            .get(&(bucket_name.to_string(), object_name.to_string()))
            .map(|o| o.metadata.clone())
            .ok_or_else(|| {
                ServiceError::not_found(
                    format!("gs://{bucket_name}/{object_name} does not exist."),
                    Some(404),
                    None,
                )
                .into()
            })
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
        let mut s = self.store.lock().unwrap();
        let entry = s
            .objects
            .get_mut(&(bucket_name.to_string(), object_name.to_string()))
            .ok_or_else(|| ServiceError::not_found("Not found", Some(404), None))?;
        if let Some(ref custom) = metadata.metadata {
            let map = entry.metadata.metadata.get_or_insert_with(BTreeMap::new);
            for (k, v) in custom {
                map.insert(k.clone(), v.clone());
            }
        }
        if !metadata.metadata_removals.is_empty() {
            if let Some(ref mut map) = entry.metadata.metadata {
                for k in &metadata.metadata_removals {
                    map.remove(k);
                }
            }
        }
        for field in &metadata.clear_fields {
            match field.as_str() {
                "cacheControl" => entry.metadata.cache_control = None,
                "contentDisposition" => entry.metadata.content_disposition = None,
                "contentEncoding" => entry.metadata.content_encoding = None,
                "contentLanguage" => entry.metadata.content_language = None,
                "contentType" => entry.metadata.content_type = None,
                "customTime" => entry.metadata.custom_time = None,
                _ => {}
            }
        }
        if let Some(ref ct) = metadata.content_type {
            entry.metadata.content_type = Some(ct.clone());
        }
        if let Some(ref sc) = metadata.storage_class {
            entry.metadata.storage_class = Some(sc.clone());
        }
        Ok(entry.metadata.clone())
    }

    async fn get_object_iam_policy(
        &self,
        _bucket_name: &str,
        _object_name: &str,
        _generation: Option<&str>,
        _fields: Option<&[String]>,
    ) -> Result<IamPolicy> {
        Ok(IamPolicy::default())
    }

    async fn set_object_iam_policy(
        &self,
        _bucket_name: &str,
        _object_name: &str,
        policy: &IamPolicy,
        _generation: Option<&str>,
    ) -> Result<IamPolicy> {
        Ok(policy.clone())
    }

    async fn get_object_media(
        &self,
        bucket_name: &str,
        object_name: &str,
        options: &DownloadOptions,
    ) -> Result<Bytes> {
        self.download_calls.fetch_add(1, Ordering::SeqCst);
        if options.start_byte.is_some() || options.end_byte.is_some() {
            self.range_download_calls.fetch_add(1, Ordering::SeqCst);
        }
        let s = self.store.lock().unwrap();
        let stored = s
            .objects
            .get(&(bucket_name.to_string(), object_name.to_string()))
            .ok_or_else(|| ServiceError::not_found("Not found", Some(404), None))?;

        let is_gzip = stored
            .metadata
            .content_encoding
            .as_deref()
            .is_some_and(|e| e.eq_ignore_ascii_case("gzip"));

        // Emulate real GCS transparent gzip decompression when client omits
        // `Accept-Encoding: gzip` (`compressed_encoding == false`).
        let effective_data: Vec<u8> = if is_gzip && !options.compressed_encoding {
            let mut dec = GzDecoder::new(stored.data.as_ref());
            let mut out = Vec::new();
            dec.read_to_end(&mut out).unwrap_or_else(|_| {
                out = stored.data.to_vec();
                out.len()
            });
            out
        } else {
            stored.data.to_vec()
        };

        let start = options.start_byte.unwrap_or(0).max(0) as usize;
        let end_inclusive = options
            .end_byte
            .map(|e| e as usize)
            .unwrap_or_else(|| effective_data.len().saturating_sub(1));

        let mut slice = if effective_data.is_empty() || start >= effective_data.len() {
            Vec::new()
        } else {
            let end = (end_inclusive + 1).min(effective_data.len());
            effective_data[start..end].to_vec()
        };

        if s.corrupt_download_bytes && !slice.is_empty() {
            slice[0] ^= 0xFF;
        }
        Ok(Bytes::from(slice))
    }

    async fn upload_object(
        &self,
        data: Bytes,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        self.upload_calls.fetch_add(1, Ordering::SeqCst);
        self.do_upload(data, object_metadata, options)
    }

    async fn upload_object_resumable(
        &self,
        data: Bytes,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        self.resumable_upload_calls.fetch_add(1, Ordering::SeqCst);
        self.do_upload(data, object_metadata, options)
    }

    async fn copy_object(
        &self,
        src_obj_metadata: &Object,
        dst_obj_metadata: &Object,
        options: &CopyOptions,
    ) -> Result<Object> {
        self.copy_calls.fetch_add(1, Ordering::SeqCst);
        let mut s = self.store.lock().unwrap();
        if s.fail_copy {
            return Err(ServiceError::service("Copy failed", Some(500), None).into());
        }
        let sb = src_obj_metadata.bucket.as_deref().unwrap_or("");
        let sn = src_obj_metadata.name.as_deref().unwrap_or("");
        let db = dst_obj_metadata.bucket.as_deref().unwrap_or(sb);
        let dn = dst_obj_metadata.name.as_deref().unwrap_or(sn);

        let src = s
            .objects
            .get(&(sb.to_string(), sn.to_string()))
            .cloned()
            .ok_or_else(|| ServiceError::not_found("Source not found", Some(404), None))?;

        let key = (db.to_string(), dn.to_string());
        if let Some(pre) = &options.preconditions {
            if let Some(gm) = pre.gen_match {
                let current_gen = s
                    .objects
                    .get(&key)
                    .and_then(|o| o.metadata.generation.as_deref())
                    .and_then(|g| g.parse::<i64>().ok())
                    .unwrap_or(0);
                if current_gen != gm {
                    return Err(
                        ServiceError::precondition("Precondition Failed", Some(412), None).into(),
                    );
                }
            }
        }

        let gen = self.next_gen.fetch_add(1, Ordering::SeqCst).to_string();
        let mut new_meta = src.metadata.clone();
        new_meta.bucket = Some(db.to_string());
        new_meta.name = Some(dn.to_string());
        new_meta.generation = Some(gen.clone());
        new_meta.etag = Some(format!("etag-{gen}"));
        if let Some(ref sc) = dst_obj_metadata.storage_class {
            new_meta.storage_class = Some(sc.clone());
        }
        if let Some(ref ct) = dst_obj_metadata.content_type {
            new_meta.content_type = Some(ct.clone());
        }
        if let Some(ref md) = dst_obj_metadata.metadata {
            new_meta.metadata = Some(md.clone());
        }
        if let Some(enc) = &options.encryption_key {
            match enc {
                EncryptionKey::Csek { key_sha256_b64, .. } => {
                    new_meta.customer_encryption = Some(ObjectCustomerEncryption {
                        encryption_algorithm: Some("AES256".to_string()),
                        key_sha256: Some(key_sha256_b64.clone()),
                    });
                    new_meta.kms_key_name = None;
                }
                EncryptionKey::Cmek { kms_key_name } => {
                    new_meta.kms_key_name = Some(kms_key_name.clone());
                    new_meta.customer_encryption = None;
                }
            }
        }

        s.objects.insert(
            key,
            StoredObject {
                data: src.data,
                metadata: new_meta.clone(),
            },
        );
        Ok(new_meta)
    }

    async fn compose_object(
        &self,
        src_objs: &[ComposeSourceObject],
        dst_obj_metadata: &Object,
        preconditions: Option<&Preconditions>,
        encryption_key: Option<&EncryptionKey>,
        _fields: Option<&[String]>,
    ) -> Result<Object> {
        self.compose_calls.fetch_add(1, Ordering::SeqCst);
        let mut s = self.store.lock().unwrap();
        let bucket = dst_obj_metadata
            .bucket
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Missing destination bucket"))?;
        let name = dst_obj_metadata
            .name
            .as_deref()
            .ok_or_else(|| GsutilError::argument("Missing destination name"))?;

        let key = (bucket.to_string(), name.to_string());
        if let Some(pre) = preconditions {
            if let Some(gm) = pre.gen_match {
                let current_gen = s
                    .objects
                    .get(&key)
                    .and_then(|o| o.metadata.generation.as_deref())
                    .and_then(|g| g.parse::<i64>().ok())
                    .unwrap_or(0);
                if current_gen != gm {
                    return Err(
                        ServiceError::precondition("Precondition Failed", Some(412), None).into(),
                    );
                }
            }
        }

        let mut combined = Vec::new();
        for comp in src_objs {
            let stored = s
                .objects
                .get(&(bucket.to_string(), comp.name.clone()))
                .ok_or_else(|| {
                    ServiceError::not_found(
                        format!("Component gs://{bucket}/{} not found", comp.name),
                        Some(404),
                        None,
                    )
                })?;
            combined.extend_from_slice(&stored.data);
        }

        let gen = self.next_gen.fetch_add(1, Ordering::SeqCst).to_string();
        let mut meta = dst_obj_metadata.clone();
        meta.generation = Some(gen.clone());
        meta.metageneration = Some("1".to_string());
        meta.size = Some(combined.len().to_string());
        meta.etag = Some(format!("etag-{gen}"));
        meta.crc32c = Some(crc32c_base64(&combined));
        // Composite objects in GCS do not have an MD5 hash.
        meta.md5_hash = None;
        meta.component_count = Some(src_objs.len() as i64);
        if meta.storage_class.is_none() {
            meta.storage_class = Some("STANDARD".to_string());
        }
        if let Some(enc) = encryption_key {
            match enc {
                EncryptionKey::Csek { key_sha256_b64, .. } => {
                    meta.customer_encryption = Some(ObjectCustomerEncryption {
                        encryption_algorithm: Some("AES256".to_string()),
                        key_sha256: Some(key_sha256_b64.clone()),
                    });
                }
                EncryptionKey::Cmek { kms_key_name } => {
                    meta.kms_key_name = Some(kms_key_name.clone());
                }
            }
        }

        s.objects.insert(
            key,
            StoredObject {
                data: Bytes::from(combined),
                metadata: meta.clone(),
            },
        );
        Ok(meta)
    }

    async fn delete_object(
        &self,
        bucket_name: &str,
        object_name: &str,
        _generation: Option<&str>,
        _preconditions: Option<&Preconditions>,
    ) -> Result<()> {
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        let mut s = self.store.lock().unwrap();
        s.objects
            .remove(&(bucket_name.to_string(), object_name.to_string()))
            .ok_or_else(|| ServiceError::not_found("Not found", Some(404), None))?;
        Ok(())
    }

    async fn watch_bucket(
        &self,
        _bucket_name: &str,
        _address: &str,
        _channel_id: &str,
        _token: Option<&str>,
    ) -> Result<Channel> {
        Ok(Channel::default())
    }

    async fn stop_channel(&self, _channel_id: &str, _resource_id: &str) -> Result<()> {
        Ok(())
    }

    async fn get_project_service_account(&self, _project_id: &str) -> Result<ServiceAccount> {
        Ok(ServiceAccount::default())
    }

    async fn create_notification_config(
        &self,
        _bucket_name: &str,
        _options: &CreateNotificationOptions,
    ) -> Result<Notification> {
        Ok(Notification::default())
    }

    async fn delete_notification_config(
        &self,
        _bucket_name: &str,
        _notification_id: &str,
    ) -> Result<()> {
        Ok(())
    }

    async fn list_notification_configs(&self, _bucket_name: &str) -> Result<Vec<Notification>> {
        Ok(Vec::new())
    }

    async fn create_hmac_key(
        &self,
        _project_id: &str,
        _service_account_email: &str,
    ) -> Result<HmacKeyCreateResponse> {
        Ok(HmacKeyCreateResponse::default())
    }

    async fn delete_hmac_key(&self, _project_id: &str, _access_id: &str) -> Result<()> {
        Ok(())
    }

    async fn get_hmac_key(&self, _project_id: &str, _access_id: &str) -> Result<HmacKeyMetadata> {
        Ok(HmacKeyMetadata::default())
    }

    async fn list_hmac_keys(
        &self,
        _project_id: &str,
        _service_account_email: Option<&str>,
        _show_deleted_keys: bool,
    ) -> Result<Vec<HmacKeyMetadata>> {
        Ok(Vec::new())
    }

    async fn update_hmac_key(
        &self,
        _project_id: &str,
        _access_id: &str,
        _state: &str,
        _etag: Option<&str>,
    ) -> Result<HmacKeyMetadata> {
        Ok(HmacKeyMetadata::default())
    }

    async fn sign_url(&self, _options: &SignUrlOptions) -> Result<String> {
        Ok("https://storage.googleapis.com/signed".into())
    }
}
