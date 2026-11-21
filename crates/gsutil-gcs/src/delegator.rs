//! Cloud API delegator routing requests between GCS JSON, GCS XML, and S3 XML APIs.
//!
//! Mirrors `gslib/cloud_api_delegator.py` in Python gsutil v5.38.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use gsutil_auth::TokenProvider;
use gsutil_core::api::{
    Bucket, Channel, CloudApi, ComposeSourceObject, CopyOptions, CreateNotificationOptions,
    CsObjectOrPrefix, DownloadOptions, EncryptionKey, HmacKeyCreateResponse, HmacKeyMetadata,
    IamPolicy, ListObjectsOptions, Notification, Object, Preconditions, ServiceAccount,
    SignUrlOptions, UploadOptions,
};
use gsutil_core::config::BotoConfig;
use gsutil_core::error::{GsutilError, Result};

use crate::client::GcsJsonClient;
use crate::xml::XmlApiClient;

/// API wire protocol selector matching `gslib/cs_api_map.py::ApiSelector`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiSelector {
    Json,
    Xml,
}

/// Routes `gs://` requests to JSON or XML based on `prefer_api`, HMAC credentials,
/// encryption configuration, and mTLS, and routes `s3://` requests to XML.
#[derive(Clone)]
pub struct CloudApiDelegator {
    default_provider: String,
    prefer_api: String,
    using_gs_hmac: bool,
    configured_encryption: bool,
    use_mtls: bool,
    gs_json: Arc<dyn CloudApi>,
    gs_xml: Arc<dyn CloudApi>,
    s3_xml: Arc<dyn CloudApi>,
}

impl CloudApiDelegator {
    /// Construct a `CloudApiDelegator` from `.boto` configuration and resolved credentials.
    pub fn from_boto_config(
        boto_config: &BotoConfig,
        credentials: Arc<dyn TokenProvider>,
    ) -> Result<Self> {
        let gs_json = Arc::new(GcsJsonClient::from_boto_config(
            boto_config,
            credentials.clone(),
        )?);
        let gs_xml = Arc::new(XmlApiClient::new("gs", boto_config, credentials.clone()));
        let s3_xml = Arc::new(XmlApiClient::new("s3", boto_config, credentials));
        Ok(Self::from_clients(
            boto_config,
            "gs",
            gs_json,
            gs_xml,
            s3_xml,
        ))
    }

    /// Construct a `CloudApiDelegator` with explicit backend clients (useful for tests).
    pub fn from_clients(
        boto_config: &BotoConfig,
        default_provider: impl Into<String>,
        gs_json: Arc<dyn CloudApi>,
        gs_xml: Arc<dyn CloudApi>,
        s3_xml: Arc<dyn CloudApi>,
    ) -> Self {
        let prefer_api = boto_config
            .get_or("GSUtil", "prefer_api", "")
            .trim()
            .to_ascii_uppercase();
        let using_gs_hmac = boto_config.using_gs_hmac();
        let configured_encryption = boto_config.has_option("GSUtil", "encryption_key")
            || boto_config.has_option("GSUtil", "decryption_key1");
        let use_mtls = boto_config.get_bool("Credentials", "use_client_certificate", false);

        Self {
            default_provider: default_provider.into(),
            prefer_api,
            using_gs_hmac,
            configured_encryption,
            use_mtls,
            gs_json,
            gs_xml,
            s3_xml,
        }
    }

    /// Determine which [`ApiSelector`] (`Json` vs `Xml`) should be used for `provider`.
    ///
    /// Matches `CloudApiDelegator::GetApiSelector` in `gslib/cloud_api_delegator.py`.
    pub fn get_api_selector(&self, provider: Option<&str>) -> Result<ApiSelector> {
        let selected_provider = provider.unwrap_or(&self.default_provider);
        match selected_provider {
            "s3" => {
                if self.use_mtls {
                    return Err(GsutilError::argument(
                        "User enabled mTLS by setting \"use_client_certificate\", but mTLS \
                         is not supported for the selected XML API. Try configuring for \
                         the GCS JSON API or setting \"use_client_certificate\" to \"False\" in \
                         the Boto config.",
                    ));
                }
                Ok(ApiSelector::Xml)
            }
            "gs" => {
                let api = if self.using_gs_hmac && self.configured_encryption {
                    return Err(GsutilError::command(
                        "gsutil does not support HMAC credentials with customer-supplied \
                         encryption keys (CSEK) or customer-managed KMS encryption keys \
                         (CMEK). Please generate and include non-HMAC credentials \
                         in your .boto configuration file, or to access public encrypted \
                         objects, remove your HMAC credentials.",
                    ));
                } else if self.using_gs_hmac {
                    ApiSelector::Xml
                } else if self.configured_encryption {
                    ApiSelector::Json
                } else if self.prefer_api == "XML" {
                    ApiSelector::Xml
                } else {
                    ApiSelector::Json
                };

                if api == ApiSelector::Xml && self.use_mtls {
                    return Err(GsutilError::argument(
                        "User enabled mTLS by setting \"use_client_certificate\", but mTLS \
                         is not supported for the selected XML API. Try configuring for \
                         the GCS JSON API or setting \"use_client_certificate\" to \"False\" in \
                         the Boto config.",
                    ));
                }

                Ok(api)
            }
            other => Err(GsutilError::argument(format!(
                "gsutil Cloud API map contains no entry for provider {other}."
            ))),
        }
    }

    /// Return the selected [`CloudApi`] backend for `provider` (`"gs"` or `"s3"`).
    pub fn api_for_provider(&self, provider: Option<&str>) -> Result<Arc<dyn CloudApi>> {
        let selected_provider = provider.unwrap_or(&self.default_provider);
        let selector = self.get_api_selector(Some(selected_provider))?;
        match (selected_provider, selector) {
            ("gs", ApiSelector::Json) => Ok(self.gs_json.clone()),
            ("gs", ApiSelector::Xml) => Ok(self.gs_xml.clone()),
            ("s3", ApiSelector::Xml) => Ok(self.s3_xml.clone()),
            (p, s) => Err(GsutilError::argument(format!(
                "gsutil Cloud API map does not support API {s:?} for provider {p}."
            ))),
        }
    }

    fn default_api(&self) -> Result<Arc<dyn CloudApi>> {
        self.api_for_provider(None)
    }
}

#[async_trait]
impl CloudApi for CloudApiDelegator {
    fn resolve_provider(&self, provider: &str) -> Result<Option<&dyn CloudApi>> {
        let selector = self.get_api_selector(Some(provider))?;
        match (provider, selector) {
            ("gs", ApiSelector::Json) => Ok(Some(self.gs_json.as_ref())),
            ("gs", ApiSelector::Xml) => Ok(Some(self.gs_xml.as_ref())),
            ("s3", ApiSelector::Xml) => Ok(Some(self.s3_xml.as_ref())),
            (p, s) => Err(GsutilError::argument(format!(
                "gsutil Cloud API map does not support API {s:?} for provider {p}."
            ))),
        }
    }

    async fn get_service_account_id(&self) -> Result<String> {
        self.default_api()?.get_service_account_id().await
    }

    async fn get_bucket(&self, bucket_name: &str, fields: Option<&[String]>) -> Result<Bucket> {
        self.default_api()?.get_bucket(bucket_name, fields).await
    }

    async fn list_buckets(
        &self,
        project_id: Option<&str>,
        fields: Option<&[String]>,
    ) -> Result<Vec<Bucket>> {
        self.default_api()?.list_buckets(project_id, fields).await
    }

    async fn create_bucket(
        &self,
        bucket_name: &str,
        project_id: Option<&str>,
        metadata: Option<&Bucket>,
        fields: Option<&[String]>,
    ) -> Result<Bucket> {
        self.default_api()?
            .create_bucket(bucket_name, project_id, metadata, fields)
            .await
    }

    async fn patch_bucket(
        &self,
        bucket_name: &str,
        metadata: &Bucket,
        canned_acl: Option<&str>,
        canned_def_acl: Option<&str>,
        preconditions: Option<&Preconditions>,
        fields: Option<&[String]>,
    ) -> Result<Bucket> {
        self.default_api()?
            .patch_bucket(
                bucket_name,
                metadata,
                canned_acl,
                canned_def_acl,
                preconditions,
                fields,
            )
            .await
    }

    async fn delete_bucket(
        &self,
        bucket_name: &str,
        preconditions: Option<&Preconditions>,
    ) -> Result<()> {
        self.default_api()?
            .delete_bucket(bucket_name, preconditions)
            .await
    }

    async fn lock_retention_policy(
        &self,
        bucket_name: &str,
        metageneration: i64,
    ) -> Result<Bucket> {
        self.default_api()?
            .lock_retention_policy(bucket_name, metageneration)
            .await
    }

    async fn get_bucket_iam_policy(
        &self,
        bucket_name: &str,
        fields: Option<&[String]>,
    ) -> Result<IamPolicy> {
        self.default_api()?
            .get_bucket_iam_policy(bucket_name, fields)
            .await
    }

    async fn set_bucket_iam_policy(
        &self,
        bucket_name: &str,
        policy: &IamPolicy,
    ) -> Result<IamPolicy> {
        self.default_api()?
            .set_bucket_iam_policy(bucket_name, policy)
            .await
    }

    async fn list_objects(
        &self,
        bucket_name: &str,
        options: &ListObjectsOptions,
    ) -> Result<Vec<CsObjectOrPrefix>> {
        self.default_api()?.list_objects(bucket_name, options).await
    }

    async fn get_object_metadata(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
        fields: Option<&[String]>,
    ) -> Result<Object> {
        self.default_api()?
            .get_object_metadata(bucket_name, object_name, generation, fields)
            .await
    }

    async fn patch_object_metadata(
        &self,
        bucket_name: &str,
        object_name: &str,
        metadata: &Object,
        canned_acl: Option<&str>,
        generation: Option<&str>,
        preconditions: Option<&Preconditions>,
        fields: Option<&[String]>,
    ) -> Result<Object> {
        self.default_api()?
            .patch_object_metadata(
                bucket_name,
                object_name,
                metadata,
                canned_acl,
                generation,
                preconditions,
                fields,
            )
            .await
    }

    async fn get_object_iam_policy(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
        fields: Option<&[String]>,
    ) -> Result<IamPolicy> {
        self.default_api()?
            .get_object_iam_policy(bucket_name, object_name, generation, fields)
            .await
    }

    async fn set_object_iam_policy(
        &self,
        bucket_name: &str,
        object_name: &str,
        policy: &IamPolicy,
        generation: Option<&str>,
    ) -> Result<IamPolicy> {
        self.default_api()?
            .set_object_iam_policy(bucket_name, object_name, policy, generation)
            .await
    }

    async fn get_object_media(
        &self,
        bucket_name: &str,
        object_name: &str,
        options: &DownloadOptions,
    ) -> Result<Bytes> {
        self.default_api()?
            .get_object_media(bucket_name, object_name, options)
            .await
    }

    async fn upload_object(
        &self,
        data: Bytes,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        self.default_api()?
            .upload_object(data, object_metadata, options)
            .await
    }

    async fn upload_object_resumable(
        &self,
        data: Bytes,
        object_metadata: &Object,
        options: &UploadOptions,
    ) -> Result<Object> {
        self.default_api()?
            .upload_object_resumable(data, object_metadata, options)
            .await
    }

    async fn copy_object(
        &self,
        src_obj_metadata: &Object,
        dst_obj_metadata: &Object,
        options: &CopyOptions,
    ) -> Result<Object> {
        self.default_api()?
            .copy_object(src_obj_metadata, dst_obj_metadata, options)
            .await
    }

    async fn compose_object(
        &self,
        src_objs: &[ComposeSourceObject],
        dst_obj_metadata: &Object,
        preconditions: Option<&Preconditions>,
        encryption_key: Option<&EncryptionKey>,
        fields: Option<&[String]>,
    ) -> Result<Object> {
        self.default_api()?
            .compose_object(
                src_objs,
                dst_obj_metadata,
                preconditions,
                encryption_key,
                fields,
            )
            .await
    }

    async fn delete_object(
        &self,
        bucket_name: &str,
        object_name: &str,
        generation: Option<&str>,
        preconditions: Option<&Preconditions>,
    ) -> Result<()> {
        self.default_api()?
            .delete_object(bucket_name, object_name, generation, preconditions)
            .await
    }

    async fn watch_bucket(
        &self,
        bucket_name: &str,
        address: &str,
        channel_id: &str,
        token: Option<&str>,
    ) -> Result<Channel> {
        self.default_api()?
            .watch_bucket(bucket_name, address, channel_id, token)
            .await
    }

    async fn stop_channel(&self, channel_id: &str, resource_id: &str) -> Result<()> {
        self.default_api()?
            .stop_channel(channel_id, resource_id)
            .await
    }

    async fn get_project_service_account(&self, project_id: &str) -> Result<ServiceAccount> {
        self.default_api()?
            .get_project_service_account(project_id)
            .await
    }

    async fn create_notification_config(
        &self,
        bucket_name: &str,
        options: &CreateNotificationOptions,
    ) -> Result<Notification> {
        self.default_api()?
            .create_notification_config(bucket_name, options)
            .await
    }

    async fn delete_notification_config(
        &self,
        bucket_name: &str,
        notification_id: &str,
    ) -> Result<()> {
        self.default_api()?
            .delete_notification_config(bucket_name, notification_id)
            .await
    }

    async fn list_notification_configs(&self, bucket_name: &str) -> Result<Vec<Notification>> {
        self.default_api()?
            .list_notification_configs(bucket_name)
            .await
    }

    async fn create_hmac_key(
        &self,
        project_id: &str,
        service_account_email: &str,
    ) -> Result<HmacKeyCreateResponse> {
        self.default_api()?
            .create_hmac_key(project_id, service_account_email)
            .await
    }

    async fn delete_hmac_key(&self, project_id: &str, access_id: &str) -> Result<()> {
        self.default_api()?
            .delete_hmac_key(project_id, access_id)
            .await
    }

    async fn get_hmac_key(&self, project_id: &str, access_id: &str) -> Result<HmacKeyMetadata> {
        self.default_api()?
            .get_hmac_key(project_id, access_id)
            .await
    }

    async fn list_hmac_keys(
        &self,
        project_id: &str,
        service_account_email: Option<&str>,
        show_deleted_keys: bool,
    ) -> Result<Vec<HmacKeyMetadata>> {
        self.default_api()?
            .list_hmac_keys(project_id, service_account_email, show_deleted_keys)
            .await
    }

    async fn update_hmac_key(
        &self,
        project_id: &str,
        access_id: &str,
        state: &str,
        etag: Option<&str>,
    ) -> Result<HmacKeyMetadata> {
        self.default_api()?
            .update_hmac_key(project_id, access_id, state, etag)
            .await
    }

    async fn sign_url(&self, options: &SignUrlOptions) -> Result<String> {
        self.default_api()?.sign_url(options).await
    }
}
