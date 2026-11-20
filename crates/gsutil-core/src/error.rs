//! Error taxonomy and exact gsutil Display formatting.
//!
//! Matches `gslib/exception.py`, `gslib/cloud_api.py`, and `gslib/__main__.py`
//! in Python gsutil v5.38.

use std::fmt;

pub const NO_URLS_MATCHED_PREFIX: &str = "No URLs matched";
pub const NO_URLS_MATCHED_GENERIC: &str =
    "No URLs matched. Do the files you're operating on exist?";

/// Format `NO_URLS_MATCHED_TARGET` matching `NO_URLS_MATCHED_PREFIX + ': %s'`.
pub fn no_urls_matched_target(target: &str) -> String {
    format!("{NO_URLS_MATCHED_PREFIX}: {target}")
}

/// Format a `ServiceException`-style message matching `gslib/cloud_api.py`:
/// `"{ClassName}:" + (" {status}" if status) + " {reason}" + ("\n{body}" if body)`
pub fn format_service_error(
    class_name: &str,
    status: Option<u16>,
    reason: &str,
    body: Option<&str>,
) -> String {
    let mut msg = format!("{class_name}:");
    if let Some(code) = status {
        msg.push_str(&format!(" {code}"));
    }
    msg.push_str(&format!(" {reason}"));
    if let Some(b) = body {
        if !b.is_empty() {
            msg.push('\n');
            msg.push_str(b);
        }
    }
    msg
}

/// Specific kind of `ServiceException` matching the subclass hierarchy in `gslib/cloud_api.py`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceErrorKind {
    Service,
    RetryableService,
    ResumableDownload,
    ResumableUpload,
    ResumableUploadStartOver,
    ResumableUploadAbort,
    Authentication,
    Precondition,
    NotFound,
    BucketNotFound { bucket_name: String },
    NotEmpty,
    BadRequest,
    AccessDenied,
    PublishPermissionDenied,
}

impl ServiceErrorKind {
    /// Exact Python exception class name used in `ServiceException.__str__`.
    pub fn class_name(&self) -> &'static str {
        match self {
            Self::Service => "ServiceException",
            Self::RetryableService => "RetryableServiceException",
            Self::ResumableDownload => "ResumableDownloadException",
            Self::ResumableUpload => "ResumableUploadException",
            Self::ResumableUploadStartOver => "ResumableUploadStartOverException",
            Self::ResumableUploadAbort => "ResumableUploadAbortException",
            Self::Authentication => "AuthenticationException",
            Self::Precondition => "PreconditionException",
            Self::NotFound => "NotFoundException",
            Self::BucketNotFound { .. } => "BucketNotFoundException",
            Self::NotEmpty => "NotEmptyException",
            Self::BadRequest => "BadRequestException",
            Self::AccessDenied => "AccessDeniedException",
            Self::PublishPermissionDenied => "PublishPermissionDeniedException",
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RetryableService
                | Self::ResumableDownload
                | Self::ResumableUpload
                | Self::ResumableUploadStartOver
        )
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound | Self::BucketNotFound { .. })
    }
}

/// Unified `ServiceException` struct carrying HTTP status, reason, and optional body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    pub kind: ServiceErrorKind,
    pub status: Option<u16>,
    pub reason: String,
    pub body: Option<String>,
}

impl ServiceError {
    pub fn new(
        kind: ServiceErrorKind,
        reason: impl Into<String>,
        status: Option<u16>,
        body: Option<String>,
    ) -> Self {
        Self {
            kind,
            status,
            reason: reason.into(),
            body,
        }
    }

    pub fn service(reason: impl Into<String>, status: Option<u16>, body: Option<String>) -> Self {
        Self::new(ServiceErrorKind::Service, reason, status, body)
    }

    pub fn retryable(reason: impl Into<String>, status: Option<u16>, body: Option<String>) -> Self {
        Self::new(ServiceErrorKind::RetryableService, reason, status, body)
    }

    pub fn access_denied(
        reason: impl Into<String>,
        status: Option<u16>,
        body: Option<String>,
    ) -> Self {
        Self::new(ServiceErrorKind::AccessDenied, reason, status, body)
    }

    pub fn not_found(reason: impl Into<String>, status: Option<u16>, body: Option<String>) -> Self {
        Self::new(ServiceErrorKind::NotFound, reason, status, body)
    }

    pub fn bucket_not_found(
        reason: impl Into<String>,
        bucket_name: impl Into<String>,
        status: Option<u16>,
        body: Option<String>,
    ) -> Self {
        Self::new(
            ServiceErrorKind::BucketNotFound {
                bucket_name: bucket_name.into(),
            },
            reason,
            status,
            body,
        )
    }

    pub fn not_empty(reason: impl Into<String>, status: Option<u16>, body: Option<String>) -> Self {
        Self::new(ServiceErrorKind::NotEmpty, reason, status, body)
    }

    pub fn bad_request(
        reason: impl Into<String>,
        status: Option<u16>,
        body: Option<String>,
    ) -> Self {
        Self::new(ServiceErrorKind::BadRequest, reason, status, body)
    }

    pub fn precondition(
        reason: impl Into<String>,
        status: Option<u16>,
        body: Option<String>,
    ) -> Self {
        Self::new(ServiceErrorKind::Precondition, reason, status, body)
    }

    pub fn authentication(
        reason: impl Into<String>,
        status: Option<u16>,
        body: Option<String>,
    ) -> Self {
        Self::new(ServiceErrorKind::Authentication, reason, status, body)
    }

    pub fn publish_permission_denied(
        reason: impl Into<String>,
        status: Option<u16>,
        body: Option<String>,
    ) -> Self {
        Self::new(
            ServiceErrorKind::PublishPermissionDenied,
            reason,
            status,
            body,
        )
    }

    pub fn resumable_download(
        reason: impl Into<String>,
        status: Option<u16>,
        body: Option<String>,
    ) -> Self {
        Self::new(ServiceErrorKind::ResumableDownload, reason, status, body)
    }

    pub fn resumable_upload(
        reason: impl Into<String>,
        status: Option<u16>,
        body: Option<String>,
    ) -> Self {
        Self::new(ServiceErrorKind::ResumableUpload, reason, status, body)
    }

    pub fn resumable_upload_start_over(
        reason: impl Into<String>,
        status: Option<u16>,
        body: Option<String>,
    ) -> Self {
        Self::new(
            ServiceErrorKind::ResumableUploadStartOver,
            reason,
            status,
            body,
        )
    }

    pub fn resumable_upload_abort(
        reason: impl Into<String>,
        status: Option<u16>,
        body: Option<String>,
    ) -> Self {
        Self::new(ServiceErrorKind::ResumableUploadAbort, reason, status, body)
    }

    pub fn is_retryable(&self) -> bool {
        self.kind.is_retryable()
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_service_error(
            self.kind.class_name(),
            self.status,
            &self.reason,
            self.body.as_deref(),
        ))
    }
}

impl std::error::Error for ServiceError {}

/// Top-level error enum covering all gsutil exceptions.
#[derive(Debug)]
pub enum GsutilError {
    /// `CommandException` from `gslib/exception.py`.
    /// When `informational` is `true`, stderr prints `reason` without the
    /// `CommandException: ` prefix (matching `_HandleCommandException` in `gslib/__main__.py`).
    Command { reason: String, informational: bool },

    /// `AbortException` from `gslib/exception.py`.
    Abort(String),

    /// `InvalidUrlError` from `gslib/exception.py`.
    /// Note: `gslib/__main__.py` prints `InvalidUrlError: {msg}.` with trailing period on CLI exit.
    InvalidUrl(String),

    /// `HashMismatchException` from `gslib/exception.py`.
    HashMismatch(String),

    /// `IamChOnResourceWithConditionsException` from `gslib/exception.py`.
    IamChOnResourceWithConditions(String),

    /// `ExternalBinaryError` from `gslib/exception.py`.
    ExternalBinary(String),

    /// `ArgumentException` from `gslib/cloud_api.py`.
    Argument(String),

    /// `ProjectIdException` from `gslib/cloud_api.py`.
    ProjectId(String),

    /// `EncryptionException` from `gslib/cloud_api.py`.
    Encryption(String),

    /// `WildcardException` from `gslib/wildcard_iterator.py`.
    Wildcard(String),

    /// Any `ServiceException` or subclass from `gslib/cloud_api.py`.
    Service(ServiceError),

    /// Broken pipe (EPIPE) — exits with code 0 in gsutil.
    BrokenPipe,

    /// Standard I/O error.
    Io(std::io::Error),
}

impl std::error::Error for GsutilError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Service(se) => Some(se),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ServiceError> for GsutilError {
    fn from(err: ServiceError) -> Self {
        Self::Service(err)
    }
}

impl From<std::io::Error> for GsutilError {
    fn from(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::BrokenPipe {
            Self::BrokenPipe
        } else {
            Self::Io(err)
        }
    }
}

impl fmt::Display for GsutilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command {
                reason,
                informational,
            } => {
                if *informational {
                    f.write_str(reason)
                } else {
                    write!(f, "CommandException: {reason}")
                }
            }
            Self::Abort(r) => write!(f, "AbortException: {r}"),
            Self::InvalidUrl(m) => write!(f, "InvalidUrlError: {m}"),
            Self::HashMismatch(m) => f.write_str(m),
            Self::IamChOnResourceWithConditions(m) => {
                write!(f, "IamChOnResourceWithConditionsException: {m}")
            }
            Self::ExternalBinary(m) => write!(f, "ExternalBinaryError: {m}"),
            Self::Argument(r) => write!(f, "ArgumentException: {r}"),
            Self::ProjectId(r) => write!(f, "ProjectIdException: {r}"),
            Self::Encryption(m) => f.write_str(m),
            Self::Wildcard(r) => f.write_str(r),
            Self::Service(se) => write!(f, "{se}"),
            Self::BrokenPipe => f.write_str("Broken pipe"),
            Self::Io(e) => {
                let raw = e.to_string();
                let clean = match raw.rfind(" (os error ") {
                    Some(idx) if raw.ends_with(')') => &raw[..idx],
                    _ => raw.as_str(),
                };
                write!(f, "OSError: {clean}.")
            }
        }
    }
}

impl GsutilError {
    pub fn command(reason: impl Into<String>) -> Self {
        Self::Command {
            reason: reason.into(),
            informational: false,
        }
    }

    pub fn command_informational(reason: impl Into<String>) -> Self {
        Self::Command {
            reason: reason.into(),
            informational: true,
        }
    }

    pub fn invalid_url(msg: impl Into<String>) -> Self {
        Self::InvalidUrl(msg.into())
    }

    pub fn argument(reason: impl Into<String>) -> Self {
        Self::Argument(reason.into())
    }

    pub fn project_id(reason: impl Into<String>) -> Self {
        Self::ProjectId(reason.into())
    }

    /// Exit code matching `gslib/__main__.py`:
    /// - `BrokenPipe` (EPIPE) -> 0
    /// - All other errors -> 1
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::BrokenPipe => 0,
            Self::Io(e) if e.kind() == std::io::ErrorKind::BrokenPipe => 0,
            _ => 1,
        }
    }

    /// Format the exact CLI stderr message matching `_RunNamedCommandAndHandleExceptions`
    /// in `gslib/__main__.py`.
    /// Returns `None` for silent exits like `BrokenPipe`.
    pub fn cli_message(&self) -> Option<String> {
        match self {
            Self::BrokenPipe => None,
            Self::Io(e) if e.kind() == std::io::ErrorKind::BrokenPipe => None,
            Self::InvalidUrl(m) => Some(format!("InvalidUrlError: {m}.")),
            Self::ProjectId(_) => Some(
                "You are attempting to perform an operation that requires a \
                 project id, with none configured. Please re-run \
                 gsutil config and make sure to follow the instructions for \
                 finding and entering your default project id."
                    .to_string(),
            ),
            other => Some(other.to_string()),
        }
    }

    /// Returns `true` if this is a `ServiceError` of kind `NotFound` or `BucketNotFound`.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Service(se) if se.kind.is_not_found())
    }

    /// Returns `true` if this is a `ServiceError` of kind `AccessDenied`.
    pub fn is_access_denied(&self) -> bool {
        matches!(self, Self::Service(se) if se.kind == ServiceErrorKind::AccessDenied)
    }
}

pub type Result<T> = std::result::Result<T, GsutilError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_exception_formatting() {
        let err = GsutilError::command("Invalid command \"foo\".");
        assert_eq!(
            err.to_string(),
            "CommandException: Invalid command \"foo\"."
        );
        assert_eq!(err.exit_code(), 1);
        assert_eq!(
            err.cli_message().as_deref(),
            Some("CommandException: Invalid command \"foo\".")
        );

        let info = GsutilError::command_informational("No URLs matched: gs://bucket/foo");
        assert_eq!(info.to_string(), "No URLs matched: gs://bucket/foo");
        assert_eq!(info.exit_code(), 1);
    }

    #[test]
    fn test_service_exception_formatting() {
        let e1 = ServiceError::not_found("gs://b/o does not exist.", Some(404), None);
        assert_eq!(
            e1.to_string(),
            "NotFoundException: 404 gs://b/o does not exist."
        );

        let e2 = ServiceError::access_denied(
            "Anonymous caller does not have storage.objects.get access",
            Some(403),
            Some("detailed body".into()),
        );
        assert_eq!(
            e2.to_string(),
            "AccessDeniedException: 403 Anonymous caller does not have storage.objects.get access\ndetailed body"
        );

        let e3 =
            ServiceError::bucket_not_found("bucket does not exist.", "my-bkt", Some(404), None);
        assert_eq!(
            e3.to_string(),
            "BucketNotFoundException: 404 bucket does not exist."
        );
        assert!(GsutilError::from(e3).is_not_found());

        let e4 = ServiceError::precondition("Precondition Failed", Some(412), None);
        assert_eq!(
            e4.to_string(),
            "PreconditionException: 412 Precondition Failed"
        );

        let e5 = ServiceError::not_empty(
            "The bucket you tried to delete is not empty.",
            Some(409),
            None,
        );
        assert_eq!(
            e5.to_string(),
            "NotEmptyException: 409 The bucket you tried to delete is not empty."
        );
    }

    #[test]
    fn test_invalid_url_cli_message_has_period() {
        let err = GsutilError::invalid_url("Unrecognized scheme \"http\"");
        assert_eq!(
            err.to_string(),
            "InvalidUrlError: Unrecognized scheme \"http\""
        );
        assert_eq!(
            err.cli_message().as_deref(),
            Some("InvalidUrlError: Unrecognized scheme \"http\".")
        );
    }

    #[test]
    fn test_epipe_exits_zero() {
        let err = GsutilError::BrokenPipe;
        assert_eq!(err.exit_code(), 0);
        assert_eq!(err.cli_message(), None);

        let io_err = GsutilError::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken pipe",
        ));
        assert_eq!(io_err.exit_code(), 0);
        assert_eq!(io_err.cli_message(), None);
    }

    #[test]
    fn test_os_error_strips_errno_suffix() {
        let err = GsutilError::Io(std::io::Error::from_raw_os_error(2));
        let msg = err.to_string();
        assert!(msg.starts_with("OSError: "));
        assert!(msg.ends_with('.'));
        assert!(!msg.contains("(os error"));
    }

    #[test]
    fn test_no_urls_matched_helpers() {
        assert_eq!(NO_URLS_MATCHED_PREFIX, "No URLs matched");
        assert_eq!(
            NO_URLS_MATCHED_GENERIC,
            "No URLs matched. Do the files you're operating on exist?"
        );
        assert_eq!(
            no_urls_matched_target("gs://foo/bar"),
            "No URLs matched: gs://foo/bar"
        );
    }
}
