//! Help specifications for additional help topics (`gslib/addlhelp/*.py`) and
//! command help formatting (`<B>...</B>` bolding, `MAX_HELP_NAME_LEN = 17`).

pub const MAX_HELP_NAME_LEN: usize = 17;

pub const TOP_LEVEL_USAGE_STRING: &str =
    "Usage: gsutil [-D] [-DD] [-h header]... [-i service_account] [-m] [-o section:flag=value]... [-q] [-u user_project] [command [opts...] args...]";

#[derive(Debug, Clone, Copy)]
pub struct AddlHelpTopic {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub one_line_summary: &'static str,
    pub help_text: &'static str,
}

/// All 13 additional help topics from `gslib/addlhelp/*.py` (sorted alphabetically by `name`).
pub const ADDL_HELP_TOPICS: &[AddlHelpTopic] = &[
    AddlHelpTopic {
        name: "acls",
        aliases: &[
            "ACL",
            "access control",
            "access control list",
            "authorization",
            "canned",
            "canned acl",
        ],
        one_line_summary: "Working With Access Control Lists",
        help_text: r#"<B>OVERVIEW</B>
  Access Control Lists (ACLs) allow you to control who can read and write your
  data, and who can read and write the ACLs themselves.

  If not specified at the time an object is uploaded (e.g., via the gsutil cp -a
  option), objects will be created with a default object ACL set on the bucket
  (see "gsutil help defacl"). You can replace the ACL on an object or bucket
  using the "gsutil acl set" command, or modify the existing ACL using the
  "gsutil acl ch" command (see "gsutil help acl").

<B>CANNED ACLS</B>
  The simplest way to set an ACL on a bucket or object is using a canned ACL:
    project-private, private, public-read, public-read-write,
    authenticated-read, bucket-owner-read, bucket-owner-full-control.
"#,
    },
    AddlHelpTopic {
        name: "crc32c",
        aliases: &["crc32", "crc", "crcmod"],
        one_line_summary: "CRC32C and Installing crcmod",
        help_text: r#"<B>OVERVIEW</B>
  Google Cloud Storage provides a cyclic redundancy check (CRC) header that
  allows clients to verify the integrity of object contents. For non-composite
  objects Cloud Storage also provides an MD5 header to allow clients to verify
  object integrity, but for composite objects only the CRC is available.

  This Rust implementation of gsutil uses hardware-accelerated CRC32C (SSE4.2 /
  ARMv8 CRC instructions) natively without requiring Python crcmod.
"#,
    },
    AddlHelpTopic {
        name: "creds",
        aliases: &["credentials", "authentication", "auth", "gcloud"],
        one_line_summary: "Credential Types Supporting Various Use Cases",
        help_text: r#"<B>OVERVIEW</B>
  gsutil supports several credential types:
  - Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS, gcloud ADC,
    or GCE/GKE metadata server)
  - OAuth2 user credentials and service account JSON keys configured in .boto
  - HMAC access keys configured in .boto for XML/interoperability APIs
  - Service account impersonation via -i / --impersonate-service-account

  Run "gsutil config" or "gcloud auth login" to configure credentials.
"#,
    },
    AddlHelpTopic {
        name: "dev",
        aliases: &["development", "developer", "code", "mods", "software"],
        one_line_summary: "Contributing Code to gsutil",
        help_text: r#"<B>OVERVIEW</B>
  gsutil is open source software licensed under the Apache License, Version 2.0.
  See the project repository and README for contribution guidelines, building,
  and running tests.
"#,
    },
    AddlHelpTopic {
        name: "encoding",
        aliases: &[
            "encodings",
            "utf8",
            "utf-8",
            "latin1",
            "unicode",
            "interoperability",
        ],
        one_line_summary: "Filename encoding and interoperability problems",
        help_text: r#"<B>OVERVIEW</B>
  Google Cloud Storage requires object names to be valid UTF-8 encoded strings.
  If you have local files with non-UTF-8 filenames, you should convert them to
  UTF-8 before uploading with gsutil.
"#,
    },
    AddlHelpTopic {
        name: "metadata",
        aliases: &[
            "cache-control",
            "caching",
            "content type",
            "mime type",
            "mime",
            "type",
        ],
        one_line_summary: "Working With Object Metadata",
        help_text: r#"<B>OVERVIEW</B>
  Objects can have associated metadata, which controls aspects of how GET
  requests are handled, including Content-Type, Cache-Control,
  Content-Disposition, Content-Encoding, Content-Language, Custom-Time, and
  custom x-goog-meta-* headers.

  You can set metadata when uploading objects using the global -h option (e.g.,
  gsutil -h "Content-Type:text/html" cp ...) or modify metadata on existing
  objects using "gsutil setmeta -h ...".
"#,
    },
    AddlHelpTopic {
        name: "naming",
        aliases: &["domain", "limits", "name", "names"],
        one_line_summary: "Object and Bucket Naming",
        help_text: r#"<B>BUCKET NAME REQUIREMENTS</B>
  Bucket names must contain only lowercase letters, numbers, dashes (-),
  underscores (_), and dots (.). Names containing dots require verification.
  Bucket names must start and end with a number or letter, and must contain
  3 to 63 characters (up to 222 for dot-separated domain names, with each
  component at most 63 characters).

<B>OBJECT NAME REQUIREMENTS</B>
  Object names can contain any sequence of valid Unicode characters, of length
  1-1024 bytes when UTF-8 encoded, and cannot contain Carriage Return or Line
  Feed characters or be "." or "..".
"#,
    },
    AddlHelpTopic {
        name: "options",
        aliases: &["arg", "args", "cli", "opt", "opts"],
        one_line_summary: "Global Command Line Options",
        help_text: r#"<B>OPTIONS</B>
  -D          Shows HTTP requests/headers and additional debug info needed when
              posting support requests, including exception stack traces.

  -DD         Shows HTTP requests/headers, additional debug info, exception
              stack traces, plus HTTP upstream payload.

  -h          Allows you to specify certain HTTP headers, for example:
                gsutil -h "Cache-Control:public,max-age=3600" \
                       -h "Content-Type:text/html" cp ...

  -i          Allows you to use the configured credentials to impersonate a
              service account, for example:
                gsutil -i "service-account@google.com" ls gs://pub

  -m          Causes supported operations (acl ch, acl set, cp, mv, rm, rsync,
              and setmeta) to run in parallel.

  -o          Overrides values in the boto configuration file, where the format
              is the same as: -o <section>:<name>=<value>.

  -q          Causes gsutil to perform operations quietly, i.e., without
              reporting progress indicators of operation. Errors are still
              reported.

  -u          Allows you to specify a user project to be billed for the
              request.

  -v          Prints the gsutil version and exits.
"#,
    },
    AddlHelpTopic {
        name: "prod",
        aliases: &[
            "production",
            "resumable",
            "resumable upload",
            "resumable transfer",
            "resumable download",
            "scripts",
            "scripting",
        ],
        one_line_summary: "Scripting Production Transfers",
        help_text: r#"<B>OVERVIEW</B>
  When scripting production transfers with gsutil:
  - Use gsutil -m for parallel transfers of many files.
  - Use gsutil -q to suppress progress output in scripts.
  - Check gsutil's exit status (0 on success, non-zero on failure).
  - Resumable uploads and downloads are enabled automatically for large objects.
"#,
    },
    AddlHelpTopic {
        name: "security",
        aliases: &["protection", "privacy", "proxies", "proxy"],
        one_line_summary: "Security and Privacy Considerations",
        help_text: r#"<B>OVERVIEW</B>
  gsutil always uses HTTPS to communicate with Google Cloud Storage and
  validates server certificates by default. Proxy settings can be configured in
  the [Boto] section of your .boto configuration file or via standard
  HTTP_PROXY / HTTPS_PROXY environment variables.
"#,
    },
    AddlHelpTopic {
        name: "shim",
        aliases: &["gcloudstorage", "gcloud storage"],
        one_line_summary: "Shim for Running gcloud storage",
        help_text: r#"<B>OVERVIEW</B>
  In Python gsutil, setting [GSUtil] use_gcloud_storage = True translates
  gsutil commands to gcloud storage commands. See
  https://cloud.google.com/storage/docs/gsutil-transition-to-gcloud for
  migration details.
"#,
    },
    AddlHelpTopic {
        name: "support",
        aliases: &[
            "techsupport",
            "tech support",
            "technical support",
            "billing",
            "faq",
            "questions",
        ],
        one_line_summary: "Google Cloud Storage Support",
        help_text: r#"<B>OVERVIEW</B>
  For Google Cloud Storage documentation, troubleshooting, and support options,
  visit https://cloud.google.com/storage/docs/getting-support.
"#,
    },
    AddlHelpTopic {
        name: "versions",
        aliases: &["concurrency", "concurrency control"],
        one_line_summary: "Object Versioning and Concurrency Control",
        help_text: r#"<B>OVERVIEW</B>
  Google Cloud Storage supports Object Versioning to retain noncurrent versions
  of objects when they are overwritten or deleted. You can reference a specific
  object generation using the gs://bucket/object#generation syntax, and use
  x-goog-if-generation-match / x-goog-if-metageneration-match headers for
  optimistic concurrency control.
"#,
    },
];

/// Render `<B>...</B>` tags: ANSI bold if TTY, stripped if non-TTY (matching `HelpCommand._OutputHelp`).
pub fn render_help_markup(text: &str, is_tty: bool) -> String {
    if is_tty {
        text.replace("<B>", "\x1b[1m").replace("</B>", "\x1b[0;0m")
    } else {
        text.replace("<B>", "").replace("</B>", "")
    }
}
