//! Stub specifications and runners for commands not yet implemented in Phase 1.
//!
//! Each command has its exact `CommandSpec` (name, aliases, deprecated aliases,
//! one-line summary, subcommand help) so `gsutil help`, alias resolution,
//! fuzzy matching, and argument parsing work cleanly. Other workers can replace
//! individual entries by creating `src/commands/<cmd>.rs` and updating `mod.rs`.

use gsutil_core::error::{GsutilError, Result};

use crate::context::CommandContext;
use crate::dispatch::{CommandSpec, NO_MAX};
use crate::getopt::OptPair;

macro_rules! stub_spec {
    (
        $ident:ident,
        name: $name:expr,
        aliases: $aliases:expr,
        summary: $summary:expr,
        synopsis: $synopsis:expr,
        sub_args: $sub_args:expr,
        min: $min:expr,
        max: $max:expr,
        file_ok: $file_ok:expr,
        prov_ok: $prov_ok:expr,
        subcommands: $subcommands:expr,
        has_sub: $has_sub:expr
    ) => {
        pub const $ident: CommandSpec = CommandSpec {
            name: $name,
            aliases: $aliases,
            help_aliases: $aliases,
            one_line_summary: $summary,
            usage_synopsis: $synopsis,
            help_text: concat!(
                "<B>SYNOPSIS</B>\n",
                $synopsis,
                "\n\n<B>DESCRIPTION</B>\n  ",
                $summary,
                ".\n"
            ),
            subcommands: $subcommands,
            min_args: $min,
            max_args: $max,
            supported_sub_args: $sub_args,
            supported_private_args: &[],
            file_url_ok: $file_ok,
            provider_url_ok: $prov_ok,
            urls_start_arg: 0,
            has_subcommands_and_subopts: $has_sub,
        };
    };
}

stub_spec!(ACL,
    name: "acl",
    aliases: &["getacl", "setacl", "chacl"],
    summary: "Get, set, or change bucket and/or object ACLs",
    synopsis: "\n  gsutil acl set [-f] [-R] [-a] file-or-canned_acl_name url...\n  gsutil acl get url\n  gsutil acl ch [-f] [-R] [-u|-g|-d] ... url...\n",
    sub_args: "afRrg:u:d:p:",
    min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[
        ("set", "<B>SYNOPSIS</B>\n  gsutil acl set [-f] [-R] [-a] file-or-canned_acl_name url...\n"),
        ("get", "<B>SYNOPSIS</B>\n  gsutil acl get url\n"),
        ("ch", "<B>SYNOPSIS</B>\n  gsutil acl ch [-f] [-R] [-u|-g|-d] ... url...\n"),
    ],
    has_sub: true
);

stub_spec!(AUTOCLASS,
    name: "autoclass",
    aliases: &[],
    summary: "Configure Autoclass feature",
    synopsis: "\n  gsutil autoclass set (on|off) gs://<bucket_name>...\n  gsutil autoclass get gs://<bucket_name>...\n",
    sub_args: "", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[("set", "<B>SYNOPSIS</B>\n  gsutil autoclass set (on|off) gs://<bucket_name>...\n"), ("get", "<B>SYNOPSIS</B>\n  gsutil autoclass get gs://<bucket_name>...\n")],
    has_sub: true
);

stub_spec!(BUCKETPOLICYONLY,
    name: "bucketpolicyonly",
    aliases: &[],
    summary: "Configure uniform bucket-level access",
    synopsis: "\n  gsutil bucketpolicyonly set (on|off) gs://<bucket_name>...\n  gsutil bucketpolicyonly get gs://<bucket_name>...\n",
    sub_args: "", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[("set", "<B>SYNOPSIS</B>\n  gsutil bucketpolicyonly set (on|off) gs://<bucket_name>...\n"), ("get", "<B>SYNOPSIS</B>\n  gsutil bucketpolicyonly get gs://<bucket_name>...\n")],
    has_sub: true
);

stub_spec!(COMPOSE,
    name: "compose",
    aliases: &["concat"],
    summary: "Concatenate a sequence of objects into a new composite object.",
    synopsis: "\n  gsutil compose gs://bucket/source_obj1 [gs://bucket/source_obj2 ...] gs://bucket/composite_obj\n",
    sub_args: "", min: 1, max: 33, file_ok: false, prov_ok: false,
    subcommands: &[], has_sub: false
);

stub_spec!(CONFIG,
    name: "config",
    aliases: &["cfg", "conf", "configure"],
    summary: "Obtain credentials and create configuration file",
    synopsis: "\n  gsutil config [-a] [-b] [-e] [-f] [-n] [-o <file>] [-r] [-s <scope>] [-w]\n",
    sub_args: "abefhno:rs:w", min: 0, max: 0, file_ok: false, prov_ok: false,
    subcommands: &[], has_sub: false
);

stub_spec!(CORS,
    name: "cors",
    aliases: &["getcors", "setcors"],
    summary: "Get or set a CORS configuration for one or more buckets",
    synopsis: "\n  gsutil cors set cors-json-file gs://<bucket_name>...\n  gsutil cors get gs://<bucket_name>\n",
    sub_args: "", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[("set", "<B>SYNOPSIS</B>\n  gsutil cors set cors-json-file gs://<bucket_name>...\n"), ("get", "<B>SYNOPSIS</B>\n  gsutil cors get gs://<bucket_name>\n")],
    has_sub: true
);

stub_spec!(CP,
    name: "cp",
    aliases: &["copy"],
    summary: "Copy files and objects",
    synopsis: "\n  gsutil cp [OPTION]... src_url dst_url\n  gsutil cp [OPTION]... src_url... dst_url\n  gsutil cp [OPTION]... -I dst_url\n",
    sub_args: "a:AcDeILj:JmnnpPrRs:St:Uvz:Z", min: 1, max: NO_MAX, file_ok: true, prov_ok: false,
    subcommands: &[], has_sub: false
);

stub_spec!(DEFACL,
    name: "defacl",
    aliases: &["setdefacl", "getdefacl", "chdefacl"],
    summary: "Get, set, or change default ACL on buckets",
    synopsis: "\n  gsutil defacl set file-or-canned_acl_name gs://<bucket_name>...\n  gsutil defacl get gs://<bucket_name>\n  gsutil defacl ch -u|-g|-d ... gs://<bucket_name>...\n",
    sub_args: "fg:u:d:p:", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[
        ("set", "<B>SYNOPSIS</B>\n  gsutil defacl set file-or-canned_acl_name gs://<bucket_name>...\n"),
        ("get", "<B>SYNOPSIS</B>\n  gsutil defacl get gs://<bucket_name>\n"),
        ("ch", "<B>SYNOPSIS</B>\n  gsutil defacl ch -u|-g|-d ... gs://<bucket_name>...\n"),
    ],
    has_sub: true
);

stub_spec!(DEFSTORAGECLASS,
    name: "defstorageclass",
    aliases: &[],
    summary: "Get or set the default storage class on buckets",
    synopsis: "\n  gsutil defstorageclass set <storage-class> gs://<bucket_name>...\n  gsutil defstorageclass get gs://<bucket_name>...\n",
    sub_args: "", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[("set", "<B>SYNOPSIS</B>\n  gsutil defstorageclass set <storage-class> gs://<bucket_name>...\n"), ("get", "<B>SYNOPSIS</B>\n  gsutil defstorageclass get gs://<bucket_name>...\n")],
    has_sub: true
);

stub_spec!(HMAC,
    name: "hmac",
    aliases: &[],
    summary: "CRUD operations on service account HMAC keys.",
    synopsis: "\n  gsutil hmac create [-p <project>] <service_account_email>\n  gsutil hmac delete [-p <project>] <access_id>\n  gsutil hmac get [-p <project>] <access_id>\n  gsutil hmac list [-a] [-l] [-p <project>] [-u <service_account_email>]\n  gsutil hmac update -s (ACTIVE|INACTIVE) [-e <etag>] [-p <project>] <access_id>\n",
    sub_args: "ae:lp:s:u:", min: 1, max: 8, file_ok: false, prov_ok: false,
    subcommands: &[
        ("create", "<B>SYNOPSIS</B>\n  gsutil hmac create [-p <project>] <service_account_email>\n"),
        ("delete", "<B>SYNOPSIS</B>\n  gsutil hmac delete [-p <project>] <access_id>\n"),
        ("get", "<B>SYNOPSIS</B>\n  gsutil hmac get [-p <project>] <access_id>\n"),
        ("list", "<B>SYNOPSIS</B>\n  gsutil hmac list [-a] [-l] [-p <project>] [-u <service_account_email>]\n"),
        ("update", "<B>SYNOPSIS</B>\n  gsutil hmac update -s (ACTIVE|INACTIVE) [-e <etag>] [-p <project>] <access_id>\n"),
    ],
    has_sub: true
);

stub_spec!(IAM,
    name: "iam",
    aliases: &[],
    summary: "Get, set, or change bucket and/or object IAM permissions.",
    synopsis: "\n  gsutil iam set [-f] [-R] [-a] [-e <etag>] file url...\n  gsutil iam get url\n  gsutil iam ch [-f] [-R] [-d] binding... url...\n",
    sub_args: "afRrd:e:", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[
        ("set", "<B>SYNOPSIS</B>\n  gsutil iam set [-f] [-R] [-a] [-e <etag>] file url...\n"),
        ("get", "<B>SYNOPSIS</B>\n  gsutil iam get url\n"),
        ("ch", "<B>SYNOPSIS</B>\n  gsutil iam ch [-f] [-R] [-d] binding... url...\n"),
    ],
    has_sub: true
);

stub_spec!(KMS,
    name: "kms",
    aliases: &[],
    summary: "Configure Cloud KMS encryption",
    synopsis: "\n  gsutil kms authorize [-p <proj_id>] -k <kms_key>\n  gsutil kms encryption [-d] [-k <kms_key>] gs://<bucket_name>...\n  gsutil kms serviceaccount [-p <proj_id>]\n",
    sub_args: "dk:p:w", min: 1, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[
        ("authorize", "<B>SYNOPSIS</B>\n  gsutil kms authorize [-p <proj_id>] -k <kms_key>\n"),
        ("encryption", "<B>SYNOPSIS</B>\n  gsutil kms encryption [-d] [-k <kms_key>] gs://<bucket_name>...\n"),
        ("serviceaccount", "<B>SYNOPSIS</B>\n  gsutil kms serviceaccount [-p <proj_id>]\n"),
    ],
    has_sub: true
);

stub_spec!(LABEL,
    name: "label",
    aliases: &[],
    summary: "Get, set, or change the label configuration of a bucket.",
    synopsis: "\n  gsutil label set label-json-file gs://<bucket_name>...\n  gsutil label get gs://<bucket_name>\n  gsutil label ch [-l <key>:<value>] [-d <key>] gs://<bucket_name>...\n",
    sub_args: "l:d:", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[
        ("set", "<B>SYNOPSIS</B>\n  gsutil label set label-json-file gs://<bucket_name>...\n"),
        ("get", "<B>SYNOPSIS</B>\n  gsutil label get gs://<bucket_name>\n"),
        ("ch", "<B>SYNOPSIS</B>\n  gsutil label ch [-l <key>:<value>] [-d <key>] gs://<bucket_name>...\n"),
    ],
    has_sub: true
);

stub_spec!(LIFECYCLE,
    name: "lifecycle",
    aliases: &["lifecycleconfig"],
    summary: "Get or set lifecycle configuration for a bucket",
    synopsis: "\n  gsutil lifecycle get gs://<bucket_name>\n  gsutil lifecycle set config-json-file gs://<bucket_name>...\n",
    sub_args: "", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[("get", "<B>SYNOPSIS</B>\n  gsutil lifecycle get gs://<bucket_name>\n"), ("set", "<B>SYNOPSIS</B>\n  gsutil lifecycle set config-json-file gs://<bucket_name>...\n")],
    has_sub: true
);

stub_spec!(LOGGING,
    name: "logging",
    aliases: &["disablelogging", "enablelogging", "getlogging"],
    summary: "Configure or retrieve logging on buckets",
    synopsis: "\n  gsutil logging set on -b gs://<log_bucket> [-o <log_object_prefix>] gs://<bucket_name>...\n  gsutil logging set off gs://<bucket_name>...\n  gsutil logging get gs://<bucket_name>\n",
    sub_args: "b:o:", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[("set", "<B>SYNOPSIS</B>\n  gsutil logging set (on|off) ...\n"), ("get", "<B>SYNOPSIS</B>\n  gsutil logging get gs://<bucket_name>\n")],
    has_sub: true
);

stub_spec!(MV,
    name: "mv",
    aliases: &["move", "ren", "rename"],
    summary: "Move/rename objects",
    synopsis: "\n  gsutil mv [-p] src_url dst_url\n  gsutil mv [-p] src_url... dst_url\n  gsutil mv [-p] -I dst_url\n",
    sub_args: "a:AcDeILj:JmnnpPrRs:St:Uvz:Z", min: 1, max: NO_MAX, file_ok: true, prov_ok: false,
    subcommands: &[], has_sub: false
);

stub_spec!(NOTIFICATION,
    name: "notification",
    aliases: &["notify", "notifyconfig", "notifications", "notif"],
    summary: "Configure object change notification",
    synopsis: "\n  gsutil notification create -f (json|none) [-p <prefix>] [-t <topic>] gs://<bucket_name>\n  gsutil notification delete gs://<bucket_name>...\n  gsutil notification list gs://<bucket_name>...\n",
    sub_args: "i:t:m:of:e:p:s", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[
        ("create", "<B>SYNOPSIS</B>\n  gsutil notification create ...\n"),
        ("delete", "<B>SYNOPSIS</B>\n  gsutil notification delete ...\n"),
        ("list", "<B>SYNOPSIS</B>\n  gsutil notification list ...\n"),
    ],
    has_sub: true
);

stub_spec!(PAP,
    name: "pap",
    aliases: &["publicaccessprevention"],
    summary: "Configure public access prevention",
    synopsis: "\n  gsutil pap set (enforced|inherited) gs://<bucket_name>...\n  gsutil pap get gs://<bucket_name>...\n",
    sub_args: "", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[("set", "<B>SYNOPSIS</B>\n  gsutil pap set (enforced|inherited) gs://<bucket_name>...\n"), ("get", "<B>SYNOPSIS</B>\n  gsutil pap get gs://<bucket_name>...\n")],
    has_sub: true
);

stub_spec!(PERFDIAG,
    name: "perfdiag",
    aliases: &["diag", "diagnostic", "perf", "performance"],
    summary: "Run performance diagnostic",
    synopsis: "\n  gsutil perfdiag [-i in.json] [-o out.json] [-n objects] [-c processes] [-k threads] [-s size] [-d directory] [-t tests] gs://<bucket_name>\n",
    sub_args: "n:c:k:p:y:s:d:t:m:i:o:j:", min: 0, max: 1, file_ok: false, prov_ok: false,
    subcommands: &[], has_sub: false
);

stub_spec!(REQUESTERPAYS,
    name: "requesterpays",
    aliases: &[],
    summary: "Enable or disable requester pays for one or more buckets",
    synopsis: "\n  gsutil requesterpays set (on|off) gs://<bucket_name>...\n  gsutil requesterpays get gs://<bucket_name>...\n",
    sub_args: "", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[("set", "<B>SYNOPSIS</B>\n  gsutil requesterpays set (on|off) gs://<bucket_name>...\n"), ("get", "<B>SYNOPSIS</B>\n  gsutil requesterpays get gs://<bucket_name>...\n")],
    has_sub: true
);

stub_spec!(RETENTION,
    name: "retention",
    aliases: &[],
    summary: "Provides utilities to interact with Retention Policy feature.",
    synopsis: "\n  gsutil retention set <time> gs://<bucket_name>...\n  gsutil retention clear gs://<bucket_name>...\n  gsutil retention get gs://<bucket_name>...\n  gsutil retention lock gs://<bucket_name>...\n  gsutil retention event-default (set|release) gs://<bucket_name>...\n  gsutil retention event (set|release) gs://<bucket_name>/<object_name>...\n  gsutil retention temp (set|release) gs://<bucket_name>/<object_name>...\n",
    sub_args: "", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[
        ("set", "<B>SYNOPSIS</B>\n  gsutil retention set <time> gs://<bucket_name>...\n"),
        ("clear", "<B>SYNOPSIS</B>\n  gsutil retention clear gs://<bucket_name>...\n"),
        ("get", "<B>SYNOPSIS</B>\n  gsutil retention get gs://<bucket_name>...\n"),
        ("lock", "<B>SYNOPSIS</B>\n  gsutil retention lock gs://<bucket_name>...\n"),
        ("event-default", "<B>SYNOPSIS</B>\n  gsutil retention event-default (set|release) gs://<bucket_name>...\n"),
        ("event", "<B>SYNOPSIS</B>\n  gsutil retention event (set|release) gs://<bucket_name>/<object_name>...\n"),
        ("temp", "<B>SYNOPSIS</B>\n  gsutil retention temp (set|release) gs://<bucket_name>/<object_name>...\n"),
    ],
    has_sub: true
);

stub_spec!(REWRITE,
    name: "rewrite",
    aliases: &[],
    summary: "Rewrite objects",
    synopsis: "\n  gsutil rewrite -k [-f] [-r] [-s <class>] url...\n",
    sub_args: "fkIrROs:", min: 0, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[], has_sub: false
);

stub_spec!(RPO,
    name: "rpo",
    aliases: &[],
    summary: "Configure replication",
    synopsis: "\n  gsutil rpo set (ASYNC_TURBO|DEFAULT) gs://<bucket_name>...\n  gsutil rpo get gs://<bucket_name>...\n",
    sub_args: "", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[("set", "<B>SYNOPSIS</B>\n  gsutil rpo set (ASYNC_TURBO|DEFAULT) gs://<bucket_name>...\n"), ("get", "<B>SYNOPSIS</B>\n  gsutil rpo get gs://<bucket_name>...\n")],
    has_sub: true
);

stub_spec!(RSYNC,
    name: "rsync",
    aliases: &[],
    summary: "Synchronize content of two buckets/directories",
    synopsis: "\n  gsutil rsync [OPTION]... src_url dst_url\n",
    sub_args: "a:cCdenpPriRuUx:y:j:J", min: 2, max: 2, file_ok: true, prov_ok: false,
    subcommands: &[], has_sub: false
);

stub_spec!(SIGNURL,
    name: "signurl",
    aliases: &["signedurl", "queryauth"],
    summary: "Create a signed URL",
    synopsis: "\n  gsutil signurl [-c <content_type>] [-d <duration>] [-m <http_method>] [-p <password>] [-r <region>] [-u] <private-key-file> url...\n",
    sub_args: "m:d:b:c:p:r:u", min: 1, max: NO_MAX, file_ok: true, prov_ok: false,
    subcommands: &[], has_sub: true
);

stub_spec!(TEST,
    name: "test",
    aliases: &[],
    summary: "Run gsutil unit/integration tests (for developers)",
    synopsis: "\n  gsutil test [-b] [-f] [-l] [-p N] [-s] [-u] [test_name...]\n",
    sub_args: "buflp:sc", min: 0, max: NO_MAX, file_ok: true, prov_ok: false,
    subcommands: &[], has_sub: false
);

stub_spec!(UBLA,
    name: "ubla",
    aliases: &["uniformbucketlevelaccess"],
    summary: "Configure Uniform bucket-level access",
    synopsis: "\n  gsutil ubla set (on|off) gs://<bucket_name>...\n  gsutil ubla get gs://<bucket_name>...\n",
    sub_args: "", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[("set", "<B>SYNOPSIS</B>\n  gsutil ubla set (on|off) gs://<bucket_name>...\n"), ("get", "<B>SYNOPSIS</B>\n  gsutil ubla get gs://<bucket_name>...\n")],
    has_sub: true
);

stub_spec!(UPDATE,
    name: "update",
    aliases: &[],
    summary: "Update to the latest gsutil release",
    synopsis: "\n  gsutil update [-f] [-n] [url]\n",
    sub_args: "fn", min: 0, max: 1, file_ok: true, prov_ok: false,
    subcommands: &[], has_sub: false
);

stub_spec!(VERSIONING,
    name: "versioning",
    aliases: &["setversioning", "getversioning"],
    summary: "Enable or suspend versioning for one or more buckets",
    synopsis: "\n  gsutil versioning set (on|off) gs://<bucket_name>...\n  gsutil versioning get gs://<bucket_name>...\n",
    sub_args: "", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[("set", "<B>SYNOPSIS</B>\n  gsutil versioning set (on|off) gs://<bucket_name>...\n"), ("get", "<B>SYNOPSIS</B>\n  gsutil versioning get gs://<bucket_name>...\n")],
    has_sub: true
);

stub_spec!(WEB,
    name: "web",
    aliases: &["setwebcfg", "getwebcfg"],
    summary: "Set a website configuration for a bucket",
    synopsis: "\n  gsutil web set [-m main_page_suffix] [-e error_page] gs://<bucket_name>...\n  gsutil web get gs://<bucket_name>\n",
    sub_args: "m:e:", min: 2, max: NO_MAX, file_ok: false, prov_ok: false,
    subcommands: &[("set", "<B>SYNOPSIS</B>\n  gsutil web set [-m main_page_suffix] [-e error_page] gs://<bucket_name>...\n"), ("get", "<B>SYNOPSIS</B>\n  gsutil web get gs://<bucket_name>\n")],
    has_sub: true
);

/// Default stub runner for unimplemented commands.
pub async fn run_stub(
    _ctx: &mut CommandContext,
    spec: &CommandSpec,
    _sub_opts: &[OptPair],
    _args: &[String],
) -> Result<i32> {
    Err(GsutilError::command(format!(
        "Command \"{}\" is not yet implemented in gsutil-rs.",
        spec.name
    )))
}
