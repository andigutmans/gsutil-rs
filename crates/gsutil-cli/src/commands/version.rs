//! `gsutil version` (`ver`) command.

use gsutil_core::error::Result;

use crate::context::{CommandContext, GSUTIL_VERSION};
use crate::dispatch::CommandSpec;
use crate::getopt::OptPair;

pub const SYNOPSIS: &str = "\n  gsutil version\n";

pub const HELP_TEXT: &str = r#"<B>SYNOPSIS</B>

  gsutil version


<B>DESCRIPTION</B>
  Prints information about the version of gsutil.

<B>OPTIONS</B>
  -l          Prints additional information, such as the version of Rust
              being used, a checksum of the code, the path to gsutil, and the
              path to gsutil's configuration file.
"#;

pub const SPEC: CommandSpec = CommandSpec {
    name: "version",
    aliases: &["ver"],
    help_aliases: &["ver"],
    one_line_summary: "Print version info about gsutil",
    usage_synopsis: SYNOPSIS,
    help_text: HELP_TEXT,
    subcommands: &[],
    min_args: 0,
    max_args: 0,
    supported_sub_args: "l",
    supported_private_args: &[],
    file_url_ok: false,
    provider_url_ok: false,
    urls_start_arg: 0,
    has_subcommands_and_subopts: false,
};

pub async fn run(ctx: &mut CommandContext, sub_opts: &[OptPair], _args: &[String]) -> Result<i32> {
    let long_form = sub_opts.iter().any(|(o, _)| o == "-l");

    ctx.println(&format!("gsutil version: {GSUTIL_VERSION}"))?;

    if long_form {
        let config_paths = ctx.config.friendly_config_file_paths().join(", ");
        let gsutil_path = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "gsutil".to_string());
        let os_version = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
        let cloud_sdk = std::env::var("CLOUDSDK_WRAPPER").is_ok();
        let shim_enabled = ctx.config.get_bool("GSUtil", "use_gcloud_storage", false);

        let long_output = format!(
            "checksum: native-rust-binary (OK)\n\
             boto version: compat-2.49.0\n\
             python version: native-rust (gsutil-rs {pkg_ver})\n\
             OS: {os_version}\n\
             multiprocessing available: True\n\
             using cloud sdk: {cloud_sdk}\n\
             pass cloud sdk credentials to gsutil: {cloud_sdk}\n\
             config path(s): {config_paths}\n\
             gsutil path: {gsutil_path}\n\
             compiled crcmod: True\n\
             installed via package manager: False\n\
             editable install: False\n\
             shim enabled: {shim_enabled}",
            pkg_ver = env!("CARGO_PKG_VERSION"),
            cloud_sdk = if cloud_sdk { "True" } else { "False" },
            shim_enabled = if shim_enabled { "True" } else { "False" },
        );
        ctx.println(&long_output)?;
    }

    Ok(0)
}
