//! Command registry, deprecated alias translation (`OLD_ALIAS_MAP`), argument
//! validation (`CommandSpec`), `--help` rewriting, and fuzzy suggestion dispatch.
//!
//! Matches `gslib/command_runner.py` and `gslib/command.py` in Python gsutil v5.38.

use gsutil_core::error::{GsutilError, Result};
use gsutil_core::url::{have_file_urls, have_provider_urls};

use crate::commands;
use crate::context::CommandContext;
use crate::difflib::get_close_matches;
use crate::getopt::{getopt, OptPair};

pub const NO_MAX: usize = usize::MAX;

/// Deprecated command aliases from `OLD_ALIAS_MAP` in `gslib/command.py` (all 15).
pub const OLD_ALIAS_MAP: &[(&str, &[&str])] = &[
    ("chacl", &["acl", "ch"]),
    ("getacl", &["acl", "get"]),
    ("setacl", &["acl", "set"]),
    ("getcors", &["cors", "get"]),
    ("setcors", &["cors", "set"]),
    ("chdefacl", &["defacl", "ch"]),
    ("getdefacl", &["defacl", "get"]),
    ("setdefacl", &["defacl", "set"]),
    ("disablelogging", &["logging", "set", "off"]),
    ("enablelogging", &["logging", "set", "on"]),
    ("getlogging", &["logging", "get"]),
    ("getversioning", &["versioning", "get"]),
    ("setversioning", &["versioning", "set"]),
    ("getwebcfg", &["web", "get"]),
    ("setwebcfg", &["web", "set"]),
];

/// Look up a deprecated alias in `OLD_ALIAS_MAP`.
pub fn lookup_old_alias(name: &str) -> Option<&'static [&'static str]> {
    OLD_ALIAS_MAP
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| *v)
}

/// Static specification of a gsutil command (mirrors `CommandSpec` + `HelpSpec`).
#[derive(Debug, Clone, Copy)]
pub struct CommandSpec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub help_aliases: &'static [&'static str],
    pub one_line_summary: &'static str,
    pub usage_synopsis: &'static str,
    pub help_text: &'static str,
    pub subcommands: &'static [(&'static str, &'static str)],
    pub min_args: usize,
    pub max_args: usize,
    pub supported_sub_args: &'static str,
    pub supported_private_args: &'static [&'static str],
    pub file_url_ok: bool,
    pub provider_url_ok: bool,
    pub urls_start_arg: usize,
    /// Commands with subcommands + subopts defer `CheckArguments` to the command itself.
    pub has_subcommands_and_subopts: bool,
}

impl CommandSpec {
    pub fn raise_wrong_num_args(&self, num_args: usize) -> GsutilError {
        let prefix = if num_args < self.min_args {
            let tail = if self.min_args > 1 { "s" } else { "" };
            format!(
                "The {} command requires at least {} argument{tail}.",
                self.name, self.min_args
            )
        } else {
            format!(
                "The {} command accepts at most {} arguments.",
                self.name, self.max_args
            )
        };
        GsutilError::command(format!(
            "{prefix} Usage:\n{}\nFor additional help run:\n  gsutil help {}",
            self.usage_synopsis, self.name
        ))
    }

    pub fn raise_invalid_argument(&self) -> GsutilError {
        GsutilError::command(format!(
            "Incorrect option(s) specified. Usage:\n{}\nFor additional help run:\n  gsutil help {}",
            self.usage_synopsis, self.name
        ))
    }
}

/// Return all registered command specifications (sorted alphabetically by canonical name).
pub fn all_commands() -> &'static [CommandSpec] {
    &commands::ALL_COMMAND_SPECS
}

/// Find a command spec by canonical name or command alias.
pub fn find_command(name: &str) -> Option<&'static CommandSpec> {
    all_commands()
        .iter()
        .find(|spec| spec.name == name || spec.aliases.contains(&name))
}

/// Collect every valid command name and command alias (for `difflib.get_close_matches`).
fn all_command_names_and_aliases() -> Vec<&'static str> {
    let mut names = Vec::new();
    for spec in all_commands() {
        names.push(spec.name);
        for &alias in spec.aliases {
            names.push(alias);
        }
    }
    names
}

/// Translate deprecated alias invocation (e.g. `getacl gs://b` -> `acl` with `["get", "gs://b"]`).
fn translate_deprecated_alias(alias_used: &str, args: &[String]) -> Vec<String> {
    if let Some(replacement) = lookup_old_alias(alias_used) {
        // Replacement is e.g. &["acl", "get"] -> prepend replacement[1..] to args.
        let mut translated: Vec<String> =
            replacement[1..].iter().map(|s| (*s).to_string()).collect();
        translated.extend_from_slice(args);
        translated
    } else {
        args.to_vec()
    }
}

/// Dispatch a named gsutil command with exact `CommandRunner.RunNamedCommand` semantics.
pub async fn run_named_command(
    ctx: &mut CommandContext,
    command_name: &str,
    raw_args: &[String],
) -> Result<i32> {
    let mut cmd_name = command_name.to_string();
    let mut args = raw_args.to_vec();

    // Include default x-goog-api-version header matching CommandRunner.RunNamedCommand.
    let api_version = ctx
        .config
        .get_or("GSUtil", "default_api_version", "1")
        .to_string();
    ctx.global
        .headers
        .insert("x-goog-api-version".to_string(), api_version);

    let Some(spec) = find_command(&cmd_name) else {
        let possibilities = all_command_names_and_aliases();
        let close = get_close_matches(&cmd_name, &possibilities, 1, 0.6);
        if let Some(&matched) = close.first() {
            let suggested = lookup_old_alias(matched)
                .and_then(|v| v.first().copied())
                .unwrap_or(matched);
            ctx.error("Did you mean this?");
            ctx.error(&format!("\t{suggested}"));
        }
        return Err(GsutilError::command(format!(
            "Invalid command \"{cmd_name}\"."
        )));
    };

    // Handle `gsutil <cmd> --help` rewriting (matches gslib/command_runner.py lines 377-386).
    if args.iter().any(|a| a == "--help") {
        let mut new_args = vec![cmd_name.clone()];
        for arg in &args {
            if spec.subcommands.iter().any(|(sub, _)| *sub == arg.as_str()) {
                new_args.push(arg.clone());
                break;
            }
        }
        cmd_name = "help".to_string();
        args = new_args;
    }

    let spec = find_command(&cmd_name)
        .ok_or_else(|| GsutilError::command(format!("Invalid command \"{cmd_name}\".")))?;

    ctx.command_alias_used = cmd_name.clone();

    // Translate OLD_ALIAS_MAP if a deprecated alias was used.
    let translated_args = translate_deprecated_alias(&cmd_name, &args);

    // Parse sub-options using getopt (skip for commands with subcommands+subopts unless they handle it).
    let (sub_opts, pos_args): (Vec<OptPair>, Vec<String>) = if spec.has_subcommands_and_subopts {
        (Vec::new(), translated_args)
    } else {
        getopt(
            &translated_args,
            spec.supported_sub_args,
            spec.supported_private_args,
        )
        .map_err(|_| spec.raise_invalid_argument())?
    };

    // Validate min_args / max_args.
    if pos_args.len() < spec.min_args || pos_args.len() > spec.max_args {
        return Err(spec.raise_wrong_num_args(pos_args.len()));
    }

    // Validate URL scheme restrictions (`CheckArguments`).
    if !spec.has_subcommands_and_subopts && pos_args.len() > spec.urls_start_arg {
        let url_slice = &pos_args[spec.urls_start_arg..];
        if !spec.file_url_ok && have_file_urls(url_slice)? {
            return Err(GsutilError::command(format!(
                "\"{}\" command does not support \"file://\" URLs. Did you mean to use a gs:// URL?",
                spec.name
            )));
        }
        if !spec.provider_url_ok && have_provider_urls(url_slice)? {
            return Err(GsutilError::command(format!(
                "\"{}\" command does not support provider-only URLs.",
                spec.name
            )));
        }
    }

    commands::execute(ctx, spec, &sub_opts, &pos_args).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global_opts::GlobalOptions;
    use gsutil_core::config::BotoConfig;

    #[test]
    fn test_all_40_plus_commands_and_15_old_aliases_registered() {
        // 40 core commands + update = 41
        assert_eq!(all_commands().len(), 41);
        assert_eq!(OLD_ALIAS_MAP.len(), 15);
        for (old_alias, target) in OLD_ALIAS_MAP {
            let spec = find_command(old_alias)
                .unwrap_or_else(|| panic!("OLD_ALIAS_MAP entry {old_alias} not registered"));
            assert_eq!(spec.name, target[0]);
        }
    }

    #[tokio::test]
    async fn test_invalid_command_error_message() {
        let mut ctx = CommandContext::new(BotoConfig::new(), GlobalOptions::default(), None);
        let err = run_named_command(&mut ctx, "notacommand", &[])
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "CommandException: Invalid command \"notacommand\"."
        );
    }

    #[tokio::test]
    async fn test_version_and_help_dispatch() {
        let mut ctx = CommandContext::new(BotoConfig::new(), GlobalOptions::default(), None);
        assert_eq!(
            run_named_command(&mut ctx, "version", &[]).await.unwrap(),
            0
        );
        assert_eq!(run_named_command(&mut ctx, "ver", &[]).await.unwrap(), 0);
        assert_eq!(run_named_command(&mut ctx, "help", &[]).await.unwrap(), 0);
        assert_eq!(
            run_named_command(&mut ctx, "ls", &["--help".to_string()])
                .await
                .unwrap(),
            0
        );
    }
}
