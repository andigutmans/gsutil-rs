//! `gsutil help` (`?`, `man`) command.

use gsutil_core::error::Result;

use crate::context::CommandContext;
use crate::dispatch::{all_commands, lookup_old_alias, CommandSpec};
use crate::getopt::OptPair;
use crate::help_topics::{
    render_help_markup, AddlHelpTopic, ADDL_HELP_TOPICS, MAX_HELP_NAME_LEN, TOP_LEVEL_USAGE_STRING,
};

pub const SYNOPSIS: &str = "\n  gsutil help [command or topic]\n";

pub const HELP_TEXT: &str = r#"<B>SYNOPSIS</B>

  gsutil help [command or topic]


<B>DESCRIPTION</B>
  The following command provides a summary of gsutil commands and additional topics on which
  help is available:

    gsutil help

  The following command provides help about the specified command or topic:

    gsutil help [command or topic]

  The following command provides help about the specified sub-command:

    gsutil help [command] [sub-command]

  For example, running the following provides help about the "set" sub-command of the "acl" command:

    gsutil help acl set

  If you set the PAGER environment variable to the path to a pager program
  (such as /bin/less on Linux), long help sections are piped through
  the specified pager.
"#;

pub const SPEC: CommandSpec = CommandSpec {
    name: "help",
    aliases: &["?", "man"],
    help_aliases: &["?"],
    one_line_summary: "Get help about commands and topics",
    usage_synopsis: SYNOPSIS,
    help_text: HELP_TEXT,
    subcommands: &[],
    min_args: 0,
    max_args: 2,
    supported_sub_args: "",
    supported_private_args: &[],
    file_url_ok: true,
    provider_url_ok: false,
    urls_start_arg: 0,
    has_subcommands_and_subopts: false,
};

enum HelpTarget {
    Command(&'static CommandSpec),
    Topic(&'static AddlHelpTopic),
}

fn find_help_target(name: &str) -> Option<HelpTarget> {
    for spec in all_commands() {
        if spec.name == name || spec.help_aliases.contains(&name) || spec.aliases.contains(&name) {
            return Some(HelpTarget::Command(spec));
        }
    }
    for topic in ADDL_HELP_TOPICS {
        if topic.name == name || topic.aliases.contains(&name) {
            return Some(HelpTarget::Topic(topic));
        }
    }
    None
}

pub fn format_top_level_help() -> String {
    let mut out = String::new();
    out.push_str(TOP_LEVEL_USAGE_STRING);
    out.push_str("\nAvailable commands:\n");
    for spec in all_commands() {
        out.push_str(&format!(
            "  {:<width$}{}\n",
            spec.name,
            spec.one_line_summary,
            width = MAX_HELP_NAME_LEN
        ));
    }
    out.push_str("\nAdditional help topics:\n");
    for topic in ADDL_HELP_TOPICS {
        out.push_str(&format!(
            "  {:<width$}{}\n",
            topic.name,
            topic.one_line_summary,
            width = MAX_HELP_NAME_LEN
        ));
    }
    out.push_str("\nUse gsutil help <command or topic> for detailed help.");
    out
}

pub async fn run(ctx: &mut CommandContext, _sub_opts: &[OptPair], args: &[String]) -> Result<i32> {
    let raw = if args.is_empty() {
        format_top_level_help()
    } else {
        let arg = &args[0];
        match find_help_target(arg) {
            None => format!("No help available for \"{arg}\""),
            Some(HelpTarget::Topic(topic)) => {
                if args.len() > 1 {
                    format!(
                        "The \"{arg}\" command has no subcommands. You can ask for the full help by running:\n\n\tgsutil help {arg}\n"
                    )
                } else {
                    format!(
                        "<B>NAME</B>\n  {} - {}\n\n\n{}",
                        topic.name,
                        topic.one_line_summary,
                        topic.help_text.trim_matches('\n')
                    )
                }
            }
            Some(HelpTarget::Command(spec)) => {
                if args.len() > 1 {
                    let sub = &args[1];
                    if let Some((_, sub_text)) =
                        spec.subcommands.iter().find(|(s, _)| *s == sub.as_str())
                    {
                        let mut text = format!(
                            "<B>NAME</B>\n  {arg} {sub} - {}\n\n\n{}",
                            spec.one_line_summary,
                            sub_text.trim_matches('\n')
                        );
                        append_deprecation_warning(&mut text, arg);
                        text
                    } else if spec.subcommands.is_empty() {
                        format!(
                            "The \"{arg}\" command has no subcommands. You can ask for the full help by running:\n\n\tgsutil help {arg}\n"
                        )
                    } else {
                        let examples: Vec<String> = spec
                            .subcommands
                            .iter()
                            .map(|(s, _)| format!("\tgsutil help {arg} {s}"))
                            .collect();
                        format!(
                            "Subcommand \"{sub}\" does not exist for command \"{arg}\".\n\
                             You can either ask for the full help about the command by running:\n\n\
                             \tgsutil help {arg}\n\n\
                             Or you can ask for help about one of the subcommands:\n\n{}",
                            examples.join("\n")
                        )
                    }
                } else {
                    let mut text = format!(
                        "<B>NAME</B>\n  {} - {}\n\n\n{}",
                        spec.name,
                        spec.one_line_summary,
                        spec.help_text.trim_matches('\n')
                    );
                    append_deprecation_warning(&mut text, arg);
                    text
                }
            }
        }
    };

    let rendered = render_help_markup(&raw, ctx.is_tty);
    ctx.println(&rendered)?;
    Ok(0)
}

fn append_deprecation_warning(out: &mut String, arg: &str) {
    if let Some(target) = lookup_old_alias(arg) {
        if let Some(new_cmd) = target.first() {
            out.push_str(&format!(
                "\n\n\n<B>DEPRECATION WARNING</B>\n\n  The \"{arg}\" alias is deprecated, and will eventually be removed completely.\n  Please use the \"{new_cmd}\" command instead."
            ));
        }
    }
}
