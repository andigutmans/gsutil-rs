//! POSIX `getopt.getopt` implementation matching Python's `getopt` module.
//!
//! Python gsutil uses `getopt.getopt` (NOT `gnu_getopt`) for both global options
//! (`gslib/utils/arg_helper.py`) and per-command sub-options (`gslib/command.py`).
//! Key behaviors preserved for exact parity:
//! - Stops parsing options at the first non-option argument.
//! - Treats `--` as end-of-options terminator.
//! - Treats single `-` as a non-option positional argument.
//! - Supports bundled short flags (`-mq`, `-DD`, `-hfoo:bar`, `-oGSUtil:k=v`).
//! - Supports long options (`--flag`, `--flag=val`, `--flag val`, unique prefix matching).
//! - Produces exact Python `getopt.GetoptError` messages.

use gsutil_core::error::{GsutilError, Result};

/// Parsed option pair `(flag_with_dashes, value_or_empty)`.
pub type OptPair = (String, String);

/// Parse `args` using Python `getopt.getopt` semantics.
///
/// - `shortopts`: string like `"dDvo:?h:i:u:mq"` where `:` after a char means it requires an argument.
/// - `longopts`: slice like `&["debug", "trace-token="]` where trailing `=` means it requires an argument.
pub fn getopt(
    args: &[String],
    shortopts: &str,
    longopts: &[&str],
) -> Result<(Vec<OptPair>, Vec<String>)> {
    let mut opts = Vec::new();
    let mut idx = 0;

    while idx < args.len() {
        let arg = &args[idx];
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        if arg == "--" {
            idx += 1;
            break;
        }
        if let Some(long_part) = arg.strip_prefix("--") {
            let (pair, consumed) = parse_long(long_part, longopts, &args[idx + 1..])?;
            opts.push(pair);
            idx += 1 + consumed;
        } else {
            let short_part = &arg[1..];
            let (pairs, consumed) = parse_short(short_part, shortopts, &args[idx + 1..])?;
            opts.extend(pairs);
            idx += 1 + consumed;
        }
    }

    let remaining = args[idx..].to_vec();
    Ok((opts, remaining))
}

fn short_has_arg(opt: char, shortopts: &str) -> std::result::Result<bool, GsutilError> {
    let chars: Vec<char> = shortopts.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c == ':' {
            continue;
        }
        if c == opt {
            return Ok(chars.get(i + 1) == Some(&':'));
        }
    }
    Err(GsutilError::command(format!(
        "option -{opt} not recognized"
    )))
}

fn parse_short(
    optstring: &str,
    shortopts: &str,
    rest_args: &[String],
) -> Result<(Vec<OptPair>, usize)> {
    let mut opts = Vec::new();
    let mut consumed = 0;
    for (byte_idx, c) in optstring.char_indices() {
        let requires_arg = short_has_arg(c, shortopts)?;
        if requires_arg {
            let remainder = &optstring[byte_idx + c.len_utf8()..];
            let optarg = if !remainder.is_empty() {
                remainder.to_string()
            } else if let Some(next_arg) = rest_args.get(consumed) {
                consumed += 1;
                next_arg.clone()
            } else {
                return Err(GsutilError::command(format!(
                    "option -{c} requires argument"
                )));
            };
            opts.push((format!("-{c}"), optarg));
            break;
        } else {
            opts.push((format!("-{c}"), String::new()));
        }
    }

    Ok((opts, consumed))
}

fn parse_long(opt_raw: &str, longopts: &[&str], rest_args: &[String]) -> Result<(OptPair, usize)> {
    let (opt_name, explicit_arg) = match opt_raw.split_once('=') {
        Some((k, v)) => (k, Some(v.to_string())),
        None => (opt_raw, None),
    };

    let (has_arg, canonical) = long_has_args(opt_name, longopts)?;
    let mut consumed = 0;

    let optarg = if has_arg {
        if let Some(val) = explicit_arg {
            val
        } else if let Some(next_arg) = rest_args.first() {
            consumed = 1;
            next_arg.clone()
        } else {
            return Err(GsutilError::command(format!(
                "option --{canonical} requires argument"
            )));
        }
    } else if explicit_arg.is_some() {
        return Err(GsutilError::command(format!(
            "option --{canonical} must not have an argument"
        )));
    } else {
        String::new()
    };

    Ok(((format!("--{canonical}"), optarg), consumed))
}

fn long_has_args(opt: &str, longopts: &[&str]) -> Result<(bool, String)> {
    let possibilities: Vec<&str> = longopts
        .iter()
        .copied()
        .filter(|o| o.starts_with(opt))
        .collect();

    if possibilities.is_empty() {
        return Err(GsutilError::command(format!(
            "option --{opt} not recognized"
        )));
    }

    // Exact match takes precedence over prefix match.
    for &p in &possibilities {
        if p == opt {
            return Ok((false, opt.to_string()));
        }
        if let Some(stripped) = p.strip_suffix('=') {
            if stripped == opt {
                return Ok((true, opt.to_string()));
            }
        }
    }

    if possibilities.len() > 1 {
        return Err(GsutilError::command(format!(
            "option --{opt} not a unique prefix"
        )));
    }

    let unique = possibilities[0];
    if let Some(stripped) = unique.strip_suffix('=') {
        Ok((true, stripped.to_string()))
    } else {
        Ok((false, unique.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn test_short_and_bundled_flags() {
        let (opts, args) = getopt(&s(&["-mq", "-DD", "ls", "-l"]), "dDmq", &[]).unwrap();
        assert_eq!(
            opts,
            vec![
                ("-m".into(), "".into()),
                ("-q".into(), "".into()),
                ("-D".into(), "".into()),
                ("-D".into(), "".into()),
            ]
        );
        assert_eq!(args, s(&["ls", "-l"]));
    }

    #[test]
    fn test_short_with_attached_and_separate_arg() {
        let (opts, args) = getopt(
            &s(&["-hContent-Type:text/plain", "-o", "GSUtil:k=v", "cp"]),
            "h:o:",
            &[],
        )
        .unwrap();
        assert_eq!(
            opts,
            vec![
                ("-h".into(), "Content-Type:text/plain".into()),
                ("-o".into(), "GSUtil:k=v".into()),
            ]
        );
        assert_eq!(args, s(&["cp"]));
    }

    #[test]
    fn test_long_options_and_terminator() {
        let (opts, args) = getopt(
            &s(&[
                "--quiet",
                "--trace-token=abc",
                "--impersonate-service-account",
                "sa@proj.iam.gserviceaccount.com",
                "--",
                "-v",
            ]),
            "v",
            &["quiet", "trace-token=", "impersonate-service-account="],
        )
        .unwrap();
        assert_eq!(
            opts,
            vec![
                ("--quiet".into(), "".into()),
                ("--trace-token".into(), "abc".into()),
                (
                    "--impersonate-service-account".into(),
                    "sa@proj.iam.gserviceaccount.com".into()
                ),
            ]
        );
        assert_eq!(args, s(&["-v"]));
    }

    #[test]
    fn test_error_messages_match_python() {
        let e1 = getopt(&s(&["-z"]), "mq", &[]).unwrap_err();
        assert_eq!(e1.to_string(), "CommandException: option -z not recognized");

        let e2 = getopt(&s(&["-o"]), "o:", &[]).unwrap_err();
        assert_eq!(
            e2.to_string(),
            "CommandException: option -o requires argument"
        );

        let e3 = getopt(&s(&["--nope"]), "", &["quiet"]).unwrap_err();
        assert_eq!(
            e3.to_string(),
            "CommandException: option --nope not recognized"
        );

        let e4 = getopt(&s(&["--quiet=1"]), "", &["quiet"]).unwrap_err();
        assert_eq!(
            e4.to_string(),
            "CommandException: option --quiet must not have an argument"
        );
    }
}
