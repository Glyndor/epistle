//! Which argument a usage error is missing, and whether an operator can
//! pick it from a list.
//!
//! The answer comes from clap's own error (the missing value name) and from
//! walking the command line against the command tree (the subcommand path,
//! `--config`, the positionals already given). Only the arguments that name
//! something that already exists are picked: an account to show, an alias
//! to remove. A name for something new is never offered from a list.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::error::{ContextKind, ContextValue, ErrorKind};

/// What the missing argument names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Kind {
	/// An account login name.
	Account,
	/// An alias address from `[[alias]]`.
	Alias,
	/// A configured domain.
	Domain,
	/// The label of one of this account's app passwords.
	AppPassword(String),
	/// The label of a management API key.
	ApiKey,
}

impl Kind {
	/// The words the picker puts after `Pick a`.
	pub(super) fn noun(&self) -> String {
		match self {
			Kind::Account => "account".to_string(),
			Kind::Alias => "alias".to_string(),
			Kind::Domain => "domain".to_string(),
			Kind::AppPassword(account) => format!("app password of {account}"),
			Kind::ApiKey => "API key".to_string(),
		}
	}
}

/// Where the picked value goes on the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Insert {
	/// As the next positional argument.
	Positional,
	/// As the value of this option, such as `--account`.
	Option(String),
}

/// A missing argument the operator can pick.
#[derive(Debug)]
pub(super) struct Want {
	pub(super) kind: Kind,
	pub(super) insert: Insert,
	/// The configuration file the command would read.
	pub(super) config: PathBuf,
}

/// The pickable argument `error` reports missing from `args`, or `None`
/// when the error is anything else or the argument is not one to pick.
pub(super) fn want(root: &clap::Command, error: &clap::Error, args: &[OsString]) -> Option<Want> {
	if error.kind() != ErrorKind::MissingRequiredArgument {
		return None;
	}
	let missing = match error.get(ContextKind::InvalidArg)? {
		ContextValue::Strings(list) => list.first()?.clone(),
		ContextValue::String(one) => one.clone(),
		_ => return None,
	};
	let (insert, value) = parse_missing(&missing)?;
	// Built, so a subcommand lists the global options (`--config`) its
	// parent propagates to it.
	let mut root = root.clone();
	root.build();
	let line = walk(&root, args);
	let path: Vec<&str> = line.path.iter().map(String::as_str).collect();
	let kind = classify(&path, &value, &line.positionals)?;
	Some(Want {
		kind,
		insert,
		config: line
			.config
			.map_or_else(|| PathBuf::from(crate::cli::DEFAULT_CONFIG), PathBuf::from),
	})
}

/// `<NAME>` is a positional; `--account <NAME>` an option and its value.
fn parse_missing(missing: &str) -> Option<(Insert, String)> {
	let value = missing
		.rsplit_once('<')
		.and_then(|(_, rest)| rest.strip_suffix('>'))?
		.to_string();
	match missing.split_once(' ') {
		Some((flag, _)) if flag.starts_with("--") => {
			Some((Insert::Option(flag.to_string()), value))
		}
		_ => Some((Insert::Positional, value)),
	}
}

/// Which pickable thing `value` names under the subcommand `path`.
fn classify(path: &[&str], value: &str, positionals: &[String]) -> Option<Kind> {
	match (path, value) {
		(["account", "add"], _) | (["alias", "add"], _) => None,
		(["account", ..], "NAME") => Some(Kind::Account),
		(["account", "catch-all", ..], "DOMAIN") => Some(Kind::Domain),
		(["export" | "import" | "mobileconfig"], "NAME") => Some(Kind::Account),
		(["masked", ..], "ACCOUNT") => Some(Kind::Account),
		(["app-password", "create" | "revoke"], "ACCOUNT") => Some(Kind::Account),
		(["app-password", "revoke"], "LABEL") => {
			positionals.first().cloned().map(Kind::AppPassword)
		}
		(["api-key", "revoke" | "rotate"], "LABEL") => Some(Kind::ApiKey),
		(["alias", ..], "ADDRESS") => Some(Kind::Alias),
		(["domain", "show" | "remove"], "DOMAIN") => Some(Kind::Domain),
		_ => None,
	}
}

/// What the command line says, read the way clap reads it.
#[derive(Debug, Default)]
struct Line {
	path: Vec<String>,
	positionals: Vec<String>,
	config: Option<OsString>,
}

/// Walk `args` down the command tree: subcommand names extend the path,
/// option values are skipped (keeping `--config`), the rest are positionals.
fn walk(root: &clap::Command, args: &[OsString]) -> Line {
	let mut line = Line::default();
	let mut command = root;
	let mut tokens = args.iter().skip(1);
	let mut raw = false;
	while let Some(token) = tokens.next() {
		let text = token.to_string_lossy();
		if raw {
			line.positionals.push(text.into_owned());
		} else if text == "--" {
			raw = true;
		} else if let Some(long) = text.strip_prefix("--") {
			let (name, inline) = match long.split_once('=') {
				Some((name, value)) => (name, Some(OsString::from(value))),
				None => (long, None),
			};
			let takes = command
				.get_arguments()
				.any(|arg| arg.get_long() == Some(name) && arg.get_action().takes_values());
			let value = inline.or_else(|| takes.then(|| tokens.next().cloned()).flatten());
			if name == "config" {
				line.config = value;
			}
		} else if text.len() > 1 && text.starts_with('-') {
			let short = text.chars().nth(1);
			let takes = command
				.get_arguments()
				.any(|arg| arg.get_short() == short && arg.get_action().takes_values());
			if takes && text.chars().count() == 2 {
				tokens.next();
			}
		} else if let Some(sub) = command.find_subcommand(text.as_ref()) {
			line.path.push(sub.get_name().to_string());
			command = sub;
		} else {
			line.positionals.push(text.into_owned());
		}
	}
	line
}

/// `args` with `value` added where clap reads it: after the other
/// positionals, or as `--flag value` ahead of a `--` separator.
pub(super) fn insert(args: &[OsString], insert: &Insert, value: &str) -> Vec<OsString> {
	let mut out = args.to_vec();
	let separator = out.iter().position(|arg| arg == "--");
	match insert {
		Insert::Positional => {
			if separator.is_none() && value.starts_with('-') {
				out.push("--".into());
			}
			out.push(value.into());
		}
		Insert::Option(flag) => {
			let at = separator.unwrap_or(out.len());
			out.splice(at..at, [OsString::from(flag), OsString::from(value)]);
		}
	}
	out
}

#[cfg(test)]
#[path = "target_tests.rs"]
mod tests;
