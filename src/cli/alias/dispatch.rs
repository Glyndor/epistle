//! `epistle alias`: the dispatch that turns an [`AliasCli`] into an
//! [`Outcome`]. Split out of `src/cli/alias/mod.rs` only to keep the umbrella
//! under the per-file code-line budget. Every change to the aliases goes
//! through [`crate::aliases::edit`], the layer the `/api/v1/aliases` routes use.

use std::path::Path;
use std::process::ExitCode;

use crate::aliases::{AliasError, Change, edit};
use crate::config::Config;

use super::helpers::find_alias;
use super::state::{Mode, commit_state};
use super::writers::set_enabled_reporting;
use super::{AliasCli, MemberSubcommand, SenderSubcommand, list, show};
use crate::cli::prompt;

/// The discriminated result of [`execute`]. Returning a structured
/// outcome (rather than `Result<ExitCode, String>`) lets the refusal
/// path surface exit code 2 instead of being squashed into the
/// generic failure exit code.
pub(super) enum Outcome {
	/// The action did what was asked.
	Code(ExitCode),
	/// An I/O or parse-layer failure: the command should be retried
	/// once the underlying problem clears.
	Error(String),
	/// A usage error: the command refused an unknown name with a message
	/// the operator can act on. Maps to exit code 2.
	Refusal(String),
}

impl From<ExitCode> for Outcome {
	fn from(value: ExitCode) -> Self {
		Outcome::Code(value)
	}
}

/// A refusal the dispatch can return directly, so the call site keeps
/// the message and the exit-code mapping in one place.
fn refused(message: impl Into<String>) -> Outcome {
	Outcome::Refusal(message.into())
}

/// How a refused change maps to the command's exit codes: an unknown alias
/// is a usage error (2), a cap of the server is exit code 3, and everything
/// else is a failure (1).
fn from_edit(error: AliasError) -> Outcome {
	match error {
		AliasError::NotFound(message) => Outcome::Refusal(message),
		AliasError::Capped(reached) => Outcome::Code(crate::cli::exit::policy(reached.to_string())),
		other => Outcome::Error(other.to_string()),
	}
}

/// Commit `change` and report it.
fn change(
	config: &Config,
	change: Change,
	verb: &str,
	mode: Mode,
	out: &mut impl std::io::Write,
	err: &mut impl std::io::Write,
) -> Outcome {
	match commit_state(config, &change, verb, mode, out, err) {
		Ok(code) => Outcome::Code(code),
		Err(error) => from_edit(error),
	}
}

/// Run the chosen alias action and produce an [`Outcome`] the umbrella's
/// [`super::run`] can map to an exit code.
pub(super) fn execute(path: &Path, action: AliasCli, dry_run: bool, json: bool) -> Outcome {
	let mut out = std::io::stdout().lock();
	let mut err = super::style::stderr();
	let config = match Config::load(path) {
		Ok(config) => config,
		Err(error) => return Outcome::Error(error.to_string()),
	};
	let mode = Mode { dry_run, json };
	match action {
		AliasCli::List { json: leaf } => match list(&config, leaf || json, &mut out) {
			Ok(()) => Outcome::Code(ExitCode::SUCCESS),
			Err(error) => Outcome::Error(error.to_string()),
		},
		AliasCli::Show {
			address,
			json: leaf,
		} => {
			if find_alias(&config, &address).is_none() {
				return refused("alias not found");
			}
			match show(&config, &address, leaf || json, &mut out) {
				Ok(()) => Outcome::Code(ExitCode::SUCCESS),
				Err(error) => Outcome::Error(error.to_string()),
			}
		}
		AliasCli::Add(args) => {
			if let Some(warning) = crate::cli::disabled_domain::warning(&config, &args.address) {
				super::style::warn_to(&mut err, warning);
			}
			let new = crate::aliases::edit::NewAlias {
				address: args.address,
				members: args.members,
				senders: args.senders,
				list_id: args.list_id,
				hidden: !args.visible,
			};
			change(&config, Change::Add(new), "added", mode, &mut out, &mut err)
		}
		AliasCli::Remove { address, yes } => {
			if find_alias(&config, &address).is_none() {
				return refused(format!("alias {address} not found"));
			}
			// Asked after the edit is validated; a dry run destroys nothing.
			let removal = Change::Remove {
				address: address.clone(),
			};
			if let Err(error) = edit::preview(&config, &removal, &crate::aliases::Origin::Operator)
			{
				return from_edit(error);
			}
			let question = format!("Remove alias \"{address}\"? [y/N]");
			if !dry_run
				&& let Err(code) = prompt::confirm_destructive("alias remove", &question, yes)
			{
				return code.into();
			}
			change(&config, removal, "removed", mode, &mut out, &mut err)
		}
		AliasCli::Member(args) => {
			let (address, edit, verb) = match args.action {
				MemberSubcommand::Add { address, member } => (
					address.clone(),
					Change::MemberAdd { address, member },
					"member added",
				),
				MemberSubcommand::Remove { address, member } => (
					address.clone(),
					Change::MemberRemove { address, member },
					"member removed",
				),
			};
			if find_alias(&config, &address).is_none() {
				return refused(format!("alias {address} not found"));
			}
			change(&config, edit, verb, mode, &mut out, &mut err)
		}
		AliasCli::Sender(args) => {
			let (address, edit, verb) = match args.action {
				SenderSubcommand::Add { address, sender } => (
					address.clone(),
					Change::SenderAdd { address, sender },
					"sender added",
				),
				SenderSubcommand::Remove { address, sender } => (
					address.clone(),
					Change::SenderRemove { address, sender },
					"sender removed",
				),
			};
			if find_alias(&config, &address).is_none() {
				return refused(format!("alias {address} not found"));
			}
			change(&config, edit, verb, mode, &mut out, &mut err)
		}
		AliasCli::Enable { address } => {
			set_enabled(&config, &address, true, json, &mut out, &mut err)
		}
		AliasCli::Disable { address } => {
			set_enabled(&config, &address, false, json, &mut out, &mut err)
		}
	}
}

fn set_enabled(
	config: &Config,
	address: &str,
	enabled: bool,
	json: bool,
	out: &mut impl std::io::Write,
	err: &mut impl std::io::Write,
) -> Outcome {
	if find_alias(config, address).is_none() {
		return refused(format!("alias {address} not found"));
	}
	match set_enabled_reporting(config, address, enabled, json, out, err) {
		Ok(code) => Outcome::Code(code),
		Err(error) => match error {
			crate::cli::resource::ResourceError::Refusal(message) => Outcome::Refusal(message),
			crate::cli::resource::ResourceError::Failure(message) => Outcome::Error(message),
		},
	}
}
