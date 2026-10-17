//! `epistle alias`: the dispatch that turns an [`AliasCli`] into an
//! [`Outcome`]. Split out of `alias.rs` only to keep the umbrella under
//! the per-file code-line budget; the dispatch sees every helper the
//! umbrella exposes (`find_alias`, `set_enabled`, the validation and
//! mutators) and the `Outcome` type that carries its decisions back.

use std::path::Path;
use std::process::ExitCode;

use crate::config::Config;
use crate::util::address::normalize;

use super::alias_helpers::find_alias;
use super::alias_writers::{commit_reporting, set_enabled_reporting};
use super::{
	AliasCli, MemberSubcommand, SenderSubcommand, add_alias, list, member_edit, open, remove_alias,
	sender_edit, show,
};
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

impl From<&str> for Outcome {
	fn from(value: &str) -> Self {
		Outcome::Error(value.to_string())
	}
}

impl From<String> for Outcome {
	fn from(value: String) -> Self {
		Outcome::Error(value)
	}
}

/// A refusal the dispatch can return directly, so the call site keeps
/// the message and the exit-code mapping in one place.
fn refused(message: impl Into<String>) -> Outcome {
	Outcome::Refusal(message.into())
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
			let mut document = match open(path) {
				Ok(document) => document,
				Err(error) => return Outcome::Error(error),
			};
			if let Err(error) = add_alias(&config, &mut document, &args) {
				return Outcome::Error(error);
			}
			if let Some(warning) = crate::cli::disabled_domain::warning(&config, &args.address) {
				super::style::warn_to(&mut err, warning);
			}
			match commit_reporting(
				document,
				&normalize(&args.address),
				"added",
				(dry_run, json),
				&mut out,
				&mut err,
			) {
				Ok(code) => Outcome::Code(code),
				Err(error) => match error {
					crate::cli::resource::ResourceError::Refusal(message) => {
						Outcome::Refusal(message)
					}
					crate::cli::resource::ResourceError::Failure(message) => {
						Outcome::Error(message)
					}
				},
			}
		}
		AliasCli::Remove { address, yes } => {
			if find_alias(&config, &address).is_none() {
				return refused(format!("alias {address} not found"));
			}
			let owned_address = address.clone();
			let mut document = match open(path) {
				Ok(document) => document,
				Err(error) => return Outcome::Error(error),
			};
			if let Err(error) = remove_alias(&config, &mut document, &address) {
				return Outcome::Error(error);
			}
			// Asked after the edit is validated; a dry run destroys nothing.
			let question = format!("Remove alias \"{address}\"? [y/N]");
			if !dry_run
				&& let Err(code) = prompt::confirm_destructive("alias remove", &question, yes)
			{
				return code.into();
			}
			match commit_reporting(
				document,
				&owned_address,
				"removed",
				(dry_run, json),
				&mut out,
				&mut err,
			) {
				Ok(code) => Outcome::Code(code),
				Err(error) => match error {
					crate::cli::resource::ResourceError::Refusal(message) => {
						Outcome::Refusal(message)
					}
					crate::cli::resource::ResourceError::Failure(message) => {
						Outcome::Error(message)
					}
				},
			}
		}
		AliasCli::Member(args) => {
			let address = match &args.action {
				MemberSubcommand::Add { address, .. }
				| MemberSubcommand::Remove { address, .. } => address.clone(),
			};
			if find_alias(&config, &address).is_none() {
				return refused(format!("alias {address} not found"));
			}
			let mut document = match open(path) {
				Ok(document) => document,
				Err(error) => return Outcome::Error(error),
			};
			let verb = match &args.action {
				MemberSubcommand::Add { .. } => "member added",
				MemberSubcommand::Remove { .. } => "member removed",
			};
			if let Err(error) = member_edit(&config, &mut document, args) {
				return Outcome::Error(error);
			}
			match commit_reporting(
				document,
				&address,
				verb,
				(dry_run, json),
				&mut out,
				&mut err,
			) {
				Ok(code) => Outcome::Code(code),
				Err(error) => match error {
					crate::cli::resource::ResourceError::Refusal(message) => {
						Outcome::Refusal(message)
					}
					crate::cli::resource::ResourceError::Failure(message) => {
						Outcome::Error(message)
					}
				},
			}
		}
		AliasCli::Sender(args) => {
			let address = match &args.action {
				SenderSubcommand::Add { address, .. }
				| SenderSubcommand::Remove { address, .. } => address.clone(),
			};
			if find_alias(&config, &address).is_none() {
				return refused(format!("alias {address} not found"));
			}
			let mut document = match open(path) {
				Ok(document) => document,
				Err(error) => return Outcome::Error(error),
			};
			let verb = match &args.action {
				SenderSubcommand::Add { .. } => "sender added",
				SenderSubcommand::Remove { .. } => "sender removed",
			};
			if let Err(error) = sender_edit(&config, &mut document, args) {
				return Outcome::Error(error);
			}
			match commit_reporting(
				document,
				&address,
				verb,
				(dry_run, json),
				&mut out,
				&mut err,
			) {
				Ok(code) => Outcome::Code(code),
				Err(error) => match error {
					crate::cli::resource::ResourceError::Refusal(message) => {
						Outcome::Refusal(message)
					}
					crate::cli::resource::ResourceError::Failure(message) => {
						Outcome::Error(message)
					}
				},
			}
		}
		AliasCli::Enable { address } => {
			if find_alias(&config, &address).is_none() {
				return refused(format!("alias {address} not found"));
			}
			match set_enabled_reporting(&config, &address, true, json, &mut out, &mut err) {
				Ok(code) => Outcome::Code(code),
				Err(error) => match error {
					crate::cli::resource::ResourceError::Refusal(message) => {
						Outcome::Refusal(message)
					}
					crate::cli::resource::ResourceError::Failure(message) => {
						Outcome::Error(message)
					}
				},
			}
		}
		AliasCli::Disable { address } => {
			if find_alias(&config, &address).is_none() {
				return refused(format!("alias {address} not found"));
			}
			match set_enabled_reporting(&config, &address, false, json, &mut out, &mut err) {
				Ok(code) => Outcome::Code(code),
				Err(error) => match error {
					crate::cli::resource::ResourceError::Refusal(message) => {
						Outcome::Refusal(message)
					}
					crate::cli::resource::ResourceError::Failure(message) => {
						Outcome::Error(message)
					}
				},
			}
		}
	}
}
