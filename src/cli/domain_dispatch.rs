//! `epistle domain`: the dispatch that turns a [`DomainCli`] into an
//! [`Outcome`]. Split out of `domain.rs` only to keep the umbrella under
//! the per-file code-line budget.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::prompt;
use crate::cli::resource::ResourceError;
use crate::config::Config;

use super::domain_writers::{add_commit, alias_commit, commit, remove_commit};
use super::{
	DomainAliasSubcommand, DomainCli, add_alias_map, add_domain, list, open, remove_alias_map,
	remove_domain, show,
};

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
	/// A usage error: the command refused an unknown domain with a
	/// message the operator can act on. Maps to exit code 2.
	Refusal(String),
}

impl From<String> for Outcome {
	fn from(value: String) -> Self {
		Outcome::Error(value)
	}
}

impl From<&str> for Outcome {
	fn from(value: &str) -> Self {
		Outcome::Error(value.to_string())
	}
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

/// `true` when `domain` is configured. The dispatch uses this to
/// distinguish a "not found" path (a refusal, exit 2) from a
/// configuration layer failure (exit 1).
fn known_domain(config: &Config, domain: &str) -> bool {
	config
		.domains
		.iter()
		.any(|existing| existing.eq_ignore_ascii_case(domain))
}

/// `true` when `alias` is already in the `domain_aliases` map.
fn known_domain_alias(config: &Config, alias: &str) -> bool {
	config
		.domain_aliases
		.iter()
		.any(|(existing, _)| existing.eq_ignore_ascii_case(alias))
}

/// Run the chosen domain action and produce an [`Outcome`] the
/// umbrella's [`super::run`] can map to an exit code.
pub(super) fn execute(path: &Path, action: DomainCli, dry_run: bool, json: bool) -> Outcome {
	let mut out = std::io::stdout().lock();
	let mut err = super::style::stderr();
	let config = match Config::load(path) {
		Ok(config) => config,
		Err(error) => return Outcome::Error(error.to_string()),
	};
	match action {
		DomainCli::List { json: leaf } => {
			if let Err(error) = list(&config, leaf || json, &mut out) {
				return Outcome::Error(error.to_string());
			}
			Outcome::Code(ExitCode::SUCCESS)
		}
		DomainCli::Show { domain, json: leaf } => {
			if !known_domain(&config, &domain) {
				return refused(format!("domain {domain} is not configured"));
			}
			if let Err(error) = show(&config, &domain, leaf || json, &mut out) {
				return Outcome::Error(error.to_string());
			}
			Outcome::Code(ExitCode::SUCCESS)
		}
		DomainCli::Add { domain } => {
			let mut document = match open(path) {
				Ok(document) => document,
				Err(error) => return Outcome::Error(error),
			};
			if let Err(error) = add_domain(&config, &mut document, &domain) {
				return Outcome::Error(error);
			}
			let mode = (dry_run, json);
			match commit(document, add_commit(&domain), mode, &mut out, &mut err) {
				Ok(code) => Outcome::Code(code),
				Err(error) => match error {
					ResourceError::Refusal(message) => Outcome::Refusal(message),
					ResourceError::Failure(message) => Outcome::Error(message),
				},
			}
		}
		DomainCli::Remove { domain, yes } => {
			if !known_domain(&config, &domain) {
				return refused(format!("domain {domain} is not configured"));
			}
			let mut document = match open(path) {
				Ok(document) => document,
				Err(error) => return Outcome::Error(error),
			};
			if let Err(error) = remove_domain(&config, &mut document, &domain) {
				return Outcome::Error(error);
			}
			// Asked after the edit is validated, so a refused removal is
			// reported before anyone is asked; a dry run destroys nothing.
			let question = format!("Remove domain \"{domain}\" from the configuration? [y/N]");
			if !dry_run
				&& let Err(code) = prompt::confirm_destructive("domain remove", &question, yes)
			{
				return code.into();
			}
			let mode = (dry_run, json);
			match commit(document, remove_commit(&domain), mode, &mut out, &mut err) {
				Ok(code) => Outcome::Code(code),
				Err(error) => match error {
					ResourceError::Refusal(message) => Outcome::Refusal(message),
					ResourceError::Failure(message) => Outcome::Error(message),
				},
			}
		}
		DomainCli::Alias(args) => match args.action {
			DomainAliasSubcommand::Add { alias, target } => {
				let mut document = match open(path) {
					Ok(document) => document,
					Err(error) => return Outcome::Error(error),
				};
				let owned_alias = alias.clone();
				if let Err(error) = add_alias_map(&config, &mut document, &alias, &target) {
					return Outcome::Error(error);
				}
				let edit = alias_commit(&owned_alias, "added");
				match commit(document, edit, (dry_run, json), &mut out, &mut err) {
					Ok(code) => Outcome::Code(code),
					Err(error) => match error {
						ResourceError::Refusal(message) => Outcome::Refusal(message),
						ResourceError::Failure(message) => Outcome::Error(message),
					},
				}
			}
			DomainAliasSubcommand::Remove { alias, yes } => {
				if !known_domain_alias(&config, &alias) {
					return refused(format!("domain alias {alias} is not declared"));
				}
				let mut document = match open(path) {
					Ok(document) => document,
					Err(error) => return Outcome::Error(error),
				};
				let owned_alias = alias.clone();
				if let Err(error) = remove_alias_map(&config, &mut document, &alias) {
					return Outcome::Error(error);
				}
				let question = format!("Remove domain alias \"{alias}\"? [y/N]");
				if !dry_run
					&& let Err(code) =
						prompt::confirm_destructive("domain alias remove", &question, yes)
				{
					return code.into();
				}
				let edit = alias_commit(&owned_alias, "removed");
				match commit(document, edit, (dry_run, json), &mut out, &mut err) {
					Ok(code) => Outcome::Code(code),
					Err(error) => match error {
						ResourceError::Refusal(message) => Outcome::Refusal(message),
						ResourceError::Failure(message) => Outcome::Error(message),
					},
				}
			}
		},
	}
}
