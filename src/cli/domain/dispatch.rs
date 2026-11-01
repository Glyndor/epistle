//! `epistle domain`: the dispatch that turns a [`DomainCli`] into an
//! [`Outcome`]. Split out of `domain/mod.rs` only to keep the umbrella under
//! the per-file code-line budget.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::prompt;
use crate::cli::resource::ResourceError;
use crate::config::Config;

use super::writers::{add_commit, alias_commit, commit, remove_commit};
use super::{
	DomainAliasSubcommand, DomainCli, add_alias_map, add_domain, list, open, remove_alias_map,
	remove_domain, show,
};
use super::{own_key, set, state};

/// Seconds since the epoch, the clock the new key's selector is named after.
fn now_epoch() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |elapsed| elapsed.as_secs())
}

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

/// `domain enable|disable`: edit, then `confirm` (only for a change that is
/// neither a dry run nor already in effect), then commit.
fn switch(
	path: &Path,
	config: &Config,
	(domain, enabled): (&str, bool),
	(dry_run, json): (bool, bool),
	confirm: impl FnOnce(&str) -> Result<(), ExitCode>,
) -> Outcome {
	if !known_domain(config, domain) {
		return refused(format!("domain {domain} is not configured"));
	}
	let mut document = match open(path) {
		Ok(document) => document,
		Err(error) => return Outcome::Error(error),
	};
	if let Err(error) = state::set_enabled(config, &mut document, domain, enabled) {
		// A rule of the server, not a mistake in the command: exit code 3.
		return Outcome::Code(super::super::exit::policy(error));
	}
	let already = state::is_enabled(config, domain) == enabled;
	if !dry_run
		&& !already
		&& let Err(code) = confirm(domain)
	{
		return code.into();
	}
	let mut out = std::io::stdout().lock();
	let mut err = super::style::stderr();
	match commit(
		document,
		state::commit(domain, enabled),
		(dry_run, json),
		&mut out,
		&mut err,
	) {
		Ok(code) => {
			// Mail already accepted for sending is not dropped by switching
			// the domain off; say how much of it there is.
			if !enabled && !dry_run && !already {
				match state::queued_from(config, domain) {
					Some(0) | None => {}
					Some(1) => super::style::warn_to(
						&mut err,
						format_args!(
							"1 queued message has a sender in {domain} and is still delivered; \
							 `epistle queue remove` drops one"
						),
					),
					Some(count) => super::style::warn_to(
						&mut err,
						format_args!(
							"{count} queued messages have a sender in {domain} and are still \
							 delivered; `epistle queue remove` drops one"
						),
					),
				}
			}
			Outcome::Code(code)
		}
		Err(ResourceError::Refusal(message)) => Outcome::Refusal(message),
		Err(ResourceError::Failure(message)) => Outcome::Error(message),
	}
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
		DomainCli::Add {
			domain,
			shared_dkim_key,
		} => {
			let mut document = match open(path) {
				Ok(document) => document,
				Err(error) => return Outcome::Error(error),
			};
			if let Err(error) = add_domain(&config, &mut document, &domain) {
				return Outcome::Error(error);
			}
			// The domain's own key is made after the edit is known to be valid
			// and before it is committed, so the record printed is the one the
			// key publishes. A key made for a commit that then fails is removed.
			let shared = (shared_dkim_key, dry_run);
			let created = match own_key::give(&config, &mut document, &domain, shared, now_epoch())
			{
				Ok(created) => created,
				Err(error) => return Outcome::Error(error),
			};
			let mode = (dry_run, json);
			match commit(document, add_commit(&domain), mode, &mut out, &mut err) {
				Ok(code) => Outcome::Code(code),
				Err(error) => {
					crate::dkim::domain_keys::remove(&created);
					match error {
						ResourceError::Refusal(message) => Outcome::Refusal(message),
						ResourceError::Failure(message) => Outcome::Error(message),
					}
				}
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
		DomainCli::Set {
			domain,
			quota,
			no_quota,
			submission_rate,
			no_submission_rate,
		} => {
			if !known_domain(&config, &domain) {
				return refused(format!("domain {domain} is not configured"));
			}
			let change = match set::Change::parse(
				(quota.as_deref(), no_quota),
				(submission_rate.as_deref(), no_submission_rate),
			) {
				Ok(change) => change,
				Err(error) => return refused(error),
			};
			let domain = domain.trim().to_ascii_lowercase();
			let mut document = match open(path) {
				Ok(document) => document,
				Err(error) => return Outcome::Error(error),
			};
			if let Err(error) = change.apply(&mut document, &domain) {
				return Outcome::Error(error);
			}
			let mut out = std::io::stdout().lock();
			let mut err = super::style::stderr();
			match commit(
				document,
				set::commit(&domain, &change),
				(dry_run, json),
				&mut out,
				&mut err,
			) {
				Ok(code) => Outcome::Code(code),
				Err(ResourceError::Refusal(message)) => Outcome::Refusal(message),
				Err(ResourceError::Failure(message)) => Outcome::Error(message),
			}
		}
		DomainCli::Disable { domain, yes } => {
			let question = format!(
				"Disable domain \"{domain}\"? Mail for it is rejected until it is enabled again. [y/N]"
			);
			switch(path, &config, (&domain, false), (dry_run, json), |_| {
				prompt::confirm_destructive("domain disable", &question, yes)
			})
		}
		DomainCli::Enable { domain } => {
			switch(path, &config, (&domain, true), (dry_run, json), |_| Ok(()))
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
