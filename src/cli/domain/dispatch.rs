//! `epistle domain`: the dispatch that turns a [`DomainCli`] into an
//! [`Outcome`]. Split out of `domain/mod.rs` only to keep the umbrella under
//! the per-file code-line budget.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::prompt;
use crate::config::Config;
use crate::dns::skip::DomainRole;
use crate::domain::state::edit::add::{self, Signing};
use crate::domain::state::{Change, EditError, StoredRole};

use super::writers::{Mode, add_commit, alias_commit, commit_state, remove_commit};
use super::{DomainAliasSubcommand, DomainCli, list, set, show, state};

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
	/// An I/O or parse-layer failure, or a change the rules refused.
	Error(String),
	/// A usage error: the command refused an unknown domain with a
	/// message the operator can act on. Maps to exit code 2.
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

/// How a refused change maps to the command's exit codes: an unknown domain
/// or alias is a usage error (2) when `unknown_is_usage`, a rule of the
/// server is exit code 3, and everything else is a failure (1).
fn from_edit(error: EditError, unknown_is_usage: bool) -> Outcome {
	match error {
		EditError::NotFound(message) if unknown_is_usage => Outcome::Refusal(message),
		EditError::Policy(message) => Outcome::Code(super::super::exit::policy(message)),
		other => Outcome::Error(other.to_string()),
	}
}

/// `true` when `domain` is hosted. The dispatch uses this to
/// distinguish a "not found" path (a refusal, exit 2) from a
/// configuration layer failure (exit 1).
fn known_domain(config: &Config, domain: &str) -> bool {
	config
		.domains
		.iter()
		.any(|existing| existing.eq_ignore_ascii_case(domain.trim()))
}

/// Whether `domain` is hosted and switched on.
fn is_enabled(config: &Config, domain: &str) -> bool {
	!config
		.disabled_domains
		.iter()
		.any(|disabled| disabled.eq_ignore_ascii_case(domain.trim()))
}

/// The stored role of a `--send-only`/`--receive-only`/`--full` flag set.
fn stored(role: Option<DomainRole>) -> Option<StoredRole> {
	role.and_then(StoredRole::of)
}

/// `domain enable|disable`: `confirm` (only for a change that is neither a
/// dry run nor already in effect), then commit.
fn switch(
	config: &Config,
	(domain, enabled): (&str, bool),
	mode: Mode,
	confirm: impl FnOnce(&str) -> Result<(), ExitCode>,
) -> Outcome {
	if !known_domain(config, domain) {
		return refused(format!("domain {domain} is not configured"));
	}
	let change = Change::SetEnabled {
		name: domain.to_string(),
		enabled,
	};
	// The rules run first, so a refused switch is reported before anyone is
	// asked.
	if let Err(error) = crate::domain::state::edit::preview(config, &change) {
		return from_edit(error, true);
	}
	let already = is_enabled(config, domain) == enabled;
	if !mode.dry_run
		&& !already
		&& let Err(code) = confirm(domain)
	{
		return code.into();
	}
	let mut out = std::io::stdout().lock();
	let mut err = super::style::stderr();
	match commit_state(
		config,
		&change,
		state::commit(domain, enabled),
		mode,
		&mut out,
		&mut err,
	) {
		Ok((code, committed)) => {
			// Mail already accepted for sending is not dropped by switching
			// the domain off; say how much of it there is.
			if !enabled && !mode.dry_run && committed.changed {
				warn_queued(config, domain, &mut err);
			}
			Outcome::Code(code)
		}
		Err(error) => from_edit(error, true),
	}
}

fn warn_queued(config: &Config, domain: &str, err: &mut impl std::io::Write) {
	match state::queued_from(config, domain) {
		Some(0) | None => {}
		Some(1) => super::style::warn_to(
			err,
			format_args!(
				"1 queued message has a sender in {domain} and is still \
				 delivered; `epistle queue remove` drops one"
			),
		),
		Some(count) => super::style::warn_to(
			err,
			format_args!(
				"{count} queued messages have a sender in {domain} and are still \
				 delivered; `epistle queue remove` drops one"
			),
		),
	}
}

/// `domain add`: make the key and the secret, commit, and remove the key
/// when the entry that names it did not reach the file.
fn add(
	config: &Config,
	domain: &str,
	(shared_dkim_key, role): (bool, Option<DomainRole>),
	mode: Mode,
) -> Outcome {
	let signing = if shared_dkim_key {
		Signing::SharedKey
	} else {
		Signing::OwnKey
	};
	let role = stored(role).unwrap_or_default();
	let prepared = match add::prepare(config, domain, role, (signing, mode.dry_run), now_epoch()) {
		Ok(prepared) => prepared,
		Err(error) => return from_edit(error, false),
	};
	let mut out = std::io::stdout().lock();
	let mut err = super::style::stderr();
	match commit_state(
		config,
		&prepared.change,
		add_commit(domain),
		mode,
		&mut out,
		&mut err,
	) {
		Ok((code, _)) => Outcome::Code(code),
		Err(error) => {
			// The keys go only when the entry that names them did not reach
			// the file: a failure after the write (a closed pipe while
			// printing the records) leaves a state that refers to them.
			if !names_key(config, domain) {
				add::discard(&prepared);
			}
			from_edit(error, false)
		}
	}
}

/// Whether the state file on disk names a key for `domain`. A file that
/// cannot be read keeps the keys: deleting a key that may be in use is the
/// worse mistake.
fn names_key(config: &Config, domain: &str) -> bool {
	let path = crate::domain::state::path(&config.data_dir);
	match crate::domain::state::DomainsFile::read(&path) {
		Ok(Some(file)) => file
			.domain(domain)
			.is_some_and(|hosted| hosted.dkim.is_some()),
		Ok(None) => false,
		Err(_) => true,
	}
}

/// `domain set`: role and limits share one atomic data-directory commit.
fn set_domain(config: &Config, domain: &str, change: set::Change, mode: Mode) -> Outcome {
	let edit = Change::Set {
		name: domain.trim().to_ascii_lowercase(),
		role: stored(change.role),
		quota: change.quota,
		submission_rate: change.submission_rate.map(|value| value.map(|n| n as u32)),
	};
	let mut out = std::io::stdout().lock();
	let mut err = super::style::stderr();
	match commit_state(
		config,
		&edit,
		set::commit(domain, &change),
		mode,
		&mut out,
		&mut err,
	) {
		Ok((code, _)) => Outcome::Code(code),
		Err(error) => from_edit(error, true),
	}
}

/// Run a change that is asked about first: `question` is put after the
/// rules accepted the change, so a refused change is reported before anyone
/// is asked; a dry run destroys nothing and asks nothing.
fn confirmed(
	config: &Config,
	change: Change,
	commit_line: super::writers::Commit,
	mode: Mode,
	(what, question, yes): (&str, String, bool),
) -> Outcome {
	if let Err(error) = crate::domain::state::edit::preview(config, &change) {
		return from_edit(error, true);
	}
	if !mode.dry_run
		&& let Err(code) = prompt::confirm_destructive(what, &question, yes)
	{
		return code.into();
	}
	let mut out = std::io::stdout().lock();
	let mut err = super::style::stderr();
	match commit_state(config, &change, commit_line, mode, &mut out, &mut err) {
		Ok((code, _)) => Outcome::Code(code),
		Err(error) => from_edit(error, true),
	}
}

/// Run the chosen domain action and produce an [`Outcome`] the
/// umbrella's [`super::run`] can map to an exit code.
pub(super) fn execute(path: &Path, action: DomainCli, dry_run: bool, json: bool) -> Outcome {
	let mode = Mode { dry_run, json };
	if let DomainCli::Import { yes } = action {
		return import(path, mode, yes);
	}
	let mut out = std::io::stdout().lock();
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
			send_only,
			receive_only,
		} => {
			drop(out);
			let role = match (send_only, receive_only) {
				(true, _) => Some(DomainRole::SendOnly),
				(false, true) => Some(DomainRole::ReceiveOnly),
				(false, false) => None,
			};
			add(&config, &domain, (shared_dkim_key, role), mode)
		}
		DomainCli::Remove { domain, yes } => {
			drop(out);
			if !known_domain(&config, &domain) {
				return refused(format!("domain {domain} is not configured"));
			}
			let question = format!("Remove domain \"{domain}\" from the configuration? [y/N]");
			confirmed(
				&config,
				Change::Remove {
					name: domain.clone(),
				},
				remove_commit(&domain),
				mode,
				("domain remove", question, yes),
			)
		}
		DomainCli::Set {
			domain,
			quota,
			no_quota,
			submission_rate,
			no_submission_rate,
			send_only,
			receive_only,
			full,
		} => {
			drop(out);
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
			let role = match (send_only, receive_only, full) {
				(true, _, _) => Some(DomainRole::SendOnly),
				(false, true, _) => Some(DomainRole::ReceiveOnly),
				(false, false, true) => Some(DomainRole::Full),
				(false, false, false) => None,
			};
			set_domain(&config, &domain, change.with_role(role), mode)
		}
		DomainCli::Disable { domain, yes } => {
			drop(out);
			let question = format!(
				"Disable domain \"{domain}\"? Mail for it is rejected until it is enabled again. [y/N]"
			);
			switch(&config, (&domain, false), mode, |_| {
				prompt::confirm_destructive("domain disable", &question, yes)
			})
		}
		DomainCli::Enable { domain } => {
			drop(out);
			switch(&config, (&domain, true), mode, |_| Ok(()))
		}
		DomainCli::Alias(args) => {
			drop(out);
			match args.action {
				DomainAliasSubcommand::Add { alias, target } => {
					let change = Change::AliasAdd {
						alias: alias.clone(),
						target,
					};
					let mut out = std::io::stdout().lock();
					let mut err = super::style::stderr();
					match commit_state(
						&config,
						&change,
						alias_commit(&alias, "added"),
						mode,
						&mut out,
						&mut err,
					) {
						Ok((code, _)) => Outcome::Code(code),
						Err(error) => from_edit(error, false),
					}
				}
				DomainAliasSubcommand::Remove { alias, yes } => {
					if !config
						.domain_aliases
						.keys()
						.any(|existing| existing.eq_ignore_ascii_case(alias.trim()))
					{
						return refused(format!("domain alias {alias} is not declared"));
					}
					let question = format!("Remove domain alias \"{alias}\"? [y/N]");
					confirmed(
						&config,
						Change::AliasRemove {
							alias: alias.clone(),
						},
						alias_commit(&alias, "removed"),
						mode,
						("domain alias remove", question, yes),
					)
				}
			}
		}
		DomainCli::Import { .. } => unreachable!("handled before the configuration is loaded"),
	}
}

/// `domain import`: read the configuration file without the state file, so
/// a state file that does not parse can be replaced, and copy its lists in.
fn import(path: &Path, mode: Mode, yes: bool) -> Outcome {
	let config = match Config::load_ignoring_domains_file(path) {
		Ok(config) => config,
		Err(error) => return Outcome::Error(error.to_string()),
	};
	let state_path = crate::domain::state::path(&config.data_dir);
	let question = format!(
		"Replace the hosted domains in {} with the configuration file's? [y/N]",
		state_path.display()
	);
	let mut yes = yes;
	let current = match crate::domain::state::DomainsFile::read(&state_path) {
		Ok(file) => file,
		Err(_) if mode.dry_run => None,
		Err(_) => {
			// A file that does not parse is replaced outright, once the
			// operator agreed: it is moved aside first, so nothing in it is
			// lost.
			if let Err(code) = prompt::confirm_destructive("domain import", &question, yes) {
				return code.into();
			}
			yes = true;
			let aside = state_path.with_extension("toml.bad");
			if let Err(error) = std::fs::rename(&state_path, &aside) {
				return Outcome::Error(format!("{}: {error}", state_path.display()));
			}
			super::style::warn(format_args!(
				"{} did not parse and was moved to {}",
				state_path.display(),
				aside.display()
			));
			if let Err(error) = crate::editable::seed::<crate::domain::state::DomainsFile>(&config)
			{
				return Outcome::Error(format!("{}: {error}", state_path.display()));
			}
			None
		}
	};
	let effective = match &current {
		Some(file) => config.with_domains_file(file),
		None => config.clone(),
	};
	confirmed(
		&effective,
		Change::Import,
		super::writers::Commit {
			subject: format!("domain state {}", state_path.display()),
			verb: "imported",
			already: "matches the configuration file",
			action: "import",
			fields: serde_json::json!({ "file": state_path.display().to_string() }),
			records_for: None,
		},
		mode,
		("domain import", question, yes),
	)
}
