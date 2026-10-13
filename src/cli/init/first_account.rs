//! The first mail account `init` creates, and the role addresses that
//! point at it.
//!
//! RFC 5321 section 4.5.1 requires every domain to accept mail for
//! `postmaster@`, and RFC 2142 names `abuse@`. A fresh install had neither:
//! the package and `init` created no mailbox at all. The wizard now asks
//! for one account after the domains, and an answers file may carry the
//! same as `[first_account]`, with the password read from a file or from
//! stdin, never written inline. With `role_aliases` (the default)
//! `postmaster@` and `abuse@` of every configured domain become aliases of
//! that account. All of it is optional.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::apply::{ApplyError, Report, ReportStep};
use crate::cli::config_edit::ConfigDocument;
use crate::config::Config;
use crate::directory_store::{AccountStore, DynamicAccount};

/// The role local parts pointed at the first account, in the order they
/// are listed.
const ROLES: [&str; 2] = ["postmaster", "abuse"];

/// `[first_account]` in an answers file, or what the wizard asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstAccount {
	/// The account's address, in one of the configured domains. Its local
	/// part is the account name.
	pub address: String,
	/// The name shown as the sender, such as `Alice Liddell`.
	#[serde(default)]
	pub display_name: Option<String>,
	/// Answers file only: a file whose first line is the password, or `-`
	/// to read it from stdin. A password is never written in the answers
	/// file itself.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub password_file: Option<PathBuf>,
	/// Point `postmaster@` and `abuse@` of every configured domain at the
	/// account. Defaults to true.
	#[serde(default = "default_true")]
	pub role_aliases: bool,
}

const fn default_true() -> bool {
	true
}

/// The first account's password, kept out of every `Debug` print.
pub struct Password(String);

impl Password {
	/// Wrap a password that passed the policy.
	pub fn new(value: String) -> Self {
		Password(value)
	}

	/// The password itself, for hashing.
	pub fn expose(&self) -> &str {
		&self.0
	}
}

impl fmt::Debug for Password {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("Password(<redacted>)")
	}
}

impl FirstAccount {
	/// The address as it is stored: lowercase.
	pub fn stored_address(&self) -> String {
		self.address.trim().to_ascii_lowercase()
	}

	/// The account name: the local part of the address.
	pub fn name(&self) -> String {
		let address = self.stored_address();
		address
			.split_once('@')
			.map_or(address.clone(), |(local, _)| local.to_string())
	}

	/// Whether the address, the name it gives and the display name are
	/// acceptable for an install serving `domains`. The reason is the
	/// operator-facing text.
	pub fn check(&self, domains: &[String]) -> Result<(), String> {
		let address = self.stored_address();
		let Some((local, domain)) = address.split_once('@') else {
			return Err(format!("{:?} is not a mail address", self.address));
		};
		if local.is_empty() || domain.is_empty() {
			return Err(format!("{:?} is not a mail address", self.address));
		}
		if !domains
			.iter()
			.any(|served| served.eq_ignore_ascii_case(domain))
		{
			return Err(format!(
				"{domain} is not one of the configured domains ({})",
				domains.join(", ")
			));
		}
		let usable = local.len() <= 64
			&& !local.starts_with('-')
			&& local
				.chars()
				.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
		if !usable {
			return Err(format!(
				"the account name is the part before @, and {local:?} must be lowercase letters, digits and hyphens"
			));
		}
		if let Some(raw) = &self.display_name {
			crate::directory_store::display_name::validate(raw)
				.map_err(|why| format!("display_name: {why}"))?;
		}
		Ok(())
	}

	/// The role addresses that become aliases of this account: none when
	/// `role_aliases` is off, and never the account's own address.
	pub fn role_addresses(&self, domains: &[String]) -> Vec<String> {
		if !self.role_aliases {
			return Vec::new();
		}
		let own = self.stored_address();
		domains
			.iter()
			.flat_map(|domain| {
				ROLES
					.iter()
					.map(move |role| format!("{role}@{}", domain.to_ascii_lowercase()))
			})
			.filter(|address| *address != own)
			.collect()
	}
}

/// The password named by `password_file`: its first line, or one line from
/// stdin for `-`, checked against the password policy.
pub(super) fn read_password(first: &FirstAccount) -> Result<Password, String> {
	use crate::cli::prompt::{self, Secret};
	let Some(path) = &first.password_file else {
		return Err(
			"password_file is required: a file whose first line is the password, or \"-\" for stdin"
				.to_string(),
		);
	};
	let value = if path.as_os_str() == "-" {
		match prompt::secret_line("password", &mut prompt::stdin()) {
			Secret::Read(value) => value,
			Secret::Eof | Secret::Blank => return Err("no password on stdin".to_string()),
			Secret::Mismatch => return Err(prompt::MISMATCH.to_string()),
			Secret::Failed(why) => return Err(format!("reading stdin: {why}")),
		}
	} else {
		let text = std::fs::read_to_string(path)
			.map_err(|error| format!("reading {}: {error}", path.display()))?;
		text.lines().next().unwrap_or_default().to_string()
	};
	crate::password::validate(&value).map_err(|rejection| rejection.message().to_string())?;
	Ok(Password::new(value))
}

/// Create the account and its role aliases once the configuration is
/// written. An account that already exists is left as it is.
pub(super) fn create(
	first: &FirstAccount,
	password: &Password,
	config_path: &Path,
	report: &mut Report,
) -> Result<(), ApplyError> {
	let fail = |why: String| ApplyError::FirstAccount(why);
	let config = Config::load(config_path).map_err(|error| fail(error.to_string()))?;
	let store = AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map_err(|error| fail(format!("opening the account store: {error}")))?;
	let name = first.name();
	let address = first.stored_address();
	if store.dynamic(&name).is_some() || config.accounts.iter().any(|a| a.name == name) {
		report.steps.push(ReportStep::Skipped {
			name: format!("account {name}"),
			reason: "it already exists".to_string(),
		});
	} else {
		let account = DynamicAccount::with_password(
			name.clone(),
			vec![address.clone()],
			password.expose(),
			config.auth.scram,
		)
		.map_err(|error| fail(error.to_string()))?;
		let display_name = first
			.display_name
			.as_deref()
			.map(crate::directory_store::display_name::validate)
			.transpose()
			.map_err(|why| fail(why.to_string()))?
			.flatten();
		store
			.add(DynamicAccount {
				display_name,
				..account
			})
			.map_err(|error| fail(error.to_string()))?;
		report.steps.push(ReportStep::AccountCreated {
			name,
			address: address.clone(),
		});
	}
	add_role_aliases(first, &config, config_path, &address, report)
}

/// Add each role address as an `[[alias]]` table delivering to `target`,
/// through the same validated, atomic edit `epistle alias add` uses. A role
/// address that is already an alias or some account's address is left alone.
fn add_role_aliases(
	first: &FirstAccount,
	config: &Config,
	config_path: &Path,
	target: &str,
	report: &mut Report,
) -> Result<(), ApplyError> {
	let fail = |why: String| ApplyError::FirstAccount(why);
	let taken: Vec<String> = config
		.alias
		.iter()
		.map(|alias| alias.address.to_ascii_lowercase())
		.chain(
			config
				.accounts
				.iter()
				.flat_map(|account| account.addresses.iter().map(|a| a.to_ascii_lowercase())),
		)
		.collect();
	let roles: Vec<String> = first
		.role_addresses(&config.domains)
		.into_iter()
		.filter(|role| !taken.contains(role))
		.collect();
	if roles.is_empty() {
		return Ok(());
	}
	let mut document = ConfigDocument::open(config_path).map_err(fail)?;
	for role in &roles {
		let mut members = toml_edit::Array::new();
		members.push(target);
		document
			.upsert_element(
				"alias",
				"address",
				role,
				&[("members", toml_edit::Value::Array(members))],
			)
			.map_err(fail)?;
	}
	document.commit().map_err(fail)?;
	for role in roles {
		report.steps.push(ReportStep::AliasAdded {
			address: role,
			target: target.to_string(),
		});
	}
	Ok(())
}

#[cfg(test)]
#[path = "first_account_tests.rs"]
mod tests;
