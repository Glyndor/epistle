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
use crate::util::account_rule;
use crate::util::address::normalize;

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
	/// The address as it is stored: lowercase, with the domain in the form the
	/// rest of the system keeps (`bücher.example` is `xn--bcher-kva.example`).
	/// A domain that cannot be normalised stays as typed, in lowercase, and
	/// [`FirstAccount::check`] refuses it for not being a configured one.
	pub fn stored_address(&self) -> String {
		normalize(&self.address)
	}

	/// The account name the address gives: its local part in lowercase,
	/// dots turned into hyphens (`torre.control` is `torre-control`). When
	/// the local part cannot give a name, [`FirstAccount::check`] refuses
	/// the address, and this is the plain lowercase local part.
	pub fn name(&self) -> String {
		let address = self.stored_address();
		let local = address
			.split_once('@')
			.map_or(address.as_str(), |(local, _)| local);
		account_rule::derive(local).unwrap_or_else(|_| local.to_string())
	}

	/// A line telling the operator which name was chosen and what was done
	/// to the typed local part to get it (dots to hyphens, capitals to
	/// lowercase); `None` when the name is the local part as typed.
	pub fn name_note(&self) -> Option<String> {
		let typed = self
			.address
			.trim()
			.split_once('@')
			.map(|(local, _)| local)?;
		let name = self.name();
		if name == typed {
			return None;
		}
		let mut changes = Vec::new();
		if typed.contains('.') {
			changes.push("dots become hyphens");
		}
		if typed.chars().any(|c| c.is_ascii_uppercase()) {
			changes.push("capital letters become lowercase");
		}
		Some(format!(
			"the account name will be \"{name}\" ({})",
			changes.join(" and ")
		))
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
		// The domain is compared in the form the server stores, with the
		// same normalisation the answers validator applies to the domains
		// it serves: a domain that normaliser refuses is refused here too,
		// instead of matching a served one by an insensitive comparison.
		let served = match crate::domain::normalize(domain) {
			Ok(stored) => stored,
			Err(why) => {
				let reason = match why {
					crate::domain::DomainError::Invalid => {
						crate::util::address_reason::domain_reason(domain)
					}
					crate::domain::DomainError::Confusable => {
						"it is confusable with another name".to_string()
					}
				};
				return Err(format!("{domain:?} is not a valid mail domain: {reason}"));
			}
		};
		if !domains.iter().any(|configured| {
			crate::domain::normalize(configured).is_ok_and(|stored| stored == served)
		}) {
			return Err(format!(
				"{domain} is not one of the configured domains ({})",
				domains.join(", ")
			));
		}
		account_rule::derive(local).map_err(|fault| {
			let converted = match fault {
				account_rule::Fault::BadChar(_) => {
					" (ASCII capital letters are converted on their own)"
				}
				_ => "",
			};
			format!("{local:?} cannot give an account name: {fault}{converted}")
		})?;
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
					.map(move |role| normalize(&format!("{role}@{domain}")))
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
		// The operator names this file for this one read, and a pipe from a
		// secret manager (`<(pass show mail)`) is a way to give it, so unlike
		// the configuration files below it is read as it comes.
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
	let exists =
		name_is_free_or_ours(&name, &address, &store, &static_pairs(&config)).map_err(fail)?;
	if exists {
		report.steps.push(ReportStep::Skipped {
			name: format!("account {name}"),
			reason: "it already exists".to_string(),
		});
	} else {
		let account = DynamicAccount::with_password(
			name.clone(),
			vec![address.clone()],
			password.expose(),
			&crate::password::Policy::from_config(&config.auth),
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
	add_role_aliases(first, &config, config_path, &address, &store, report)
}

/// Whether the account named `name` already exists and is the one `address`
/// asks for (`Ok(true)`), does not exist (`Ok(false)`), or exists under other
/// addresses (an error: the collision).
fn name_is_free_or_ours(
	name: &str,
	address: &str,
	store: &AccountStore,
	static_accounts: &[(String, Vec<String>)],
) -> Result<bool, String> {
	let holder: Option<Vec<String>> = store
		.dynamic(name)
		.map(|existing| existing.addresses)
		.or_else(|| {
			static_accounts
				.iter()
				.find(|(static_name, _)| static_name == name)
				.map(|(_, addresses)| addresses.clone())
		});
	match holder {
		Some(holder) => name_holder(name, address, &holder),
		None => Ok(false),
	}
}

/// Whether the address is free for the account `owner`: no alias, masked
/// address or other account holds it, compared in the form the system stores.
/// The account `owner` itself may already hold it, which is a re-run; with
/// no owner the address must be free of every account.
fn address_is_free_or_ours(
	owner: Option<&str>,
	address: &str,
	store: &AccountStore,
	static_accounts: &[(String, Vec<String>)],
	aliases: &[String],
) -> Result<(), String> {
	let wanted = normalize(address);
	if aliases.iter().any(|existing| normalize(existing) == wanted) {
		return Err(format!(
			"the address {address} is already used by an alias; use another address"
		));
	}
	if store
		.masked_handle()
		.read()
		.expect("masked lock")
		.get(address)
		.is_some()
	{
		return Err(format!(
			"the address {address} is already used by a masked address; use another address"
		));
	}
	let dynamic_owner = store
		.dynamic_accounts()
		.into_iter()
		.find(|account| {
			Some(account.name.as_str()) != owner
				&& account
					.addresses
					.iter()
					.any(|existing| normalize(existing) == wanted)
		})
		.map(|account| account.name);
	let static_owner = static_accounts.iter().find_map(|(holder, addresses)| {
		if Some(holder.as_str()) != owner
			&& addresses
				.iter()
				.any(|existing| normalize(existing) == wanted)
		{
			Some(holder.clone())
		} else {
			None
		}
	});
	if let Some(holder) = dynamic_owner.or(static_owner) {
		return Err(format!(
			"the address {address} is already used by the account \"{holder}\"; use another address"
		));
	}
	Ok(())
}

/// The `[[accounts]]` of a configuration file as name and addresses, read
/// from the raw TOML so a file the full loader refuses still counts.
fn static_accounts_of(config_path: &Path) -> Vec<(String, Vec<String>)> {
	let Ok(text) = crate::cli::regular::read::read_to_string(config_path) else {
		return Vec::new();
	};
	let Ok(table) = text.parse::<toml::Table>() else {
		return Vec::new();
	};
	let Some(accounts) = table.get("accounts").and_then(|v| v.as_array()) else {
		return Vec::new();
	};
	accounts
		.iter()
		.filter_map(|entry| {
			let name = entry.get("name")?.as_str()?.to_string();
			let addresses = entry
				.get("addresses")
				.and_then(|v| v.as_array())
				.map(|list| {
					list.iter()
						.filter_map(|a| a.as_str().map(str::to_string))
						.collect()
				})
				.unwrap_or_default();
			Some((name, addresses))
		})
		.collect()
}

/// The addresses of the `[[alias]]` entries of a configuration file, read from
/// the raw TOML so a file the full loader refuses still counts.
fn static_aliases_of(config_path: &Path) -> Vec<String> {
	let Ok(text) = crate::cli::regular::read::read_to_string(config_path) else {
		return Vec::new();
	};
	let Ok(table) = text.parse::<toml::Table>() else {
		return Vec::new();
	};
	table
		.get("alias")
		.and_then(|value| value.as_array())
		.into_iter()
		.flatten()
		.filter_map(|entry| entry.get("address")?.as_str().map(str::to_string))
		.collect()
}

/// The collision check that needs no write: with a configuration already on
/// disk, whether an account other than the one asked for holds the derived
/// name, or whether another account, an alias or a masked address holds the
/// address. Run before anything is applied, so a clash stops the run (and
/// `--dry-run`) with nothing written, and the assistant can ask again.
pub(super) fn precheck(
	first: &FirstAccount,
	data_dir: &Path,
	config_path: &Path,
) -> Result<(), String> {
	// The store is opened from `data_dir` whether or not the configuration
	// exists or loads: a lost or unreadable config must not hide the
	// accounts already on disk. A config that loads gives its accounts
	// normalised and with `${VAR}` expanded; the raw file is only the
	// fallback when it does not load.
	let (domain_aliases, statics, aliases) = match Config::load(config_path) {
		Ok(config) => (
			config.domain_aliases.clone(),
			static_pairs(&config),
			config
				.alias
				.iter()
				.map(|alias| alias.address.clone())
				.collect(),
		),
		Err(_) => (
			Default::default(),
			static_accounts_of(config_path),
			static_aliases_of(config_path),
		),
	};
	let store = AccountStore::open(data_dir, Vec::new(), domain_aliases, Vec::new())
		.map_err(|error| format!("opening the account store: {error}"))?;
	let name = first.name();
	let address = first.stored_address();
	name_is_free_or_ours(&name, &address, &store, &statics)?;
	address_is_free_or_ours(Some(&name), &address, &store, &statics, &aliases)
}

/// The static accounts of a loaded configuration as name and addresses.
fn static_pairs(config: &Config) -> Vec<(String, Vec<String>)> {
	config
		.accounts
		.iter()
		.map(|account| (account.name.clone(), account.addresses.clone()))
		.collect()
}

/// Whether the account already named `name` is the one `address` asks for.
/// An account with that name but other addresses is a collision, such as
/// `torre.control` and `torre-control` both giving `torre-control`: it is
/// refused instead of being skipped as if it were the same account.
fn name_holder(name: &str, address: &str, holder_addresses: &[String]) -> Result<bool, String> {
	let wanted = normalize(address);
	if holder_addresses
		.iter()
		.any(|existing| normalize(existing) == wanted)
	{
		return Ok(true);
	}
	Err(format!(
		"the account name \"{name}\" is already used by the account with the address {}, \
		 and {address} would get the same name; use another address",
		holder_addresses.join(", ")
	))
}

/// Add each role address as an `[[alias]]` table delivering to `target`,
/// through the same validated, atomic edit `epistle alias add` uses. A role
/// address that anything already holds is left alone: an alias, a masked
/// address, or the address of a dynamic or static account.
fn add_role_aliases(
	first: &FirstAccount,
	config: &Config,
	config_path: &Path,
	target: &str,
	store: &AccountStore,
	report: &mut Report,
) -> Result<(), ApplyError> {
	let fail = |why: String| ApplyError::FirstAccount(why);
	let statics = static_pairs(config);
	let aliases: Vec<String> = config
		.alias
		.iter()
		.map(|alias| alias.address.clone())
		.collect();
	let roles: Vec<String> = first
		.role_addresses(&config.domains)
		.into_iter()
		// A role address that is taken is left alone, so init never writes
		// an alias on top of an address that already delivers somewhere.
		.filter(|role| address_is_free_or_ours(None, role, store, &statics, &aliases).is_ok())
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
mod tests;
