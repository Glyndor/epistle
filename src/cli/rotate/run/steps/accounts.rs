//! The reset of every account's password and second factor.
//!
//! One step covers every dynamic account that holds a password or a TOTP
//! secret, and its store write is one atomic rewrite of `accounts.toml`.
//! Each account is recorded with the digest of the password hash it held
//! when the step was prepared, and is reset only while it still holds it:
//! after a cut, an account the earlier write reached, or one an
//! administrator gave a new password in between, is left alone.

use crate::config::Config;
use crate::directory_store::credential_reset::hash_digest;
use crate::directory_store::{AccountStore, DynamicAccount, ResetTarget};

use super::super::journal::{Intent, Kind, Step};

fn open(config: &Config) -> Result<AccountStore, String> {
	AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map_err(|error| format!("opening the account store: {error}"))
}

/// Whether a reset has anything to take from `account`.
fn holds_a_credential(account: &DynamicAccount) -> bool {
	!account.password_hash.is_empty() || account.totp_secret.is_some()
}

/// The dynamic accounts the reset covers, by name.
pub(in crate::cli::rotate) fn accounts(config: &Config) -> Result<Vec<String>, String> {
	Ok(open(config)?
		.dynamic_accounts()
		.into_iter()
		.filter(holds_a_credential)
		.map(|account| account.name)
		.collect())
}

/// What the reset cannot reach on this server, for the operator.
pub(in crate::cli::rotate) fn notes(config: &Config) -> Vec<String> {
	let mut notes: Vec<String> = config
		.accounts
		.iter()
		.filter(|account| account.password_hash.is_some())
		.map(|account| {
			format!(
				"the static account {} keeps its password: replace its `password_hash` in the \
				 configuration file",
				account.name
			)
		})
		.collect();
	if config
		.database
		.as_ref()
		.is_some_and(|database| database.directory)
	{
		notes.push(
			"the accounts of the SQL directory (`[database] directory`) keep their passwords: \
			 change them in that database"
				.to_string(),
		);
	}
	if config.ldap.is_some() {
		notes.push(
			"the accounts that sign in through `[ldap]` keep their passwords: change them in the \
			 directory server"
				.to_string(),
		);
	}
	notes
}

/// One step when any account holds a credential, and the notes.
pub(super) fn plan(config: &Config) -> Result<(Vec<Step>, Vec<String>), String> {
	let steps = if accounts(config)?.is_empty() {
		Vec::new()
	} else {
		vec![Step::pending(Kind::AccountReset, "", None)]
	};
	Ok((steps, notes(config)))
}

/// Record every account to reset with the digest of its password hash.
pub(super) fn prepare(config: &Config) -> Result<Intent, String> {
	let targets = open(config)?
		.dynamic_accounts()
		.into_iter()
		.filter(holds_a_credential)
		.map(|account| ResetTarget {
			digest: hash_digest(&account.password_hash),
			name: account.name,
		})
		.collect();
	Ok(Intent::Reset { targets })
}

/// Whether the write reached every account: none still holds the hash it
/// was recorded with.
pub(super) fn landed(config: &Config, targets: &[ResetTarget]) -> Result<bool, String> {
	let store = open(config)?;
	Ok(targets.iter().all(|target| {
		store
			.dynamic_account(&target.name)
			.is_none_or(|account| hash_digest(&account.password_hash) != target.digest)
	}))
}

/// Reset every recorded account that still holds its recorded hash. Its
/// password is replaced by the hash of a secret drawn here and thrown away.
pub(super) fn apply(config: &Config, intent: &Intent) -> Result<(), String> {
	let Intent::Reset { targets } = intent else {
		return Err("the journal records no account to reset".to_string());
	};
	let secret =
		crate::cli::generate_secret().ok_or("the system gave no random bytes for a secret")?;
	let placeholder = crate::smtp::auth::hash_password(&secret)
		.map_err(|error| format!("cannot hash the placeholder: {error}"))?;
	open(config)?
		.reset_credentials(targets, &placeholder)
		.map(drop)
		.map_err(|error| format!("resetting the accounts: {error}"))
}
