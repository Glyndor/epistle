//! Builder helpers for [`super::AccountStore::build_directory`].
//!
//! Split into a sibling module so `mod.rs` stays under the per-file
//! code-line budget. Every helper is a free function on borrowed
//! slices — the lifetime annotation is `'a` for both inputs and the
//! returned iterator, which keeps the call site (`build_directory`)
//! one-line and avoids re-allocating an intermediate `Vec` only to
//! re-iterate it into a builder.
//!
//! The precedence on a name collision (static > dynamic > SQL > LDAP)
//! is the same convention `AccountStore::build_directory` already
//! uses for the address map and the password-hash map: later chains
//! overwrite earlier ones, because the directory's `HashMap` keeps
//! the last writer.

use std::collections::HashSet;

use crate::config::{Account, Protocol};
use crate::smtp::scram::ScramStored;

use super::{DynamicAccount, LdapAccount, SqlAccount};

/// `(address, account)` pairs for every account across all sources.
/// LDAP first, SQL next, then static config, then dynamic — so static
/// config and dynamic accounts take precedence on a name or address
/// collision (the directory's maps keep the last writer).
pub(super) fn address_accounts<'a>(
	ldap: &'a [LdapAccount],
	sql: &'a [SqlAccount],
	static_accounts: &'a [Account],
	dynamic: &'a [DynamicAccount],
) -> Vec<(String, String)> {
	ldap.iter()
		.flat_map(|account| {
			account
				.addresses
				.iter()
				.map(|address| (address.clone(), account.name.clone()))
		})
		.chain(sql.iter().flat_map(|account| {
			account
				.addresses
				.iter()
				.map(|address| (address.clone(), account.name.clone()))
		}))
		.chain(static_accounts.iter().flat_map(|account| {
			account
				.addresses
				.iter()
				.map(|address| (address.clone(), account.name.clone()))
		}))
		.chain(dynamic.iter().flat_map(|account| {
			account
				.addresses
				.iter()
				.map(|address| (address.clone(), account.name.clone()))
		}))
		.collect()
}

/// `(account, hash)` pairs for every account with a stored argon2id
/// password hash. The dynamic row wins on a name collision: the
/// dynamic chain runs last and overwrites whatever the static or SQL
/// chain wrote.
pub(super) fn password_hashes<'a>(
	sql: &'a [SqlAccount],
	static_accounts: &'a [Account],
	dynamic: &'a [DynamicAccount],
) -> Vec<(String, String)> {
	sql.iter()
		.filter_map(|account| {
			account
				.password_hash
				.as_ref()
				.map(|hash| (account.name.clone(), hash.clone()))
		})
		.chain(static_accounts.iter().filter_map(|account| {
			account
				.password_hash
				.as_ref()
				.map(|hash| (account.name.clone(), hash.clone()))
		}))
		.chain(
			dynamic
				.iter()
				.map(|account| (account.name.clone(), account.password_hash.clone())),
		)
		.collect()
}

/// Per-account protocol allowlist. Absent entries are "every protocol
/// authenticates" — the default for accounts that never opted into
/// the restriction.
pub(super) fn allowed_protocols<'a>(
	static_accounts: &'a [Account],
	dynamic: &'a [DynamicAccount],
) -> impl Iterator<Item = (String, Vec<Protocol>)> + 'a {
	static_accounts
		.iter()
		.filter_map(|account| {
			account
				.allowed_protocols
				.as_ref()
				.map(|set| (account.name.clone(), set.clone()))
		})
		.chain(dynamic.iter().filter_map(|account| {
			account
				.allowed_protocols
				.as_ref()
				.map(|set| (account.name.clone(), set.clone()))
		}))
}

/// Names of administratively-disabled accounts (set rebuilt on every
/// directory swap; see `authenticate_local` for the rejection path).
pub(super) fn disabled(dynamic: &[DynamicAccount]) -> HashSet<String> {
	dynamic
		.iter()
		.filter(|account| account.disabled)
		.map(|account| account.name.clone())
		.collect()
}

/// SCRAM-SHA-256 credentials per dynamic account (only dynamic
/// accounts carry SCRAM — derived from the plaintext password at
/// set time).
pub(super) fn scram(dynamic: &[DynamicAccount]) -> Vec<(String, ScramStored)> {
	dynamic
		.iter()
		.filter_map(|account| {
			account
				.scram
				.clone()
				.map(|stored| (account.name.clone(), stored))
		})
		.collect()
}

/// TOTP secrets per dynamic account (RFC 6238; `None` leaves 2FA
/// disabled).
pub(super) fn totp(dynamic: &[DynamicAccount]) -> Vec<(String, String)> {
	dynamic
		.iter()
		.filter_map(|account| {
			account
				.totp_secret
				.clone()
				.map(|secret| (account.name.clone(), secret))
		})
		.collect()
}
