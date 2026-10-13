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
/// LDAP first, SQL next, then static config, then dynamic, so static
/// config and dynamic accounts take precedence over the external
/// directories (the directory's maps keep the last writer). Between
/// static and dynamic accounts the first claim of an address wins (static
/// before dynamic, file order within each): a later claim stays on disk
/// and is reported by `AccountStore::address_collisions`.
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
		.chain(first_claims(static_accounts, dynamic))
		.collect()
}

/// Static then dynamic `(address, account)` pairs, keeping only the first
/// claim of each address in its stored form.
fn first_claims<'a>(
	static_accounts: &'a [Account],
	dynamic: &'a [DynamicAccount],
) -> impl Iterator<Item = (String, String)> + 'a {
	let mut seen = HashSet::new();
	static_accounts
		.iter()
		.map(|account| (&account.addresses, &account.name))
		.chain(
			dynamic
				.iter()
				.map(|account| (&account.addresses, &account.name)),
		)
		.flat_map(|(addresses, name)| addresses.iter().map(move |a| (a.clone(), name.clone())))
		.filter(move |(address, _)| seen.insert(crate::util::address::normalize(address)))
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
/// disabled), opened with `crypto` when they are stored sealed.
pub(super) fn totp(
	dynamic: &[DynamicAccount],
	crypto: &crate::storage::MessageCrypto,
) -> Vec<(String, String)> {
	dynamic
		.iter()
		.filter_map(|account| {
			account
				.totp_secret
				.as_deref()
				.map(|stored| (account.name.clone(), super::set_totp::open(crypto, stored)))
		})
		.collect()
}

/// Per-account storage quota (bytes) for every dynamic account that
/// carries one. `None` is omitted so the rebuilt directory falls back to
/// the domain quota and the server default, the same chain
/// `Account::quota_bytes = None` already takes in `Directory::quota_for`.
pub(super) fn quota_bytes(dynamic: &[DynamicAccount]) -> Vec<(String, u64)> {
	dynamic
		.iter()
		.filter_map(|account| {
			account
				.quota_bytes
				.map(|bytes| (account.name.clone(), bytes))
		})
		.collect()
}

/// Per-account `save_sent` preference for every dynamic account that
/// carries an explicit override (`Some(true)` or `Some(false)`).
/// Accounts with `save_sent = None` (the default and the value on
/// `accounts.toml` files written before the field existed) are
/// omitted, so the rebuilt directory resolves them as "no preference"
/// and the saver treats that as "on".
pub(super) fn save_sent(dynamic: &[DynamicAccount]) -> Vec<(String, bool)> {
	dynamic
		.iter()
		.filter_map(|account| {
			account
				.save_sent
				.map(|value| (account.name.clone(), value))
		})
		.collect()
}

/// Catch-all domain to account pairs: static accounts first, then dynamic
/// ones. Both stores refuse a domain another account already catches, so
/// no pair overwrites another in the directory's map.
pub(super) fn catch_all<'a>(
	static_accounts: &'a [Account],
	dynamic: &'a [DynamicAccount],
) -> impl Iterator<Item = (String, String)> + 'a {
	let pairs = |name: &'a str, domains: &'a [String]| {
		domains
			.iter()
			.map(move |domain| (domain.clone(), name.to_string()))
	};
	static_accounts
		.iter()
		.flat_map(move |account| pairs(&account.name, &account.catch_all))
		.chain(
			dynamic
				.iter()
				.flat_map(move |account| pairs(&account.name, &account.catch_all)),
		)
}

/// Account to (forward targets, keep a local copy) for every account that
/// forwards. A dynamic account always keeps its local copy: the store has
/// no switch for pure forwarding.
pub(super) fn forwards<'a>(
	static_accounts: &'a [Account],
	dynamic: &'a [DynamicAccount],
) -> impl Iterator<Item = (String, (Vec<String>, bool))> + 'a {
	static_accounts
		.iter()
		.filter(|account| !account.forward.is_empty())
		.map(|account| {
			(
				account.name.clone(),
				(account.forward.clone(), account.forward_keep_local),
			)
		})
		.chain(
			dynamic
				.iter()
				.filter(|account| !account.forward.is_empty())
				.map(|account| (account.name.clone(), (account.forward.clone(), true))),
		)
}
