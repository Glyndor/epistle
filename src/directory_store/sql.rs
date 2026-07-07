//! SQL directory backend: load accounts from PostgreSQL into the in-memory
//! directory.
//!
//! The SQL backend is a third account source alongside the static config and
//! the dynamic `accounts.toml`. It is loaded into the [`AccountStore`] at
//! startup and refreshed periodically, never queried per authentication: SQL
//! stores argon2id hashes just like the local accounts, so once loaded, resolve
//! and authenticate stay synchronous against the in-memory directory. Only the
//! load is async.

use sqlx::PgPool;

/// A directory account sourced from SQL: name, its delivered addresses, and an
/// optional argon2id password hash (absent leaves the account receive-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlAccount {
	/// Account name; doubles as the mailbox directory name.
	pub name: String,
	/// Addresses delivered to this account.
	pub addresses: Vec<String>,
	/// argon2id PHC hash, or `None` for a receive-only account.
	pub password_hash: Option<String>,
}

/// Load every SQL directory account with its addresses, ready to merge into the
/// directory. Accounts with no addresses are still returned (they may exist as
/// receive-only placeholders); the caller decides how to merge.
pub async fn load_sql_accounts(pool: &PgPool) -> Result<Vec<SqlAccount>, sqlx::Error> {
	// One pass over accounts and one over addresses, joined in memory by name.
	// Both queries are bound-parameter-free and compile-time checked, so the
	// offline `.sqlx` cache covers them.
	let accounts = sqlx::query!("SELECT name, password_hash FROM directory_account ORDER BY name")
		.fetch_all(pool)
		.await?;
	let addresses =
		sqlx::query!("SELECT account, address FROM directory_address ORDER BY account, address")
			.fetch_all(pool)
			.await?;

	let mut by_name: std::collections::HashMap<String, SqlAccount> = accounts
		.into_iter()
		.map(|row| {
			(
				row.name.clone(),
				SqlAccount {
					name: row.name,
					addresses: Vec::new(),
					password_hash: row.password_hash,
				},
			)
		})
		.collect();
	for row in addresses {
		if let Some(account) = by_name.get_mut(&row.account) {
			account.addresses.push(row.address);
		}
	}

	// Stable ordering keeps the merge deterministic across reloads.
	let mut loaded: Vec<SqlAccount> = by_name.into_values().collect();
	loaded.sort_by(|a, b| a.name.cmp(&b.name));
	Ok(loaded)
}

#[cfg(test)]
#[path = "sql_tests.rs"]
mod tests;
