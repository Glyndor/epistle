//! Per-account app passwords: secondary mail credentials for IMAP/SMTP.
//!
//! An app password lets a client authenticate to a mail account without the
//! primary password — handy for a device whose secret you may want to revoke in
//! isolation. Each carries a human `label`, an argon2id PHC hash of the secret
//! (never the secret itself), an optional `expires_at` (epoch seconds) and an
//! optional single-CIDR `ip_cidr` allowlist. They persist to
//! `<data_dir>/app_passwords.toml`, mirroring how dynamic accounts persist in
//! [`super`].
//!
//! Verification is fail-closed: an app password authenticates only when the
//! argon2id hash verifies AND it is unexpired AND (no `ip_cidr`, or the client
//! IP is inside it). Anything malformed or missing is a rejection, never an
//! allow.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::StoreError;

/// One app password as persisted in `app_passwords.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPassword {
	/// Human-readable label identifying the credential (e.g. "iphone").
	pub label: String,
	/// argon2id PHC hash of the secret. The secret is shown once at creation.
	pub hash: String,
	/// Expiry as epoch seconds; `None` never expires.
	#[serde(default)]
	pub expires_at: Option<u64>,
	/// Single-CIDR allowlist (`203.0.113.0/24` or a bare IP); `None` allows any.
	#[serde(default)]
	pub ip_cidr: Option<String>,
}

impl AppPassword {
	/// Whether this app password admits `password` from `client_ip` at `now`
	/// (epoch seconds). Fail-closed on every branch: a malformed CIDR rejects;
	/// a CIDR with no client IP rejects (we cannot prove the IP is permitted).
	/// The argon2id verification runs first and unconditionally so the
	/// expiry/IP checks do not become a faster-rejection timing oracle.
	pub fn admits(&self, password: &str, client_ip: Option<IpAddr>, now: u64) -> bool {
		let hash_ok = crate::smtp::auth::verify_password(&self.hash, password);
		let time_ok = self.expires_at.is_none_or(|expiry| now < expiry);
		let ip_ok = match &self.ip_cidr {
			None => true,
			Some(spec) => match (crate::cidr::Cidr::parse(spec), client_ip) {
				(Some(cidr), Some(ip)) => cidr.contains(ip),
				// A configured allowlist with an unparseable spec or an unknown
				// client IP cannot be satisfied: reject.
				_ => false,
			},
		};
		hash_ok && time_ok && ip_ok
	}
}

/// The TOML document: account name → its app passwords.
#[derive(Debug, Default, Serialize, Deserialize)]
struct AppPasswordFile {
	/// `[accounts.<name>]` tables, each a list under `passwords`.
	#[serde(default)]
	accounts: HashMap<String, AccountEntry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AccountEntry {
	#[serde(default)]
	passwords: Vec<AppPassword>,
}

/// Filesystem-backed store of per-account app passwords.
pub struct AppPasswordStore {
	path: PathBuf,
	accounts: HashMap<String, Vec<AppPassword>>,
}

impl AppPasswordStore {
	/// Open (loading if present) the store under `data_dir`. A missing file is
	/// an empty store.
	pub fn open(data_dir: &Path) -> Result<Self, StoreError> {
		let path = data_dir.join("app_passwords.toml");
		let file: AppPasswordFile = match std::fs::read_to_string(&path) {
			Ok(text) => {
				toml::from_str(&text).map_err(|error| StoreError::Invalid(error.to_string()))?
			}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
				AppPasswordFile::default()
			}
			Err(error) => return Err(error.into()),
		};
		let accounts = file
			.accounts
			.into_iter()
			.map(|(name, entry)| (name.to_ascii_lowercase(), entry.passwords))
			.collect();
		Ok(AppPasswordStore { path, accounts })
	}

	/// The app passwords for one account (lowercased lookup), or an empty slice.
	pub fn for_account(&self, account: &str) -> &[AppPassword] {
		self.accounts
			.get(&account.to_ascii_lowercase())
			.map(Vec::as_slice)
			.unwrap_or(&[])
	}

	/// Every `(account, app_password)` pair, for attaching to the directory.
	pub fn entries(&self) -> impl Iterator<Item = (String, AppPassword)> + '_ {
		self.accounts.iter().flat_map(|(account, passwords)| {
			passwords
				.iter()
				.map(move |password| (account.clone(), password.clone()))
		})
	}

	/// Add an app password for an account (the account is lowercased). The hash
	/// must already be argon2id; the caller generated and showed the secret.
	pub fn add(&mut self, account: &str, password: AppPassword) -> Result<(), StoreError> {
		if let Some(spec) = &password.ip_cidr
			&& crate::cidr::Cidr::parse(spec).is_none()
		{
			return Err(StoreError::Invalid(format!("invalid CIDR \"{spec}\"")));
		}
		let account = account.to_ascii_lowercase();
		let list = self.accounts.entry(account).or_default();
		if list.iter().any(|existing| existing.label == password.label) {
			return Err(StoreError::Duplicate(password.label));
		}
		list.push(password);
		self.persist()
	}

	/// Remove an account's app password by label. `NotFound` if absent.
	pub fn remove(&mut self, account: &str, label: &str) -> Result<(), StoreError> {
		let account = account.to_ascii_lowercase();
		let list = self
			.accounts
			.get_mut(&account)
			.ok_or_else(|| StoreError::NotFound(format!("{account}/{label}")))?;
		let before = list.len();
		list.retain(|existing| existing.label != label);
		if list.len() == before {
			return Err(StoreError::NotFound(format!("{account}/{label}")));
		}
		if list.is_empty() {
			self.accounts.remove(&account);
		}
		self.persist()
	}

	/// Every `(account, label, expires_at, ip_cidr)` for listing. Secrets and
	/// hashes are never exposed.
	pub fn list(&self) -> Vec<(String, String, Option<u64>, Option<String>)> {
		let mut rows: Vec<_> = self
			.accounts
			.iter()
			.flat_map(|(account, passwords)| {
				passwords.iter().map(move |password| {
					(
						account.clone(),
						password.label.clone(),
						password.expires_at,
						password.ip_cidr.clone(),
					)
				})
			})
			.collect();
		rows.sort();
		rows
	}

	/// Atomically rewrite the backing file (write-temp-then-rename).
	fn persist(&self) -> Result<(), StoreError> {
		let file = AppPasswordFile {
			accounts: self
				.accounts
				.iter()
				.map(|(name, passwords)| {
					(
						name.clone(),
						AccountEntry {
							passwords: passwords.clone(),
						},
					)
				})
				.collect(),
		};
		let text = toml::to_string_pretty(&file)
			.map_err(|error| StoreError::Invalid(error.to_string()))?;
		let tmp = self.path.with_extension("toml.tmp");
		std::fs::write(&tmp, text)?;
		std::fs::rename(&tmp, &self.path)?;
		Ok(())
	}
}

#[cfg(test)]
#[path = "app_passwords_tests.rs"]
mod tests;
