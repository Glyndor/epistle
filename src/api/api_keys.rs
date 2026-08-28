//! Labeled bearer API keys for the management API.
//!
//! Alongside the single configured bearer token (held by the API state, a
//! private module), an
//! operator may issue any number of labeled API keys. Each carries a `label`,
//! the SHA-256 hash of the key (the same `sha256:<hex>` form the configured
//! token uses), an optional `expires_at` (epoch seconds) and an optional
//! single-CIDR `ip_cidr` allowlist. Keys persist to `<data_dir>/api_keys.toml`.
//!
//! A request authenticates if the configured token matches OR any non-expired,
//! IP-permitted key's hash matches. Verification is fail-closed: an expired
//! key, an IP outside the allowlist, a malformed CIDR, or a missing client IP
//! where a CIDR is set all reject.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Permissions a key may carry. The set is intentionally small — one per
/// damage class — so an operator can read at a glance what a leaked key would
/// let through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
	/// Read-only views (status, domains, accounts list, mailboxes, queue list,
	/// suppression list, auth/verify, JMAP reads, JMAP `/download`).
	Read,
	/// State mutation that does not originate outbound mail: account
	/// create/delete/password/TOTP, queue and suppression delete, JMAP
	/// `/set` on mailbox/email/push-subscription, JMAP `/upload`.
	Write,
	/// Outbound mail submission: `POST /api/v1/send`, JMAP `EmailSubmission/set`.
	Send,
}

/// Error returned when the [`std::str::FromStr`] impl for [`Scope`] is
/// handed a value that is not one of the canonical `read`/`write`/`send`
/// strings. Carries the offending value so a caller can format a context-aware
/// message; nobody needs to construct one outside of this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownScopeError(String);

impl std::fmt::Display for UnknownScopeError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(formatter, "unknown scope \"{}\"", self.0)
	}
}

impl std::error::Error for UnknownScopeError {}

impl std::str::FromStr for Scope {
	type Err = UnknownScopeError;

	/// Parse the canonical form (`read`, `write`, `send`). Unknown values are
	/// rejected — the store refuses to load an `api_keys.toml` containing a
	/// typo, and the CLI rejects `--scope` values it does not recognise.
	fn from_str(value: &str) -> Result<Self, Self::Err> {
		match value {
			"read" => Ok(Scope::Read),
			"write" => Ok(Scope::Write),
			"send" => Ok(Scope::Send),
			_ => Err(UnknownScopeError(value.to_string())),
		}
	}
}

impl Scope {
	/// Canonical serialised form (`read`, `write`, `send`) used in
	/// `api_keys.toml` and in the `ApiKey.scopes` vector.
	pub fn as_str(self) -> &'static str {
		match self {
			Scope::Read => "read",
			Scope::Write => "write",
			Scope::Send => "send",
		}
	}
}

/// One API key as persisted in `api_keys.toml`. The plaintext key is shown once
/// at creation and never stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
	/// Human-readable label identifying the key.
	pub label: String,
	/// `sha256:<lowercase-hex>` digest of the key.
	pub hash: String,
	/// Expiry as epoch seconds; `None` never expires.
	#[serde(default)]
	pub expires_at: Option<u64>,
	/// Single-CIDR allowlist; `None` allows any client IP.
	#[serde(default)]
	pub ip_cidr: Option<String>,
	/// Permissions granted to this key. Absent (legacy) = all scopes, with a
	/// one-time startup warning per key. New keys added through the store are
	/// required to declare at least one scope.
	#[serde(default)]
	pub scopes: Vec<String>,
}

impl ApiKey {
	/// Whether this key admits `presented` from `client_ip` at `now` (epoch
	/// seconds), and whether it carries at least one of `acceptable_scopes`.
	/// Fail-closed on every branch.
	///
	/// A key with no `scopes` field (legacy) admits every scope — that is the
	/// pre-existing behaviour and the migration contract: keys installed
	/// before the field existed must keep authenticating on upgrade. The
	/// caller (the API state) is responsible for emitting a one-time warning
	/// per legacy key.
	///
	/// Scopes are independent — a `write`-only key is not also `read`, and a
	/// `send`-only key cannot `write`. When the caller wants "any of these",
	/// pass the full set; when it wants "this specific scope", pass a
	/// single-element slice.
	pub fn admits_any(
		&self,
		presented: &str,
		client_ip: Option<IpAddr>,
		now: u64,
		acceptable_scopes: &[Scope],
	) -> bool {
		let hash_ok = sha256_token_matches(&self.hash, presented);
		let time_ok = self.expires_at.is_none_or(|expiry| now < expiry);
		let ip_ok = match &self.ip_cidr {
			None => true,
			Some(spec) => match (crate::cidr::Cidr::parse(spec), client_ip) {
				(Some(cidr), Some(ip)) => cidr.contains(ip),
				_ => false,
			},
		};
		// Empty `scopes` = legacy key = admit any scope (preserve behaviour).
		// A scoped key must list at least one of the acceptable scopes.
		let scope_ok = self.scopes.is_empty()
			|| acceptable_scopes
				.iter()
				.any(|scope| self.scopes.iter().any(|s| s == scope.as_str()));
		hash_ok && time_ok && ip_ok && scope_ok
	}
}

/// Compute the SHA-256 of `token` and compare it to a stored `sha256:<hex>`
/// digest. Comparing pre-image-resistant digests, so a timing leak cannot
/// reveal the key. A non-`sha256:` stored value never matches here.
pub fn sha256_token_matches(stored: &str, token: &str) -> bool {
	let Some(expected_hex) = stored.strip_prefix("sha256:") else {
		return false;
	};
	let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
	let actual_hex = digest
		.as_ref()
		.iter()
		.fold(String::with_capacity(64), |mut s, b| {
			use std::fmt::Write;
			write!(s, "{b:02x}").ok();
			s
		});
	crate::api::oauth::constant_time_eq(
		expected_hex.to_ascii_lowercase().as_bytes(),
		actual_hex.as_bytes(),
	)
}

/// The `sha256:<hex>` digest of `token`, for storing a new key.
pub fn sha256_hash(token: &str) -> String {
	let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
	let hex = digest
		.as_ref()
		.iter()
		.fold(String::with_capacity(64), |mut s, b| {
			use std::fmt::Write;
			write!(s, "{b:02x}").ok();
			s
		});
	format!("sha256:{hex}")
}

/// The TOML document.
#[derive(Debug, Default, Serialize, Deserialize)]
struct ApiKeyFile {
	#[serde(default)]
	keys: Vec<ApiKey>,
}

/// One row of [`ApiKeyStore::list`]. Carries everything an operator can see
/// about a key without ever seeing the secret or its hash.
#[derive(Debug, Clone)]
pub struct ApiKeySummary {
	/// Human-readable label identifying the key.
	pub label: String,
	/// Expiry as epoch seconds; `None` never expires.
	pub expires_at: Option<u64>,
	/// Single-CIDR allowlist; `None` allows any client IP.
	pub ip_cidr: Option<String>,
	/// Permissions granted to the key (canonical strings, e.g. `read`); empty
	/// means the legacy "any scope" form.
	pub scopes: Vec<String>,
}

/// Filesystem-backed store of management API keys.
pub struct ApiKeyStore {
	path: PathBuf,
	keys: Vec<ApiKey>,
}

/// Validate `scopes` for a brand-new key (the CLI path): at least one scope
/// must be listed, and every entry must be a known `Scope`.
fn validate_new_scopes(scopes: &[String]) -> std::io::Result<()> {
	if scopes.is_empty() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::InvalidInput,
			"API key must declare at least one scope (read/write/send)",
		));
	}
	for scope in scopes {
		if scope.parse::<Scope>().is_err() {
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidInput,
				format!("unknown API key scope \"{scope}\" (expected read, write or send)"),
			));
		}
	}
	Ok(())
}

/// Validate the scope entries loaded from disk: empty is allowed (legacy),
/// every non-empty entry must be a known `Scope`. A typo in the file is the
/// kind of thing that should keep the server from starting — the file is
/// small and operator-edited, so any mistake is best surfaced immediately.
fn validate_loaded_scopes(scopes: &[String]) -> std::io::Result<()> {
	for scope in scopes {
		if scope.parse::<Scope>().is_err() {
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				format!(
					"unknown API key scope \"{scope}\" in api_keys.toml (expected read, write or send)"
				),
			));
		}
	}
	Ok(())
}

impl ApiKeyStore {
	/// Open (loading if present) the store under `data_dir`. A missing file is
	/// an empty store.
	pub fn open(data_dir: &Path) -> std::io::Result<Self> {
		let path = data_dir.join("api_keys.toml");
		let file: ApiKeyFile = match std::fs::read_to_string(&path) {
			Ok(text) => toml::from_str(&text)
				.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => ApiKeyFile::default(),
			Err(error) => return Err(error),
		};
		for key in &file.keys {
			validate_loaded_scopes(&key.scopes)?;
		}
		Ok(ApiKeyStore {
			path,
			keys: file.keys,
		})
	}

	/// The loaded keys, for attaching to the API state.
	pub fn keys(&self) -> &[ApiKey] {
		&self.keys
	}

	/// Add a key. The hash must already be `sha256:<hex>`; a duplicate label is
	/// rejected, as is a malformed CIDR or an empty/unknown `scopes` vector.
	pub fn add(&mut self, key: ApiKey) -> std::io::Result<()> {
		if let Some(spec) = &key.ip_cidr
			&& crate::cidr::Cidr::parse(spec).is_none()
		{
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidInput,
				format!("invalid CIDR \"{spec}\""),
			));
		}
		validate_new_scopes(&key.scopes)?;
		if self.keys.iter().any(|existing| existing.label == key.label) {
			return Err(std::io::Error::new(
				std::io::ErrorKind::AlreadyExists,
				format!("API key \"{}\" already exists", key.label),
			));
		}
		self.keys.push(key);
		self.persist()
	}

	/// Remove a key by label. `NotFound` if absent.
	pub fn remove(&mut self, label: &str) -> std::io::Result<()> {
		let before = self.keys.len();
		self.keys.retain(|existing| existing.label != label);
		if self.keys.len() == before {
			return Err(std::io::Error::new(
				std::io::ErrorKind::NotFound,
				format!("no such API key \"{label}\""),
			));
		}
		self.persist()
	}

	/// Every key as an [`ApiKeySummary`], sorted by label. Hashes are never
	/// exposed.
	pub fn list(&self) -> Vec<ApiKeySummary> {
		let mut rows: Vec<ApiKeySummary> = self
			.keys
			.iter()
			.map(|key| ApiKeySummary {
				label: key.label.clone(),
				expires_at: key.expires_at,
				ip_cidr: key.ip_cidr.clone(),
				scopes: key.scopes.clone(),
			})
			.collect();
		rows.sort_by(|a, b| a.label.cmp(&b.label));
		rows
	}

	/// Atomically rewrite the backing file.
	fn persist(&self) -> std::io::Result<()> {
		let file = ApiKeyFile {
			keys: self.keys.clone(),
		};
		let text = toml::to_string_pretty(&file)
			.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
		crate::storage::write_secret(&self.path, text.as_bytes())
	}
}

#[cfg(test)]
#[path = "api_keys_tests.rs"]
mod tests;
