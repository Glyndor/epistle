//! Labeled bearer API keys for the management API.
//!
//! Alongside the single configured bearer token (see [`super::state`]), an
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
}

impl ApiKey {
	/// Whether this key admits `presented` from `client_ip` at `now` (epoch
	/// seconds). Fail-closed on every branch.
	pub fn admits(&self, presented: &str, client_ip: Option<IpAddr>, now: u64) -> bool {
		let hash_ok = sha256_token_matches(&self.hash, presented);
		let time_ok = self.expires_at.is_none_or(|expiry| now < expiry);
		let ip_ok = match &self.ip_cidr {
			None => true,
			Some(spec) => match (crate::cidr::Cidr::parse(spec), client_ip) {
				(Some(cidr), Some(ip)) => cidr.contains(ip),
				_ => false,
			},
		};
		hash_ok && time_ok && ip_ok
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
	expected_hex.eq_ignore_ascii_case(&actual_hex)
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

/// Filesystem-backed store of management API keys.
pub struct ApiKeyStore {
	path: PathBuf,
	keys: Vec<ApiKey>,
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
	/// rejected, as is a malformed CIDR.
	pub fn add(&mut self, key: ApiKey) -> std::io::Result<()> {
		if let Some(spec) = &key.ip_cidr
			&& crate::cidr::Cidr::parse(spec).is_none()
		{
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidInput,
				format!("invalid CIDR \"{spec}\""),
			));
		}
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

	/// Every `(label, expires_at, ip_cidr)`, sorted. Hashes are never exposed.
	pub fn list(&self) -> Vec<(String, Option<u64>, Option<String>)> {
		let mut rows: Vec<_> = self
			.keys
			.iter()
			.map(|key| (key.label.clone(), key.expires_at, key.ip_cidr.clone()))
			.collect();
		rows.sort();
		rows
	}

	/// Atomically rewrite the backing file.
	fn persist(&self) -> std::io::Result<()> {
		let file = ApiKeyFile {
			keys: self.keys.clone(),
		};
		let text = toml::to_string_pretty(&file)
			.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
		let tmp = self.path.with_extension("toml.tmp");
		std::fs::write(&tmp, text)?;
		std::fs::rename(&tmp, &self.path)
	}
}

#[cfg(test)]
#[path = "api_keys_tests.rs"]
mod tests;
