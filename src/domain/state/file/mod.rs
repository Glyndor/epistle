//! The shape of `<data_dir>/domains.toml` and how it is read and written.
//!
//! ```toml
//! seed_digest = "sha256:..."
//!
//! [[domain]]
//! name = "example.org"
//! role = "full"
//! enabled = true
//!
//! [aliases]
//! "example.net" = "example.org"
//! ```
//!
//! A domain added through the file carries the key and the SRS secret that
//! `domain add` made for it (`dkim` and `srs_secret`), since the
//! configuration file is not written. The file holds a secret, so it is
//! written owner-only like the other data-directory stores.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::dns::skip::DomainRole;

/// The role a domain is stored with. A switched-off domain keeps its role
/// and is `enabled = false`, so switching it back on restores the role.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StoredRole {
	/// Mail is received, sent and set up by clients.
	#[default]
	Full,
	/// Mail is only sent.
	SendOnly,
	/// Mail is only received.
	ReceiveOnly,
}

impl StoredRole {
	/// The role of the DNS records and of who may send, for a domain that is
	/// switched on.
	pub fn role(self) -> DomainRole {
		match self {
			StoredRole::Full => DomainRole::Full,
			StoredRole::SendOnly => DomainRole::SendOnly,
			StoredRole::ReceiveOnly => DomainRole::ReceiveOnly,
		}
	}

	/// The stored role of `role`, `None` for [`DomainRole::Disabled`], which
	/// is the switch and not a role.
	pub fn of(role: DomainRole) -> Option<Self> {
		match role {
			DomainRole::Full => Some(StoredRole::Full),
			DomainRole::SendOnly => Some(StoredRole::SendOnly),
			DomainRole::ReceiveOnly => Some(StoredRole::ReceiveOnly),
			DomainRole::Disabled => None,
		}
	}
}

/// The DKIM key of its own a domain added through the file signs with: what
/// a `[[dkim.domain]]` entry of the configuration file names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnKey {
	/// The ed25519 selector.
	pub selector: String,
	/// The ed25519 private key file.
	pub key_file: PathBuf,
	/// The RSA selector, when the server signs twice.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rsa_selector: Option<String>,
	/// The RSA private key file paired with `rsa_selector`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rsa_key_file: Option<PathBuf>,
}

/// One hosted domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedDomain {
	/// The domain, a lowercase ASCII name.
	pub name: String,
	/// What the domain does when it is switched on.
	#[serde(default)]
	pub role: StoredRole,
	/// `false` when the domain is switched off: mail for it is rejected and
	/// nobody may send as it.
	#[serde(default = "switched_on")]
	pub enabled: bool,
	/// The DKIM key `domain add` made for the domain.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub dkim: Option<OwnKey>,
	/// The SRS secret `domain add` made for the domain.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub srs_secret: Option<String>,
}

fn switched_on() -> bool {
	true
}

impl HostedDomain {
	/// A domain switched on with the `full` role and nothing of its own.
	pub fn new(name: &str) -> Self {
		HostedDomain {
			name: name.to_string(),
			role: StoredRole::Full,
			enabled: true,
			dkim: None,
			srs_secret: None,
		}
	}

	/// The role the records and the sending rules apply: the stored role, or
	/// [`DomainRole::Disabled`] while the domain is switched off.
	pub fn effective_role(&self) -> DomainRole {
		if self.enabled {
			self.role.role()
		} else {
			DomainRole::Disabled
		}
	}
}

/// The whole state file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainsFile {
	/// The digest of what the configuration file declared when this file was
	/// made or last imported ([`crate::domain::state::seed::DomainSeed::digest`]),
	/// so a later edit of the configuration file can be noticed.
	#[serde(default, skip_serializing_if = "String::is_empty")]
	pub seed_digest: String,
	/// The hosted domains, in the order they were added.
	#[serde(default, rename = "domain")]
	pub domains: Vec<HostedDomain>,
	/// Domain aliases: the alias domain and the hosted domain it resolves as.
	#[serde(default)]
	pub aliases: BTreeMap<String, String>,
}

impl DomainsFile {
	/// Parse the text of the file.
	pub fn parse(text: &str) -> std::io::Result<Self> {
		toml::from_str(text).map_err(|error| {
			std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
		})
	}

	/// The text written to disk.
	pub fn render(&self) -> std::io::Result<String> {
		let body = toml::to_string_pretty(self).map_err(|error| {
			std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
		})?;
		Ok(format!("{HEADER}{body}"))
	}

	/// Read the file at `path`. `Ok(None)` when it does not exist.
	pub fn read(path: &Path) -> std::io::Result<Option<Self>> {
		match std::fs::read_to_string(path) {
			Ok(text) => Self::parse(&text).map(Some),
			Err(error)
				if matches!(
					error.kind(),
					std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
				) =>
			{
				Ok(None)
			}
			Err(error) => Err(error),
		}
	}

	/// The hosted domain `name`, matched without regard to ASCII case.
	pub fn domain(&self, name: &str) -> Option<&HostedDomain> {
		self.domains
			.iter()
			.find(|domain| domain.name.eq_ignore_ascii_case(name.trim()))
	}

	/// [`Self::domain`], to change it.
	pub fn domain_mut(&mut self, name: &str) -> Option<&mut HostedDomain> {
		self.domains
			.iter_mut()
			.find(|domain| domain.name.eq_ignore_ascii_case(name.trim()))
	}

	/// The alias entry `alias`, matched without regard to ASCII case, as the
	/// key it is stored under and its target.
	pub fn alias(&self, alias: &str) -> Option<(&String, &String)> {
		self.aliases
			.iter()
			.find(|(key, _)| key.eq_ignore_ascii_case(alias.trim()))
	}

	/// The names of the hosted domains.
	pub fn names(&self) -> Vec<String> {
		self.domains
			.iter()
			.map(|domain| domain.name.clone())
			.collect()
	}
}

/// The comment the file starts with, for whoever opens it.
const HEADER: &str = "# The hosted domains of this server. `epistle domain` and the\n\
	# /api/v1/domains routes write this file and the server reloads it within\n\
	# seconds. While it exists, `domains`, `domain_aliases` and the role lists\n\
	# of the configuration file are not read; `epistle domain import` copies\n\
	# them in again.\n\n";

#[cfg(test)]
mod tests;
