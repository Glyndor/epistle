//! Server configuration: loading, validation and secure defaults.
//!
//! The configuration is TOML. Every default is the most restrictive option:
//! listeners bind to localhost, TLS is required wherever a transport supports
//! it, and any validation error aborts loading (fail closed).

mod account;
mod acme;
mod api;
mod arc;
mod database;
mod dkim;
mod listener;
mod tls;
mod validate;

pub use account::Account;
pub use acme::Acme;
pub use api::Api;
pub use arc::Arc;
pub use database::Database;
pub use dkim::Dkim;
pub use listener::{Listener, ListenerKind};
pub use tls::Tls;

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Errors produced while loading or validating a configuration file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
	#[error("cannot read config file {path}: {source}")]
	Read {
		path: PathBuf,
		source: std::io::Error,
	},
	#[error("invalid TOML in {path}: {source}")]
	Parse {
		path: PathBuf,
		source: Box<toml::de::Error>,
	},
	#[error("invalid configuration: {0}")]
	Invalid(String),
}

/// Log output format.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
	/// Human-readable text (the default).
	#[default]
	Text,
	/// Structured JSON, one object per event.
	Json,
}

/// Top-level server configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
	/// Fully qualified hostname the server identifies as (EHLO, TLS).
	pub hostname: String,
	/// Directory where all server state lives.
	pub data_dir: PathBuf,
	/// Domains this server accepts mail for. Required when any listener
	/// is configured: without it every recipient would be rejected.
	#[serde(default)]
	pub domains: Vec<String>,
	/// Domain aliases (alias domain → target domain): mail to `user@alias`
	/// is delivered as `user@target`.
	#[serde(default)]
	pub domain_aliases: std::collections::HashMap<String, String>,
	/// DNS blocklist zones (RFC 5782) screened against unauthenticated
	/// clients. Empty disables DNSBL screening (the default).
	#[serde(default)]
	pub dnsbl_zones: Vec<String>,
	/// Seconds to delay a first-time (no-reputation) unauthenticated sender
	/// before accepting. 0 disables the slowdown (the default). Requires a
	/// configured database.
	#[serde(default)]
	pub first_time_sender_delay_secs: u64,
	/// Delivery rules: route or flag locally delivered mail by sender/header.
	#[serde(default)]
	pub rules: Vec<crate::rules::Rule>,
	/// URL of an external scanner hook (ClamAV/Rspamd behind HTTP) consulted
	/// for unauthenticated inbound mail. Absent disables scanning.
	pub scanner_hook_url: Option<String>,
	/// Network listeners. Empty means the server starts nothing.
	#[serde(default)]
	pub listeners: Vec<Listener>,
	/// Mail accounts. Mail for a local domain address not listed here is
	/// rejected during RCPT.
	#[serde(default)]
	pub accounts: Vec<Account>,
	/// TLS material. Required by `submissions` listeners; enables STARTTLS
	/// on `smtp` and `submission` listeners.
	pub tls: Option<Tls>,
	/// DKIM signing for outbound mail.
	pub dkim: Option<Dkim>,
	/// Management API. Required by `api` listeners.
	pub api: Option<Api>,
	/// PostgreSQL backing for the antispam engine. Optional until antispam
	/// persistence is enabled.
	pub database: Option<Database>,
	/// Log output format (text or json).
	#[serde(default)]
	pub log_format: LogFormat,
	/// Automatic TLS (ACME). Present enables certificate issuance/renewal.
	pub acme: Option<Acme>,
	/// ARC sealing for inbound mail (RFC 8617). Present enables sealing.
	pub arc: Option<Arc>,
}

impl Config {
	/// Load and validate a configuration file. Fails closed: any read,
	/// parse or validation error aborts loading.
	pub fn load(path: &Path) -> Result<Self, ConfigError> {
		let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
			path: path.to_path_buf(),
			source,
		})?;
		let config: Config = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
			path: path.to_path_buf(),
			source: Box::new(source),
		})?;
		config.validate()?;
		Ok(config)
	}

	/// The loopback address listeners bind to unless explicitly configured.
	pub const fn default_bind_addr() -> IpAddr {
		IpAddr::V4(Ipv4Addr::LOCALHOST)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn write_temp(content: &str) -> tempfile::NamedTempFile {
		use std::io::Write;
		let mut file = tempfile::NamedTempFile::new().expect("create temp file");
		file.write_all(content.as_bytes()).expect("write temp file");
		file
	}

	#[test]
	fn loads_minimal_valid_config() {
		let file = write_temp(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
		);
		let config = Config::load(file.path()).expect("valid config loads");
		assert_eq!(config.hostname, "mail.example.org");
		assert!(config.listeners.is_empty());
	}

	#[test]
	fn rejects_unknown_keys() {
		let file = write_temp(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
surprise = true
"#,
		);
		assert!(matches!(
			Config::load(file.path()),
			Err(ConfigError::Parse { .. })
		));
	}

	#[test]
	fn rejects_missing_file() {
		let missing = Path::new("/nonexistent/mail.toml");
		assert!(matches!(
			Config::load(missing),
			Err(ConfigError::Read { .. })
		));
	}

	#[test]
	fn rejects_invalid_toml() {
		let file = write_temp("hostname = ");
		assert!(matches!(
			Config::load(file.path()),
			Err(ConfigError::Parse { .. })
		));
	}

	#[test]
	fn default_bind_is_loopback() {
		assert!(Config::default_bind_addr().is_loopback());
	}
}
