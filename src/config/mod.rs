//! Server configuration: loading, validation and secure defaults.
//!
//! The configuration is TOML. Every default is the most restrictive option:
//! listeners bind to localhost, TLS is required wherever a transport supports
//! it, and any validation error aborts loading (fail closed).

mod account;
mod acme;
mod alias;
mod api;
mod arc;
mod database;
mod dkim;
mod dns;
mod listener;
mod oauth;
mod otel;
mod privileges;
mod queue;
mod storage;
mod tls;
mod transport;
mod validate;
mod webhook;

pub use account::Account;
pub use acme::Acme;
pub use alias::Alias;
pub use api::Api;
pub use arc::Arc;
pub use database::Database;
pub use dkim::Dkim;
pub use dns::Dns;
pub use listener::{Listener, ListenerKind};
pub use oauth::Oauth;
pub use otel::Otel;
pub use privileges::Privileges;
pub use queue::{OutboundTls, Queue};
pub use storage::Storage;
pub use tls::Tls;
pub use transport::{Transport, TransportKind, select as select_transport};
pub use webhook::Webhook;

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
	#[error("config file {path} is group/world-accessible (mode {mode:#o}); restrict it to 0600")]
	InsecurePermissions { path: PathBuf, mode: u32 },
	#[error("config references undefined environment variable ${{{0}}}")]
	MissingEnv(String),
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
	/// Seconds an unseen (client, sender, recipient) triplet is greylisted
	/// (deferred with a 451) before a retry is accepted. 0 disables greylisting
	/// (the default).
	#[serde(default)]
	pub greylist_delay_secs: u64,
	/// Secret for Sender Rewriting Scheme (SRS) on forwarded mail. When set,
	/// redirected/forwarded mail's envelope sender is rewritten so it passes
	/// SPF at the next hop. Absent disables SRS (the default).
	pub srs_secret: Option<String>,
	/// Per-account IMAP storage quota in bytes (RFC 9208). Absent uses the
	/// built-in default (5 GiB).
	pub quota_bytes: Option<u64>,
	/// Outbound give-up window in seconds: undelivered mail older than this is
	/// bounced to the sender. Absent uses the built-in default (5 days).
	pub queue_give_up_secs: Option<u64>,
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
	/// DNS provider for record automation (e.g. TLSA refresh on cert rotation).
	#[serde(default)]
	pub dns: Option<Dns>,
	/// Default storage quota (bytes) per domain, applied to accounts in that
	/// domain that have no quota of their own.
	#[serde(default)]
	pub domain_quotas: std::collections::HashMap<String, u64>,
	/// Max messages an authenticated account may submit per minute. Absent
	/// disables per-account submission rate limiting.
	#[serde(default)]
	pub submission_rate_limit_per_min: Option<u32>,
	/// Max concurrent connections per listener (back-pressure cap). Absent
	/// uses each protocol's built-in default. Excess connections are dropped.
	#[serde(default)]
	pub max_connections_per_listener: Option<usize>,
	/// Outbound transport rules (smarthost relay / SOCKS / direct / fail) with
	/// account/domain/global routing. Empty means direct MX delivery for all.
	#[serde(default)]
	pub transport: Vec<Transport>,
	/// OpenTelemetry OTLP trace export. Present enables span export.
	#[serde(default)]
	pub otel: Option<Otel>,
	/// Multi-target aliases: an address that delivers to several accounts.
	#[serde(default)]
	pub alias: Vec<Alias>,
	/// ARC sealing for inbound mail (RFC 8617). Present enables sealing.
	pub arc: Option<Arc>,
	/// OAuth2/OIDC token verification (OAUTHBEARER/XOAUTH2). Present enables it.
	pub oauth: Option<Oauth>,
	/// Outbound event webhooks. Present enables notifications.
	pub webhook: Option<Webhook>,
	/// Unprivileged user/group to drop to after privileged ports are bound.
	/// Absent leaves the process running as whoever started it.
	pub privileges: Option<Privileges>,
	/// At-rest message encryption. Absent leaves stored mail unencrypted at the
	/// application layer (relying on full-disk encryption); present can enable
	/// transparent ChaCha20-Poly1305 encryption of stored message files.
	#[serde(default)]
	pub storage: Option<Storage>,
	/// Outbound queue settings (currently the STARTTLS authentication mode).
	/// Absent uses the secure defaults (strict outbound TLS).
	#[serde(default)]
	pub queue: Queue,
}

impl Config {
	/// Load and validate a configuration file. Fails closed: insecure
	/// permissions, a read, parse or validation error, or an undefined
	/// referenced environment variable all abort loading.
	///
	/// Secrets should not be written into the file directly: any `${VAR}` in
	/// the file is substituted from the process environment at load time, so
	/// credentials (e.g. the database password) can stay in the environment or
	/// a secret store rather than on disk.
	pub fn load(path: &Path) -> Result<Self, ConfigError> {
		check_permissions(path)?;
		let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
			path: path.to_path_buf(),
			source,
		})?;
		let expanded = expand_env(&raw)?;
		let config: Config = toml::from_str(&expanded).map_err(|source| ConfigError::Parse {
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

/// Substitute every `${VAR}` in the raw config with its environment value.
/// Fails closed: a referenced variable that is not set aborts the load, so a
/// missing secret can never silently become an empty string.
fn expand_env(raw: &str) -> Result<String, ConfigError> {
	let mut out = String::with_capacity(raw.len());
	let mut rest = raw;
	while let Some(start) = rest.find("${") {
		out.push_str(&rest[..start]);
		let after = &rest[start + 2..];
		let end = after
			.find('}')
			.ok_or_else(|| ConfigError::Invalid("unterminated ${...} in config".to_string()))?;
		let var = &after[..end];
		let value = std::env::var(var).map_err(|_| ConfigError::MissingEnv(var.to_string()))?;
		out.push_str(&value);
		rest = &after[end + 1..];
	}
	out.push_str(rest);
	Ok(out)
}

/// Reject a config file that is readable or writable by group or others: it may
/// hold secrets (or `${VAR}` references aside, paths and tokens), so it must be
/// owner-only. Best effort on non-Unix platforms.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), ConfigError> {
	use std::os::unix::fs::PermissionsExt;
	let mode = std::fs::metadata(path)
		.map_err(|source| ConfigError::Read {
			path: path.to_path_buf(),
			source,
		})?
		.permissions()
		.mode();
	if mode & 0o077 != 0 {
		return Err(ConfigError::InsecurePermissions {
			path: path.to_path_buf(),
			mode: mode & 0o777,
		});
	}
	Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), ConfigError> {
	Ok(())
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
	fn expands_environment_variables() {
		// SAFETY: the variable name is unique to this test, so no other test
		// reads or writes it concurrently.
		unsafe { std::env::set_var("EPISTLE_TEST_HOSTNAME", "mail.expanded.example") };
		let file = write_temp(
			r#"
hostname = "${EPISTLE_TEST_HOSTNAME}"
data_dir = "/var/lib/mail"
"#,
		);
		let config = Config::load(file.path()).expect("config loads");
		assert_eq!(config.hostname, "mail.expanded.example");
		// SAFETY: same uniquely-named variable as set above.
		unsafe { std::env::remove_var("EPISTLE_TEST_HOSTNAME") };
	}

	#[test]
	fn rejects_undefined_environment_variable() {
		let file = write_temp(
			r#"
hostname = "${EPISTLE_DEFINITELY_UNSET_VAR_XYZ}"
data_dir = "/var/lib/mail"
"#,
		);
		assert!(matches!(
			Config::load(file.path()),
			Err(ConfigError::MissingEnv(_))
		));
	}

	#[cfg(unix)]
	#[test]
	fn rejects_group_or_world_accessible_config() {
		use std::os::unix::fs::PermissionsExt;
		let file = write_temp(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
		);
		std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644))
			.expect("chmod");
		assert!(matches!(
			Config::load(file.path()),
			Err(ConfigError::InsecurePermissions { .. })
		));
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
	fn outbound_tls_defaults_strict_and_parses() {
		// Absent [queue] section: strict (fail closed, back-compatible).
		let default = write_temp(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
		);
		assert_eq!(
			Config::load(default.path())
				.expect("loads")
				.queue
				.outbound_tls,
			OutboundTls::Strict
		);

		// Explicit opportunistic parses.
		let opportunistic = write_temp(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
[queue]
outbound_tls = "opportunistic"
"#,
		);
		assert_eq!(
			Config::load(opportunistic.path())
				.expect("loads")
				.queue
				.outbound_tls,
			OutboundTls::Opportunistic
		);

		// An unknown key inside [queue] is rejected (deny_unknown_fields).
		let bad = write_temp(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
[queue]
surprise = true
"#,
		);
		assert!(matches!(
			Config::load(bad.path()),
			Err(ConfigError::Parse { .. })
		));
	}

	#[test]
	fn default_bind_is_loopback() {
		assert!(Config::default_bind_addr().is_loopback());
	}

	#[test]
	fn max_connections_per_listener_parses_and_defaults_none() {
		let default = write_temp(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
		);
		assert_eq!(
			Config::load(default.path())
				.expect("loads")
				.max_connections_per_listener,
			None
		);

		let set = write_temp(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
max_connections_per_listener = 2048
"#,
		);
		assert_eq!(
			Config::load(set.path())
				.expect("loads")
				.max_connections_per_listener,
			Some(2048)
		);
	}
}
