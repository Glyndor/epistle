//! Server configuration: loading, validation and secure defaults.
//!
//! The configuration is TOML. Every default is the most restrictive option:
//! listeners bind to localhost, TLS is required wherever a transport supports
//! it, and any validation error aborts loading (fail closed).

mod account;
mod acme;
mod alerts;
mod alias;
mod antispam;
mod api;
mod arc;
mod database;
mod dkim;
mod dns;
mod ldap;
mod listener;
mod oauth;
mod otel;
mod privileges;
mod queue;
mod storage;
mod tenant;
mod tls;
mod transport;
mod validate;
pub(crate) use validate::validate_dns_name;
mod webhook;

pub use account::Account;
pub use acme::Acme;
pub use alerts::{Alert, AlertOp};
pub use alias::Alias;
pub use antispam::Llm;
pub use api::Api;
pub use arc::Arc;
pub use database::{Database, DatabaseTls};
pub use dkim::Dkim;
pub use dns::Dns;
pub use ldap::Ldap;
pub use listener::{Listener, ListenerKind, Protocol};
pub use oauth::Oauth;
pub use otel::Otel;
pub use privileges::Privileges;
pub use queue::{OutboundTls, Queue};
pub use storage::{BlobBackendConfig, S3BlobConfig, Storage};
pub use tenant::Tenant;
pub use tls::Tls;
pub use transport::{Transport, TransportKind, select as select_transport};
pub use webhook::Webhook;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Errors produced while loading or validating a configuration file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
	/// The configuration file could not be read from disk: missing file,
	/// permission denied, or another I/O failure. The variant carries the
	/// path that was attempted and the underlying `std::io::Error`.
	#[error("cannot read config file {path}: {source}")]
	Read {
		/// Path passed to `Config::load`.
		path: PathBuf,
		/// Underlying I/O error returned by `std::fs`.
		source: std::io::Error,
	},
	/// The file was read but its contents are not valid TOML, or they contain
	/// an unknown key (the schema is `deny_unknown_fields`). Carries the path
	/// and the parser error.
	#[error("invalid TOML in {path}: {source}")]
	Parse {
		/// Path of the file that failed to parse.
		path: PathBuf,
		/// Underlying TOML deserialization error.
		source: Box<toml::de::Error>,
	},
	/// The configuration file is group- or world-readable (or writable): on
	/// Unix the loader requires mode `0600`. Carries the path and the
	/// observed permission bits (masked to the low 9).
	#[error("config file {path} is group/world-accessible (mode {mode:#o}); restrict it to 0600")]
	InsecurePermissions {
		/// Path whose permissions were rejected.
		path: PathBuf,
		/// Observed permission mode, masked to `0o777`.
		mode: u32,
	},
	/// The configuration referenced `${VAR}` for a variable that is not set
	/// in the process environment. Carries the variable name.
	#[error("config references undefined environment variable ${{{0}}}")]
	MissingEnv(String),
	/// A semantic validation check failed after parsing: cross-field
	/// consistency, an out-of-range number, or a malformed `${...}` token.
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

/// Default for [`Config::masked_addresses_max`]. Generous enough for the
/// usual disposable-alias use cases (one address per signup service);
/// caps abuse before it can mint the whole 8-character suffix space.
fn default_masked_addresses_max() -> usize {
	100
}

/// Top-level server configuration.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
	/// Fully qualified hostname the server identifies as (EHLO, TLS).
	pub hostname: String,
	/// The public IPv4 address the hostname resolves to. Optional: when set,
	/// `dns-records` emits the A record and `verify-dns` checks the PTR of
	/// this address; when absent, `verify-dns` resolves the hostname instead.
	#[serde(default)]
	pub public_ipv4: Option<Ipv4Addr>,
	/// Same for IPv6 (an AAAA record). Publishing SPF for a host that also
	/// has AAAA without listing the IPv6 makes mail sent over IPv6 fail SPF.
	#[serde(default)]
	pub public_ipv6: Option<Ipv6Addr>,
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
	/// LLM-assisted screening for unauthenticated mail whose Bayesian score
	/// lands in an uncertain band. Absent disables the hook.
	pub antispam_llm: Option<Llm>,
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
	/// Per-domain submission rate limit (messages/min) for authenticated
	/// senders in that domain. Resolved by walking the account's own
	/// addresses — the same lookup [`crate::smtp::directory::Directory::quota_for`]
	/// performs — so the limit is the one for the domain the account is
	/// actually in, not the first domain configured. An account without a
	/// matching entry falls back to `submission_rate_limit_per_min` (and
	/// then to no limit, if that is also unset). Absent entries in
	/// `domain_quotas` and the existing `with_domain_quotas` builder mirror
	/// the same shape and lifecycle.
	#[serde(default)]
	pub domain_submission_limits: std::collections::HashMap<String, u32>,
	/// Messages an unauthenticated client IP may start per minute. Absent
	/// disables the per-IP inbound limit. Enforced on
	/// `MAIL FROM` for sessions that never authenticated; a send over the
	/// cap is deferred with `450 4.7.1 too many messages from this client;
	/// retry later` so a legitimate burst (a mailing list, a resend after
	/// an outage) retries rather than bounces.
	#[serde(default)]
	pub inbound_rate_limit_per_ip_per_min: Option<u32>,
	/// Messages a single envelope sender may start per minute across all
	/// clients. Absent disables the per-sender inbound limit. Enforced on
	/// `MAIL FROM` for sessions that never authenticated, lowercased
	/// reverse path; the null sender (`<>`) used by bounces is skipped so
	/// a verification failure does not exhaust the budget of a real
	/// client. Over the cap is deferred with
	/// `450 4.7.1 too many messages from this sender; retry later`.
	#[serde(default)]
	pub inbound_rate_limit_per_sender_per_min: Option<u32>,
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
	/// LDAP / Active Directory directory backend. Present enables authenticating
	/// non-local logins against the LDAP server and loading its users for
	/// recipient resolution.
	pub ldap: Option<Ldap>,
	/// Maximum masked email addresses one account may own. 0 disables
	/// masked addresses entirely; the default of 100 is generous for the
	/// usual disposable-alias use cases (a signup per service) and stops a
	/// runaway loop from minting the whole address space. `429 Too Many
	/// Requests` answers requests above the limit.
	#[serde(default = "default_masked_addresses_max")]
	pub masked_addresses_max: usize,
	/// Outbound event webhooks. Present enables notifications.
	pub webhook: Option<Webhook>,
	/// Tenant definitions: named groups of domains with optional aggregate
	/// caps on accounts, domains, storage and submission rate. Absent or
	/// empty means no tenancy is in effect and the server behaves exactly as
	/// it did before this field existed.
	#[serde(default, rename = "tenant")]
	pub tenants: Vec<Tenant>,
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
	/// Alert rules: periodic metric comparisons that fire webhooks or email
	/// when the configured condition holds. Absent or empty disables the
	/// alert engine entirely (the default).
	#[serde(default)]
	pub alerts: Vec<Alert>,
}

impl std::fmt::Debug for Config {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Config")
			.field("hostname", &self.hostname)
			.field("public_ipv4", &self.public_ipv4)
			.field("public_ipv6", &self.public_ipv6)
			.field("data_dir", &self.data_dir)
			.field("domains", &self.domains)
			.field("domain_aliases", &self.domain_aliases)
			.field("dnsbl_zones", &self.dnsbl_zones)
			.field(
				"first_time_sender_delay_secs",
				&self.first_time_sender_delay_secs,
			)
			.field("greylist_delay_secs", &self.greylist_delay_secs)
			.field("srs_secret", &self.srs_secret.as_ref().map(|_| "***"))
			.field("quota_bytes", &self.quota_bytes)
			.field("queue_give_up_secs", &self.queue_give_up_secs)
			.field("rules", &self.rules)
			.field("scanner_hook_url", &self.scanner_hook_url)
			.field("antispam_llm", &self.antispam_llm)
			.field("listeners", &self.listeners)
			.field("accounts", &self.accounts)
			.field("tls", &self.tls)
			.field("dkim", &self.dkim)
			.field("api", &self.api)
			.field("database", &self.database)
			.field("log_format", &self.log_format)
			.field("acme", &self.acme)
			.field("dns", &self.dns)
			.field("domain_quotas", &self.domain_quotas)
			.field(
				"submission_rate_limit_per_min",
				&self.submission_rate_limit_per_min,
			)
			.field("domain_submission_limits", &self.domain_submission_limits)
			.field(
				"inbound_rate_limit_per_ip_per_min",
				&self.inbound_rate_limit_per_ip_per_min,
			)
			.field(
				"inbound_rate_limit_per_sender_per_min",
				&self.inbound_rate_limit_per_sender_per_min,
			)
			.field(
				"max_connections_per_listener",
				&self.max_connections_per_listener,
			)
			.field("transport", &self.transport)
			.field("otel", &self.otel)
			.field("alias", &self.alias)
			.field("arc", &self.arc)
			.field("oauth", &self.oauth)
			.field("ldap", &self.ldap)
			.field("webhook", &self.webhook)
			.field("tenants", &self.tenants)
			.field("privileges", &self.privileges)
			.field("storage", &self.storage)
			.field("queue", &self.queue)
			.field("alerts", &self.alerts)
			.finish()
	}
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
#[path = "redaction_tests.rs"]
mod redaction_tests;

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
