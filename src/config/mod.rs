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
mod attachments;
mod auth;
mod database;
mod dkim;
mod dns;
mod ldap;
mod listener;
mod mta_sts;
mod oauth;
mod otel;
mod privileges;
mod queue;
mod scanner;
mod storage;
mod tenant;
mod tls;
mod transport;
mod validate;
mod validate_limits;
pub(crate) use validate::validate_addresses::{non_global_ipv4_reason, non_global_ipv6_reason};
pub(crate) use validate::validate_dns_name;
mod webhook;

pub use account::Account;
pub use acme::{Acme, AcmeChallenge};
pub use alerts::{Alert, AlertOp};
pub use alias::Alias;
pub use antispam::{Llm, SubjectPass};
pub use api::Api;
pub use arc::Arc;
pub use attachments::{
	AttachmentMode, Attachments, ContentAction, normalise_extension, valid_extension,
};
pub use auth::Auth;
pub use database::{Database, DatabaseTls};
pub use dkim::{DKIM_RSA_REQUIRED_FROM, Dkim, DkimDomain};
pub use dns::Dns;
pub(crate) use dns::{SUPPORTED_PROVIDERS, is_supported_provider};
pub use ldap::Ldap;
pub use listener::{Listener, ListenerKind, Protocol};
pub use mta_sts::{MtaSts, MtaStsMode};
pub use oauth::Oauth;
pub use otel::Otel;
pub use privileges::Privileges;
pub use queue::{OutboundTls, Queue};
pub use scanner::{Antispam, ClamdOnFound};
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
	/// A file the configuration needed could not be read from disk: missing
	/// file, permission denied, or another I/O failure. The variant carries
	/// the path that was attempted, the underlying `std::io::Error`, and a
	/// short `kind` so the same variant can report both the config file
	/// itself and the `[database] password_file` secret (the operator reads
	/// a different fix for each one, but the I/O surface is the same).
	#[error("cannot read {kind} {path}: {source}")]
	Read {
		/// Path that failed to read.
		path: PathBuf,
		/// Underlying I/O error returned by `std::fs`.
		source: std::io::Error,
		/// What kind of file the rejected path was. `"config file"` for the
		/// loader, `"[database] password_file"` for the database password
		/// secret; both can fail with the same I/O error, but the operator
		/// reads a different fix.
		kind: &'static str,
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
	/// Unix the loader requires mode `0600`. Carries the path, the
	/// observed permission bits (masked to the low 9) and a short
	/// description of what kind of file it was (so the same variant can be
	/// reused for the `[database] password_file` check, which produces the
	/// same kind of refusal for a different file).
	#[error(
		"{kind} {path} is group/world-accessible (mode {mode:#o}); restrict it to owner-only (0600 or 0400)"
	)]
	InsecurePermissions {
		/// Path whose permissions were rejected.
		path: PathBuf,
		/// Observed permission mode, masked to `0o777`.
		mode: u32,
		/// What kind of file the rejected path was. `"config file"` for the
		/// loader, `"[database] password_file"` for the database password
		/// secret; both can fail with the same bit pattern, but the operator
		/// reads a different fix.
		kind: &'static str,
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
	/// Right-hand-side blocklist zones queried with the envelope sender's
	/// domain (RFC 5782 §2.3). Absent disables the sender-domain screen.
	#[serde(default)]
	pub dnsbl_domain_zones: Vec<String>,
	/// URI blocklist zones queried with the host of every URL found in the
	/// body (RFC 5782 §2.3). Absent disables the URL-host screen.
	#[serde(default)]
	pub dnsbl_url_zones: Vec<String>,
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
	/// Outbound wait after a recipient's first failed attempt, in seconds;
	/// each later wait doubles. Absent uses 60 (one minute).
	pub queue_retry_base_secs: Option<u64>,
	/// Longest outbound wait between attempts, in seconds. Absent uses 3600.
	pub queue_retry_cap_secs: Option<u64>,
	/// Message age, in seconds, at which the one "delivery delayed" warning
	/// is sent. Absent uses 14400 (four hours).
	pub queue_delay_warning_secs: Option<u64>,
	/// Delivery rules: route or flag locally delivered mail by sender/header.
	#[serde(default)]
	pub rules: Vec<crate::rules::Rule>,
	/// URL of an external scanner hook (ClamAV/Rspamd behind HTTP) consulted
	/// for unauthenticated inbound mail. Leave unset to disable HTTP scanning.
	pub scanner_hook_url: Option<String>,
	/// Unix socket scanner configuration. Absent disables clamd.
	#[serde(default)]
	pub antispam: Antispam,
	/// What to do with attachments that are not what they claim. Absent
	/// flags them.
	#[serde(default)]
	pub attachments: Attachments,
	/// LLM-assisted screening for unauthenticated mail whose Bayesian score
	/// lands in an uncertain band. Absent disables the hook.
	pub antispam_llm: Option<Llm>,
	/// SubjectPass opt-in: signed retry token for the uncertain band.
	/// Disabled by default; enabling requires a `[database]` section so the
	/// band has a Bayesian score to fall back on.
	#[serde(default)]
	pub subjectpass: SubjectPass,
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
	/// Public MTA-STS policy settings.
	#[serde(default)]
	pub mta_sts: MtaSts,
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
	/// Cap on the number of recipients an authenticated account may write
	/// to for the first time in a rolling 24h window. Every submission path
	/// (SMTP authenticated end-of-DATA, `POST /api/v1/send`, JMAP
	/// `EmailSubmission/set`) computes the count of recipients the account
	/// has not previously contacted, sums it with the number of markers
	/// already inside the window, and refuses the message when the sum
	/// would exceed this limit. Absent disables the cap (the default).
	/// The intent is to stop the slow-exfiltration pattern a per-minute
	/// rate limit cannot see: a compromised account can stay under
	/// `submission_rate_limit_per_min` for hours while sending to fresh
	/// addresses, and a daily ceiling on the *new* recipients makes that
	/// visible.
	#[serde(default)]
	pub new_recipients_per_day: Option<u32>,
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
	/// Max concurrent connections per client IP per SMTP listener. A peer
	/// over the cap is answered `421 4.7.0 too many connections from your
	/// address` and closed. Absent (or `0`) uses the built-in default of
	/// 20. An IPv6 client is counted by its /64; no peer is exempt.
	#[serde(default)]
	pub max_connections_per_ip: Option<usize>,
	/// Shared byte budget every SMTP `DATA` / `BDAT` reservation draws
	/// from. When a reservation would push the in-flight total past the
	/// cap the message is refused with `452 4.3.1 insufficient system
	/// resources; try again later`, so a busy server cannot grow without
	/// bound. `0` disables the cap (every reservation succeeds, the
	/// historical behaviour). Absent derives it from the memory the `mail`
	/// container may use (see [`crate::smtp::memory_fit`]): a fifth of
	/// the limit, at least `max_message_size`, at most 1 GiB.
	#[serde(default)]
	pub message_memory_budget: Option<u64>,
	/// Minimum average transfer rate of one message transaction, in
	/// bytes per second, once `data_rate_grace` is over. A client below it
	/// is answered `421 4.4.2 transfer too slow, closing connection` and
	/// closed. Absent uses 10240; `0` turns the check off.
	#[serde(default)]
	pub min_data_rate: Option<u64>,
	/// Seconds from the start of a message transaction (the 354 of DATA,
	/// or the first BDAT chunk) before `min_data_rate` applies. Absent
	/// uses 120; from 1 to 3600.
	#[serde(default)]
	pub data_rate_grace: Option<u64>,
	/// Commands that bring an SMTP session no closer to a delivered
	/// message (NOOP, RSET, VRFY, AUTH response lines, refused commands)
	/// one session may send before it is answered `421 4.7.0` and closed.
	/// Absent uses 100; `0` turns the limit off, else from 10 to 10000.
	#[serde(default)]
	pub junk_command_limit: Option<u64>,
	/// Seconds an SMTP session may last before it is answered `421 4.4.2`
	/// and closed at the next command boundary (never while a message body
	/// is being received). Absent uses 1800; `0` turns the limit off, else
	/// from 60 to 86400.
	#[serde(default)]
	pub max_session_time: Option<u64>,
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
	/// Per-instance message-size cap in bytes. `None` keeps the
	/// historical default of 25 MiB (the same value the SMTP
	/// `SIZE` extension, the JMAP `maxSizeRequest` / upload cap and
	/// the REST `POST /api/v1/send` builder enforce). Applied
	/// consistently: the SMTP `MAIL FROM` SIZE check, the per-line
	/// running size, the end-of-DATA check, the per-chunk BDAT cap,
	/// the JMAP `Email/set` / `EmailSubmission/set` builder, the JMAP
	/// `upload` body limit, and the REST `send` body limit all use
	/// the same value.
	#[serde(default)]
	pub max_message_size: Option<u64>,
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
	/// Authentication toggles. Absent keeps the historical default of
	/// `scram = true`. Present with `scram = false` hides the mechanism on
	/// the wire, refuses an explicit `AUTHENTICATE`/`AUTH` against it,
	/// and prevents account-create and password-change paths from deriving
	/// or storing a verifier.
	#[serde(default)]
	pub auth: Auth,
	/// Alert rules: periodic metric comparisons that fire webhooks or email
	/// when the configured condition holds. Absent or empty disables the
	/// alert engine entirely (the default).
	#[serde(default)]
	pub alerts: Vec<Alert>,
	/// When `true`, the outbound queue worker is not started: mail submitted
	/// for a recipient outside a configured domain stays in the spool, and
	/// no outbound SMTP connection is ever opened. Only `epistle local`
	/// sets this; the field is `#[serde(skip)]` so `Config::load` cannot
	/// produce `true` from a TOML file (the loader would reject such a
	/// file as an unknown field, by design).
	#[serde(skip, default)]
	pub hold_outbound: bool,
	/// Mail addresses and domains the file spells with capitals, each as a
	/// line naming the entry and the lowercase form epistle uses for it.
	/// Filled when the file is loaded, never read from it.
	#[serde(skip)]
	pub mixed_case: Vec<String>,
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
			.field("dnsbl_domain_zones", &self.dnsbl_domain_zones)
			.field("dnsbl_url_zones", &self.dnsbl_url_zones)
			.field(
				"first_time_sender_delay_secs",
				&self.first_time_sender_delay_secs,
			)
			.field("greylist_delay_secs", &self.greylist_delay_secs)
			.field("srs_secret", &self.srs_secret.as_ref().map(|_| "***"))
			.field("quota_bytes", &self.quota_bytes)
			.field("queue_give_up_secs", &self.queue_give_up_secs)
			.field("queue_retry_base_secs", &self.queue_retry_base_secs)
			.field("queue_retry_cap_secs", &self.queue_retry_cap_secs)
			.field("queue_delay_warning_secs", &self.queue_delay_warning_secs)
			.field("rules", &self.rules)
			.field("scanner_hook_url", &self.scanner_hook_url)
			.field("antispam", &self.antispam)
			.field("attachments", &self.attachments)
			.field("antispam_llm", &self.antispam_llm)
			.field("subjectpass", &self.subjectpass)
			.field("listeners", &self.listeners)
			.field("accounts", &self.accounts)
			.field("tls", &self.tls)
			.field("mta_sts", &self.mta_sts)
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
			.field("new_recipients_per_day", &self.new_recipients_per_day)
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
			.field("max_connections_per_ip", &self.max_connections_per_ip)
			.field("message_memory_budget", &self.message_memory_budget)
			.field("min_data_rate", &self.min_data_rate)
			.field("data_rate_grace", &self.data_rate_grace)
			.field("junk_command_limit", &self.junk_command_limit)
			.field("max_session_time", &self.max_session_time)
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
			.field("auth", &self.auth)
			.field("alerts", &self.alerts)
			.field("hold_outbound", &self.hold_outbound)
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
		check_permissions(path, "config file")?;
		let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
			path: path.to_path_buf(),
			source,
			kind: "config file",
		})?;
		Self::parse_text(&raw, path)
	}

	/// The loopback address listeners bind to unless explicitly configured.
	pub const fn default_bind_addr() -> IpAddr {
		IpAddr::V4(Ipv4Addr::LOCALHOST)
	}

	/// Whether the outbound queue worker should be started for this config.
	/// `false` only when `hold_outbound` is `true`, a flag `epistle local`
	/// sets to keep the harness from opening any outbound SMTP connection.
	/// Pulled out so the `serve` startup path and the unit tests share the
	/// same source of truth.
	pub fn start_queue_worker(&self) -> bool {
		!self.hold_outbound
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

/// Reject a file that is readable or writable by group or others: it may hold
/// secrets, so it must be owner-only. `kind` labels the message the operator
/// will read in the refusal (`"config file"` for the loader, `"[database]
/// password_file"` for the database secret). Best effort on non-Unix platforms
/// where the bit check is meaningless and the check passes through.
#[cfg(unix)]
pub(super) fn check_permissions(path: &Path, kind: &'static str) -> Result<(), ConfigError> {
	use std::os::unix::fs::PermissionsExt;
	let mode = std::fs::metadata(path)
		.map_err(|source| ConfigError::Read {
			path: path.to_path_buf(),
			source,
			kind: "config file",
		})?
		.permissions()
		.mode();
	if mode & 0o077 != 0 {
		return Err(ConfigError::InsecurePermissions {
			path: path.to_path_buf(),
			mode: mode & 0o777,
			kind,
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
#[path = "hold_outbound_tests.rs"]
mod hold_outbound_tests;

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;

mod parse;

#[path = "normalize.rs"]
mod normalize;
