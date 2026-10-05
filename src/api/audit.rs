//! Security event audit: emit a `tracing::info!` with structured fields for
//! every privilege change made through the management API.
//!
//! The shape is stable: target `epistle::api::audit`, fields `event`,
//! `account`, `client_ip`, plus the message. Operators correlate these
//! from the JSON log output (or via OpenTelemetry). The four privileged
//! handlers (`create`, `remove`, `set_password`, `enroll_totp`,
//! `disable_totp`) call [`log_privilege_change`] after a successful
//! state change so an operator with the bearer token cannot reset the
//! 2FA of any account, receive the new secret in the response, and leave
//! no trace.
//!
//! What is never logged: the TOTP secret, the password hash, the SCRAM
//! credentials, the plaintext password, and the bearer token. Those stay
//! in the request and response; the audit channel only carries the
//! fact that a privileged action happened.

use std::net::IpAddr;

use crate::config::Protocol;

/// A privileged action taken against an account through the management API.
///
/// Each variant maps to a stable string in the `event` field of the emitted
/// tracing event; operators grep/filter on it.
#[derive(Debug, Clone, Copy)]
pub enum AuditEvent {
	/// A dynamic account was removed.
	AccountRemoved,
	/// A dynamic account's password (argon2id hash + SCRAM) was replaced.
	PasswordReset,
	/// A fresh TOTP secret was generated and stored for a dynamic account.
	TotpEnrolled,
	/// A dynamic account's TOTP secret was cleared (2FA disabled).
	TotpDisabled,
	/// A masked email address was minted for an account.
	MaskedCreated,
	/// A masked email address was disabled or re-enabled.
	MaskedUpdated,
	/// A masked email address was removed from an account.
	MaskedRemoved,
	/// A password-based authentication attempt (PLAIN, LOGIN, IMAP LOGIN,
	/// WebDAV Basic, ManageSieve PLAIN, the API's credential-verification
	/// endpoints) accepted the presented credentials and resolved an account.
	LoginSucceeded,
	/// The same attempt was rejected: the login was unknown, the account was
	/// disabled, the password did not match, an app-password CIDR did not
	/// admit the peer, or an LDAP bind failed.
	LoginFailed,
	/// A submission was refused because the account would exceed the
	/// rolling 24h cap on first-time recipients
	/// (`Config::new_recipients_per_day`). The fast-evolving exfiltration
	/// signal: a compromised account that stays under the per-minute rate
	/// limit but fans out to fresh addresses.
	SendLimited,
}

impl AuditEvent {
	/// The stable, dotted identifier written to the `event` field.
	fn as_str(self) -> &'static str {
		match self {
			AuditEvent::AccountRemoved => "account.removed",
			AuditEvent::PasswordReset => "account.password_reset",
			AuditEvent::TotpEnrolled => "account.totp_enrolled",
			AuditEvent::TotpDisabled => "account.totp_disabled",
			AuditEvent::MaskedCreated => "masked.created",
			AuditEvent::MaskedUpdated => "masked.updated",
			AuditEvent::MaskedRemoved => "masked.removed",
			AuditEvent::LoginSucceeded => "auth.login_succeeded",
			AuditEvent::LoginFailed => "auth.login_failed",
			AuditEvent::SendLimited => "send.new_recipients_limited",
		}
	}
}

/// Emit a structured audit event for a privileged API action.
///
/// `account` is the affected account name. `client_ip` is the source IP
/// extracted by `require_bearer_token` from the `ConnectInfo<SocketAddr>`
/// extension; in tests it is `None`, which is rendered as the literal
/// `unknown` so the field is always present and never null in operator
/// queries. Never logged: the TOTP secret, the password hash, the SCRAM
/// credentials, the plaintext password, and the bearer token.
pub fn log_privilege_change(event: AuditEvent, account: &str, client_ip: Option<IpAddr>) {
	let client_ip = client_ip
		.map(|ip| ip.to_string())
		.unwrap_or_else(|| "unknown".to_string());
	tracing::info!(
		target: "epistle::api::audit",
		event = event.as_str(),
		account = %account,
		client_ip = %client_ip,
		"privilege change"
	);
}

/// Emit a structured audit event for a submission refused because the
/// account would exceed the daily new-recipient cap. Carries the
/// numbers (count of new recipients, configured limit) so an operator
/// chasing an exfiltration signal can read them straight off the log
/// line without correlating with the metric counter.
///
/// `client_ip` follows the same `unknown` convention as
/// [`log_privilege_change`]. This is the only emitter in this module
/// that takes numeric fields, because it is the only one whose event
/// is data-shaped rather than action-shaped.
pub fn log_send_limited(account: &str, client_ip: Option<IpAddr>, count: u32, limit: u32) {
	let client_ip = client_ip
		.map(|ip| ip.to_string())
		.unwrap_or_else(|| "unknown".to_string());
	tracing::info!(
		target: "epistle::api::audit",
		event = AuditEvent::SendLimited.as_str(),
		account = %account,
		client_ip = %client_ip,
		count = count,
		limit = limit,
		"submission limited by daily new-recipient cap"
	);
}

/// Emit the per-record counts an account-removal call returned. Each
/// tally is a separate structured field on the same `epistle::api::audit`
/// event with `event = account.removed`, so an operator can filter on the
/// `mailbox_files`, `masked_addresses`, `app_passwords`,
/// `suppressed_addresses`, `correspondent_addresses`, `queued_discarded`
/// and `queued_left` fields directly: no second log line to correlate.
pub fn log_account_removal(
	account: &str,
	client_ip: Option<IpAddr>,
	counts: &crate::directory_store::Removed,
) {
	let client_ip = client_ip
		.map(|ip| ip.to_string())
		.unwrap_or_else(|| "unknown".to_string());
	tracing::info!(
		target: "epistle::api::audit",
		event = AuditEvent::AccountRemoved.as_str(),
		account = %account,
		client_ip = %client_ip,
		mailbox_files = counts.mailbox_files,
		masked_addresses = counts.masked_addresses,
		app_passwords = counts.app_passwords,
		suppressed_addresses = counts.suppressed_addresses,
		correspondent_addresses = counts.correspondent_addresses,
		queued_discarded = counts.queued_messages_discarded,
		queued_left = counts.queued_messages_left,
		"account removed with footprint cleared"
	);
}

/// Emit a structured audit event for a password-based authentication attempt
/// (PLAIN / LOGIN / IMAP LOGIN / WebDAV Basic / ManageSieve PLAIN / API
/// credential-verification). `login` is whatever the client presented as
/// the authcid — for a failed attempt that name may not resolve to any
/// account, in which case `account` is `None` and is rendered as `unknown`.
/// The plaintext password and the TOTP code (when the account has 2FA) are
/// never written to the log: only the result and the identifiers needed to
/// correlate one attempt with the next do. `client_ip` follows the same
/// `unknown` convention as [`log_privilege_change`]. `protocol` is the
/// authentication path the request reached the server through (SMTP
/// submission, IMAP, POP3, ManageSieve, the API, OAuth approval, WebDAV);
/// operators correlate per-protocol blocks, and a rejection on a path the
/// account never opted into is recorded as `auth.login_failed` like any
/// other failure.
pub fn log_auth_attempt(
	event: AuditEvent,
	login: &str,
	account: Option<&str>,
	client_ip: Option<IpAddr>,
	protocol: Protocol,
) {
	let client_ip = client_ip
		.map(|ip| ip.to_string())
		.unwrap_or_else(|| "unknown".to_string());
	let account = account.unwrap_or("unknown");
	tracing::info!(
		target: "epistle::auth",
		event = event.as_str(),
		login = %login,
		account = %account,
		client_ip = %client_ip,
		protocol = protocol.as_str(),
		"authentication attempt"
	);
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
