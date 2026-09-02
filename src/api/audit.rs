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
