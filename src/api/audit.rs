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

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
