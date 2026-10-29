//! The INFO lines an SMTP session writes at the default level.
//!
//! Two facts about a session were invisible in the log: a message the
//! server accepted (an operator could not tell from the log whether mail
//! had arrived at all) and an authentication attempt on a mechanism that
//! does not go through the password audit (SCRAM, OAuth and SASL
//! EXTERNAL). Both are written here, in one shape: the account the line
//! is about as its log pseudonym (`log_id`), the protocol that carried
//! it and the outcome.
//!
//! No address and no account name reach the log. The pseudonym is an
//! HMAC under the per-server key (`crate::log_id`), and the operator
//! maps it back with `epistle account find-log-id`.
//!
//! The password path (SASL PLAIN, AUTH LOGIN) is not repeated here: it
//! writes the audit channel `epistle::auth` (`src/api/audit/mod.rs`), which
//! carries the same facts.

/// The value a line carries when the account it is about is not known.
///
/// A refused authentication never names the account it tried to be: the
/// wire answer is the same for an unknown login and a wrong password,
/// and the log must not be the place that tells the two apart.
pub const UNKNOWN: &str = "unknown";

/// The outcome of an authentication that succeeded.
pub const SUCCEEDED: &str = "succeeded";

/// The outcome of an authentication that was refused.
pub const FAILED: &str = "failed";

/// What the line about an accepted message carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
	/// The recipient account's log pseudonym, or [`UNKNOWN`] when the
	/// recipient does not resolve to a local account.
	pub log_id: String,
	/// The octets of the message as it is delivered.
	pub size: u64,
	/// How many recipients the envelope named.
	pub recipients: u64,
}

/// Record one accepted inbound message.
///
/// The message is the fact the operator cannot see anywhere else: the
/// Maildir shows it afterwards and the metrics show a counter, but
/// nothing in the log said that the server took it.
pub fn accepted(record: &Accepted) {
	tracing::info!(
		log_id = %record.log_id,
		size = record.size,
		protocol = "smtp",
		recipients = record.recipients,
		result = "accepted",
		"message accepted"
	);
}

/// Record one authentication attempt on an SMTP session.
///
/// `mechanism` names the SASL mechanism, `result` the outcome and
/// `failures` how many attempts this session has already failed.
pub fn authentication(log_id: &str, protocol: &str, mechanism: &str, result: &str, failures: u8) {
	tracing::info!(
		log_id = %log_id,
		protocol = %protocol,
		mechanism = %mechanism,
		result = %result,
		failures = failures,
		"authentication attempt"
	);
}
