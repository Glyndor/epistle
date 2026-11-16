//! What a scope asks of the three checks that only annotate by default:
//! DKIM, ARC and the reverse DNS of the connecting address (RFC 7372,
//! RFC 8617). The resolution is in [`crate::antispam::scopes`].

use serde::Deserialize;

/// What a check does with the message it evaluates.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum CheckPolicy {
	/// The check is not run for this scope, and its result is not written
	/// to `Authentication-Results`. DKIM is the exception that DMARC needs:
	/// it is always evaluated, and `off` leaves its result as it is today.
	Off,
	/// The result is recorded in `Authentication-Results` and never refuses
	/// the message.
	#[default]
	Annotate,
	/// A failed check refuses the message with the status of RFC 7372 or
	/// RFC 8617; a temporary DNS error defers it (`4xx`), never refuses it.
	Reject,
}

/// The `[antispam_scope.checks]` table: absent keys keep the next wider
/// scope's value, and the server's own when no scope sets one.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CheckScope {
	/// DKIM: `reject` refuses a message whose signatures all fail
	/// (`550 5.7.21`). A sender with no signature, or with a signature for
	/// a key its domain does not publish, is never refused unless
	/// `dkim_require_signature` says so. Server default: `annotate`.
	pub dkim: Option<CheckPolicy>,
	/// With `dkim = "reject"`, also refuse a message that carries no DKIM
	/// signature that passes (`550 5.7.20`), including mail from a domain
	/// that publishes no DKIM key. Server default: `false`.
	pub dkim_require_signature: Option<bool>,
	/// ARC (RFC 8617): `annotate` writes `arc=` into
	/// `Authentication-Results`, `reject` refuses a broken chain
	/// (`550 5.7.29`). A message with no ARC chain is never refused.
	/// Server default: `off`, which is what the server does today.
	pub arc: Option<CheckPolicy>,
	/// Reverse DNS of the connecting address: `annotate` writes `iprev=`
	/// into `Authentication-Results`, `reject` refuses an address whose PTR
	/// is missing or does not resolve back to it (`550 5.7.25`). Server
	/// default: `off`, which is what the server does today.
	pub reverse_dns: Option<CheckPolicy>,
}

impl CheckScope {
	/// Whether the scope sets nothing.
	pub fn is_empty(&self) -> bool {
		*self == Self::default()
	}
}
