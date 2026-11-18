//! The `[smtp]` section: what a refusal tells a sender that has not
//! authenticated, the networks whose mail skips the sender screens and the
//! answer for a full mailbox.

use serde::Deserialize;

mod trusted;
use trusted::trusted_networks;

/// How much the text of a refusal tells a stranger. The enhanced status
/// code and the permanent or temporary class of a refusal are the same at
/// every level: only the words change.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RefusalDetail {
	/// The least a stranger can learn: the enhanced code and a generic
	/// sentence that names no check, list, policy or limit.
	Terse,
	/// What a refusal said before this setting existed.
	#[default]
	Standard,
	/// The actionable detail: what to fix for an SPF, DMARC or blocklist
	/// refusal, the figure of a limit and the time to retry at.
	Verbose,
}

/// How a full mailbox is refused, at `RCPT TO` and again once the message
/// is complete, so the two stages always agree.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MailboxFull {
	/// `452 4.2.2`: the sender retries until the owner makes room, as
	/// RFC 3463 describes a full mailbox. What the server answered before
	/// this setting existed.
	#[default]
	Temporary,
	/// `552 5.2.2`: the sender gets a bounce at once, for an operator who
	/// would rather tell the sender than let a message wait days in its
	/// queue.
	Permanent,
}

/// The `[smtp]` section.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Smtp {
	/// How much a refusal sent to a sender that has not authenticated tells it.
	#[serde(default)]
	pub reject_detail: RefusalDetail,
	/// Whether a final refusal carries a short reference the sender can
	/// quote and the log line of the same refusal repeats.
	#[serde(default = "default_reference")]
	pub reject_reference: bool,
	/// Networks whose peers are the operator's own relays (a secondary MX,
	/// an internal gateway). Mail from them skips the checks that judge the
	/// connecting address, which a relay would always fail: the DNS
	/// blocklist screen of the client address, greylisting, the first-time
	/// sender delay, SPF, DKIM and DMARC. It is never marked as verified,
	/// so no allow list favours it, and the virus scan, the attachment
	/// policy, the Bayesian thresholds and the size limits still apply.
	/// Empty (the default) trusts nobody. Each entry needs a prefix length,
	/// an IPv4 prefix of at least 8 bits and an IPv6 one of at least 32,
	/// and at most 256 are listed.
	#[serde(default, deserialize_with = "trusted_networks")]
	pub trusted_networks: Vec<crate::cidr::Cidr>,
	/// How a full mailbox is refused: `temporary` (`452`, the default) or
	/// `permanent` (`552`).
	#[serde(default)]
	pub mailbox_full: MailboxFull,
}

fn default_reference() -> bool {
	true
}

impl Default for Smtp {
	fn default() -> Self {
		Self {
			reject_detail: RefusalDetail::default(),
			reject_reference: default_reference(),
			trusted_networks: Vec::new(),
			mailbox_full: MailboxFull::default(),
		}
	}
}

#[cfg(test)]
mod tests;
