//! The `[[antispam_scope]]` entries: antispam settings for one tenant,
//! domain or account, resolved on top of the server-wide sections.
//!
//! An entry names exactly one target with `tenant`, `domain` or `account`.
//! Most specific wins for a number, lists add up, and a deny anywhere is a
//! deny everywhere; the resolution is in [`crate::antispam::scopes`] and the
//! rules are written in `docs/configuration.md`. A scope may only tighten
//! what the server-wide sections already require: it cannot allow an
//! attachment the server blocks, nor lower a mode, an action or a size cap
//! the server sets, and the load refuses an entry that tries.

use serde::Deserialize;

use super::{AttachmentMode, Config, ContentAction};

mod checks;
mod validate;

pub use checks::{CheckPolicy, CheckScope};

/// Sender and recipient lists of one scope. See
/// [`crate::antispam::sender_lists`] for the entry shapes.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SenderLists {
	/// Envelope senders whose mail skips the score-based screens (the
	/// Bayesian thresholds, the uncertain band and the reputation screen)
	/// when this server verified them itself: SPF passed for the sender's
	/// domain, or a DKIM signature of the same organization did, and the
	/// `From` domain is the sender's organization. Never overrides SPF,
	/// DMARC, DNS blocklists, greylisting, the virus scanner or the
	/// attachment policy.
	pub allow: Vec<String>,
	/// Envelope senders refused at `RCPT TO` with `550 5.7.1`, whatever the
	/// session authenticated. Wins over every allow entry at every scope.
	pub deny: Vec<String>,
	/// Recipients an authenticated account may not send to, refused at
	/// `RCPT TO` with `550 5.7.1`. Unlike `[[transport]] kind = "fail"`,
	/// `*.example.com` covers subdomains and the refusal is immediate, not a
	/// bounce from the queue.
	pub deny_recipients: Vec<String>,
}

impl SenderLists {
	/// Whether no list has an entry.
	pub fn is_empty(&self) -> bool {
		self.allow.is_empty() && self.deny.is_empty() && self.deny_recipients.is_empty()
	}
}

/// What a scope adds to the `[attachments]` policy. Every field only
/// tightens: there is no way to allow what the server blocks.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AttachmentScope {
	/// A stronger action than the server's, for every finding. Absent keeps
	/// the server's.
	pub mode: Option<AttachmentMode>,
	/// Extensions treated as dangerous for this scope, without the dot, on
	/// top of the server's list.
	pub block_extensions: Vec<String>,
	/// Declared MIME types (`application/pdf`, or `image/*` for a whole
	/// family) that count as a finding for this scope.
	pub block_mime_types: Vec<String>,
	/// Largest single attachment, in bytes after decoding. Absent keeps the
	/// server's cap, if any.
	pub max_attachment_bytes: Option<u64>,
	/// A stronger action for macros than the server's.
	pub macros: Option<ContentAction>,
	/// A stronger action for encrypted archives than the server's.
	pub encrypted_archives: Option<ContentAction>,
}

impl AttachmentScope {
	/// Whether the scope sets nothing.
	pub fn is_empty(&self) -> bool {
		*self == Self::default()
	}
}

/// One `[[antispam_scope]]` entry.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AntispamScope {
	/// The `name` of a `[[tenant]]`: every domain of the tenant.
	pub tenant: Option<String>,
	/// A hosted domain, which must also be in `domains`.
	pub domain: Option<String>,
	/// An account name, from any source (configuration file, API,
	/// directory). Not checked against a list: an unknown name has no
	/// effect.
	pub account: Option<String>,
	/// Sender and recipient lists.
	pub senders: SenderLists,
	/// Attachment tightening.
	pub attachments: AttachmentScope,
	/// `bayes_junk_at` for the mail of this scope. Absent keeps the
	/// next wider scope's value.
	pub bayes_junk_at: Option<f64>,
	/// `bayes_reject_at` for the mail of this scope. Absent keeps the next
	/// wider scope's value, which may be none.
	pub bayes_reject_at: Option<f64>,
	/// Greylisting for the mail of this scope, in seconds: `0` turns it off
	/// here, a number turns it on or changes the delay, even when the
	/// server does not greylist. Absent keeps the next wider scope's value.
	pub greylist_delay_secs: Option<u64>,
	/// The delay of a sender this server has never seen, in seconds (see
	/// the top-level `first_time_sender_delay_secs`), at most 300. It needs
	/// `[database]`, as the server-wide one does. Absent keeps the next wider
	/// scope's value.
	pub first_time_sender_delay_secs: Option<u64>,
	/// Whether the DKIM, ARC and reverse-DNS checks of the mail of this
	/// scope only annotate or refuse. Absent keys keep the next wider
	/// scope's value.
	pub checks: CheckScope,
}

/// Longest first-time delay a scope may set: the connection waits it out.
pub const MAX_FIRST_TIME_DELAY_SECS: u64 = 300;
/// Longest greylist delay a scope may set: a day, the life of a triplet.
pub const MAX_GREYLIST_DELAY_SECS: u64 = 86_400;

impl Config {
	/// Whether greylisting is on anywhere: the server-wide delay, or the
	/// delay of any scope. The store is built when it is.
	pub fn greylisting_anywhere(&self) -> bool {
		self.greylist_delay_secs > 0
			|| self
				.antispam_scopes
				.iter()
				.any(|scope| scope.greylist_delay_secs.is_some_and(|delay| delay > 0))
	}
}

#[cfg(test)]
mod tests;
