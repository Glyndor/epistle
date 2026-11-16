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

use super::{AttachmentMode, ContentAction};

mod validate;

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
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
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
}

#[cfg(test)]
mod tests;
