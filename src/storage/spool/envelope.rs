//! The envelope stored, sealed, next to each spooled message.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::recipients::RecipientState;

/// Envelope metadata stored next to the raw message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
	/// Spool id (UUID v7: time-ordered).
	pub id: Uuid,
	/// SMTP reverse-path (empty for bounces).
	pub reverse_path: String,
	/// Accepted recipients.
	pub recipients: Vec<String>,
	/// Failed delivery attempts so far.
	#[serde(default)]
	pub attempts: u32,
	/// Epoch seconds before which delivery must not be retried.
	#[serde(default)]
	pub next_attempt: u64,
	/// REQUIRETLS (RFC 8689): onward delivery must use verified TLS.
	#[serde(default)]
	pub require_tls: bool,
	/// Recipients that suppress failure DSNs (`NOTIFY=NEVER`, RFC 3461).
	#[serde(default)]
	pub no_dsn: Vec<String>,
	/// Whether the "delivery delayed" warning DSN has already been sent, so it
	/// is sent at most once (RFC 5321 §4.5.4.1).
	#[serde(default)]
	pub delay_warned: bool,
	/// Epoch seconds at which an operator put the entry on hold. A held entry
	/// is never attempted until released. `None` for an entry in the normal
	/// flow, which is also how every spool file written before this field
	/// existed loads.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub held: Option<u64>,
	/// Seconds the entry has spent on hold in earlier hold/release cycles. The
	/// give-up window counts message age minus this, so a message an operator
	/// parked for a week is not bounced on its first attempt after release.
	#[serde(default, skip_serializing_if = "is_zero")]
	pub held_secs: u64,
	/// Reason the most recent delivery attempt failed, for `queue show`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub last_error: Option<String>,
	/// Delivery state per recipient (see [`RecipientState`]). Empty in every
	/// envelope written before it existed, which reads as all pending.
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub recipient_state: BTreeMap<String, RecipientState>,
	/// The local account that submitted the message, when the submission went
	/// through one of this server's submission paths (SMTP after AUTH, the
	/// API, JMAP). `None` when the sender is an external relay or the entry
	/// was written before this field existed, which the delivery log records
	/// as "submitted by an unknown account".
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub account: Option<String>,
	/// The caller-supplied correlation map the API allows on a `send`. Kept
	/// alongside the message in the envelope so the delivery log and the
	/// delivery webhooks can copy it onto every record they emit, but never
	/// written into the message itself (the field is a server-side tag, not
	/// a header). Empty in every envelope written before this field existed.
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub extra: BTreeMap<String, String>,
	/// The class the server granted the submission. Written by the server,
	/// never by the client; `personal` for every envelope written before the
	/// field existed and for mail that arrived from elsewhere.
	#[serde(default, skip_serializing_if = "is_personal")]
	pub class: crate::evidence::MailClass,
	/// Whether an evidence acceptance record is written for this entry, so
	/// its outcomes are recorded too and a crash before it was queued leaves
	/// an `abandoned` record.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub evidence: bool,
	/// Days the acceptance is kept, which its outcomes inherit, whatever the
	/// policy says by the time they arrive. `0` in an envelope written before
	/// the field existed, whose outcomes follow the policy.
	#[serde(default, skip_serializing_if = "is_zero_days")]
	pub retain_days: u32,
	/// Outcomes of recipients that were delivered, bounced or expired but
	/// could not be written to the evidence log. The entry stays in the queue
	/// until each is written, and is not sent again meanwhile.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub outcomes_pending: Vec<PendingOutcome>,
	/// Epoch seconds at which an operator's removal of the entry began and did
	/// not finish: the entry is on hold, and the removal records only the
	/// cancellations the evidence log does not already hold from that day on.
	/// Not the hold of the operator, which can be as old as they like.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cancelling: Option<u64>,
}

/// An outcome the evidence log has not taken yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOutcome {
	/// The recipient.
	pub recipient: String,
	/// What happened.
	pub result: crate::evidence::record::OutcomeKind,
	/// The attempt that produced it.
	pub attempt: u32,
	/// The receiving server, when one answered.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub remote: Option<String>,
	/// Its reply, or the reason.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub reply: Option<String>,
	/// The TLS version and cipher, when there was a session.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub tls: Option<(String, String)>,
	/// Whether DANE authenticated the server.
	#[serde(default)]
	pub dane: bool,
	/// The MTA-STS mode of the recipient domain.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mta_sts: Option<String>,
}

fn is_personal(class: &crate::evidence::MailClass) -> bool {
	*class == crate::evidence::MailClass::Personal
}

fn is_zero_days(value: &u32) -> bool {
	*value == 0
}

fn is_zero(value: &u64) -> bool {
	*value == 0
}

/// Longest `last_error` kept in the envelope: remote replies can be long and
/// the field is for an operator's eyes only.
pub(super) const LAST_ERROR_MAX: usize = 512;

impl Envelope {
	/// Put the entry on hold as of `now`. Holding an entry that is already
	/// held keeps the original start so the held time is not shortened.
	pub fn hold(&mut self, now: u64) {
		if self.held.is_none() {
			self.held = Some(now);
		}
	}

	/// Release a held entry as of `now`, folding the time spent on hold into
	/// [`Envelope::held_secs`]. A no-op for an entry that is not held.
	pub fn release(&mut self, now: u64) {
		if let Some(since) = self.held.take() {
			self.held_secs = self.held_secs.saturating_add(now.saturating_sub(since));
		}
	}
}
