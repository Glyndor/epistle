//! Per-recipient delivery state of a spooled message.
//!
//! One message can go to several recipients in several domains, and each of
//! them gets its own answer: one is accepted, another is refused, a third
//! domain is down. The envelope records, per recipient, whether it was
//! delivered, failed for good, or is still pending with its own retry
//! schedule, so a retry only addresses the recipients still pending.
//!
//! The map is absent from every envelope written before it existed; such an
//! entry reads as every recipient pending, with the entry-wide attempt count
//! and retry time it already had.

use serde::{Deserialize, Serialize};

use super::spool::Envelope;

/// Where one recipient stands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientStatus {
	/// Not delivered yet; it is attempted again once its retry time comes.
	#[default]
	Pending,
	/// A remote server accepted the message for this recipient.
	Delivered,
	/// Delivery failed for good (a permanent refusal, or the message expired).
	Failed,
}

/// The delivery state of one recipient.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientState {
	/// Pending, delivered or failed.
	#[serde(default)]
	pub status: RecipientStatus,
	/// Attempts that ended without a final answer for this recipient.
	#[serde(default)]
	pub attempts: u32,
	/// Epoch seconds before which this recipient is not attempted again.
	#[serde(default)]
	pub next_attempt: u64,
	/// The last answer that was not a success: the remote reply, or the local
	/// reason the attempt could not happen.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub last_error: Option<String>,
	/// The host that gave that answer, when a server answered.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub remote: Option<String>,
	/// Whether it failed because the message expired in the queue, rather
	/// than being refused.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub expired: bool,
	/// Whether the failure report (DSN) covering this recipient has been
	/// sent, or deliberately skipped, so it goes out once.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub reported: bool,
	/// Deferrals in a row in which the destination asked the queue to slow
	/// down (see [`crate::queue::backoff`]). It picks the next backoff step
	/// and holds the destination while the recipient waits; any other
	/// answer sets it back to zero.
	#[serde(default, skip_serializing_if = "is_zero")]
	pub throttled: u32,
}

fn is_zero(value: &u32) -> bool {
	*value == 0
}

impl Envelope {
	/// The state of `recipient`. A recipient the map does not know yet is
	/// pending and inherits the entry-wide retry fields.
	pub fn recipient_state(&self, recipient: &str) -> RecipientState {
		self.recipient_state
			.get(recipient)
			.cloned()
			.unwrap_or(RecipientState {
				attempts: self.attempts,
				next_attempt: self.next_attempt,
				..RecipientState::default()
			})
	}

	/// Replace the state of `recipient`. The first write gives every
	/// recipient its own entry, inherited from the entry-wide fields, so a
	/// later change to those fields (see [`Envelope::settle`]) does not leak
	/// into recipients that were never attempted.
	pub fn set_recipient_state(&mut self, recipient: &str, state: RecipientState) {
		if self.recipient_state.is_empty() {
			for other in self.recipients.clone() {
				let inherited = self.recipient_state(&other);
				self.recipient_state.insert(other, inherited);
			}
		}
		self.recipient_state.insert(recipient.to_string(), state);
	}

	/// The recipients in `status`, in envelope order.
	pub fn recipients_in(&self, status: RecipientStatus) -> Vec<String> {
		self.recipients
			.iter()
			.filter(|recipient| self.recipient_state(recipient).status == status)
			.cloned()
			.collect()
	}

	/// The recipients still waiting for delivery, in envelope order.
	pub fn pending(&self) -> Vec<String> {
		self.recipients_in(RecipientStatus::Pending)
	}

	/// The pending recipients due at `now`. The entry-wide `next_attempt` is
	/// kept at the earliest pending retry time, so when it is earlier than
	/// that, someone pulled the entry forward (`epistle queue retry`) and
	/// every pending recipient is due.
	pub fn due(&self, now: u64) -> Vec<String> {
		let pending = self.pending();
		let earliest = pending
			.iter()
			.map(|recipient| self.recipient_state(recipient).next_attempt)
			.min()
			.unwrap_or(0);
		let forced = self.next_attempt < earliest;
		pending
			.into_iter()
			.filter(|recipient| forced || self.recipient_state(recipient).next_attempt <= now)
			.collect()
	}

	/// Bring the entry-wide retry fields in line with the per-recipient ones:
	/// the attempt count is the highest of any recipient, and the next attempt
	/// the earliest of the pending ones.
	pub fn settle(&mut self) {
		let states: Vec<RecipientState> = self
			.recipients
			.iter()
			.map(|recipient| self.recipient_state(recipient))
			.collect();
		if let Some(attempts) = states.iter().map(|state| state.attempts).max() {
			self.attempts = self.attempts.max(attempts);
		}
		if let Some(next) = states
			.iter()
			.filter(|state| state.status == RecipientStatus::Pending)
			.map(|state| state.next_attempt)
			.min()
		{
			self.next_attempt = next;
		}
	}
}

#[cfg(test)]
#[path = "spool_recipients_tests.rs"]
mod tests;
