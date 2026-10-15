//! The IP warm-up as the queue applies it (see [`crate::queue::warmup`]).
//!
//! A conversation asks the warm-up how many of its recipients may go
//! before it says a word to the exchanger, whose host names the receiver
//! group. The ones granted go; the rest wait for the cap of their group
//! until the warm-up says it opens. Waiting is not an attempt, not a
//! failure and not a deferral: nothing is counted or logged for it, and the
//! wait does not use up the give-up window. Recipients granted and never
//! offered to the remote (a connection that failed before any reply) are
//! given back, so a destination that does not answer cannot use up the cap.
//!
//! Between conversations, a recipient waiting for the cap is left out of
//! the scan while its group is still closed to its sender, and woken early
//! once it opens: an operator raise, the next unit of the day, or the
//! warm-up turned off.

use std::collections::HashSet;
use std::sync::Arc;

use super::Worker;
use super::attempt::Route;
use super::conversation::Conversation;
use super::waiting::Sender;
use crate::queue::client::DeliveryError;
use crate::queue::warmup::{Grant, Group, Warmup};
use crate::storage::{Envelope, RecipientState};

/// Recipients a conversation left waiting for the cap of their group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Capped {
	/// The group whose cap they wait for.
	pub(super) group: Group,
	/// When they may be tried again (epoch seconds).
	pub(super) until: u64,
	/// Who waits.
	pub(super) recipients: Vec<String>,
}

/// The reason kept with a recipient that waits for the cap.
fn reason(group: Group) -> DeliveryError {
	DeliveryError::Transient(format!("waiting for the {group} warm-up cap"))
}

/// Whether a stored reason is a remote reply (`421 ...`) rather than a
/// local error with no reply at all.
fn is_reply(reason: &str) -> bool {
	reason
		.get(..3)
		.is_some_and(|head| head.bytes().all(|byte| byte.is_ascii_digit()))
		&& matches!(reason.as_bytes().get(3), None | Some(b' ' | b'-'))
}

impl Conversation {
	/// Every one of `recipients` waits for the cap of `group` until `until`.
	pub(super) fn capped(recipients: &[String], group: Group, until: u64) -> Self {
		let mut conversation = Conversation::all(&[], None, reason(group));
		conversation.add_capped(recipients, group, until);
		conversation
	}

	/// Add `recipients` as waiting for the cap of `group` until `until`.
	pub(super) fn add_capped(&mut self, recipients: &[String], group: Group, until: u64) {
		if recipients.is_empty() {
			return;
		}
		for recipient in recipients {
			self.results.push((recipient.clone(), Err(reason(group))));
		}
		self.capped = Some(Capped {
			group,
			until,
			recipients: recipients.to_vec(),
		});
	}

	/// The cap `recipient` waits for, when this conversation left it waiting.
	pub(super) fn capped_for(&self, recipient: &str) -> Option<&Capped> {
		self.capped
			.as_ref()
			.filter(|capped| capped.recipients.iter().any(|other| other == recipient))
	}
}

impl Worker {
	/// Apply the IP warm-up to direct delivery. A configured smarthost
	/// sends from its own address and is not capped.
	pub fn with_warmup(mut self, warmup: Arc<Warmup>) -> Self {
		self.warmup = Some(warmup);
		self
	}

	/// The group of `host` and when its cap opens for the sender of
	/// `envelope`, while it is closed. Takes nothing.
	pub(super) fn host_closed(
		&self,
		envelope: &Envelope,
		host: &str,
		now: u64,
	) -> Option<(Group, u64)> {
		let warmup = self.warmup.as_ref()?;
		let group = Group::of_exchanger(host);
		warmup
			.blocked(group, Sender::of(envelope).as_str(), now)
			.map(|until| (group, until))
	}

	/// How many of the route's recipients may go to `host` now, with its
	/// group and when the rest may; `None` when no cap applies.
	pub(super) fn admit(
		&self,
		route: &Route<'_>,
		host: &str,
		now: u64,
	) -> Option<(Group, usize, u64)> {
		let warmup = self.warmup.as_ref()?;
		let group = Group::of_exchanger(host);
		let sender = Sender::of(&route.entry.envelope);
		match warmup.grant(group, sender.as_str(), route.recipients.len(), now) {
			Grant::Unlimited => None,
			Grant::Limited { granted, until } => Some((group, granted, until)),
		}
	}

	/// Give back the granted recipients `conversation` never offered to the
	/// remote: those answered with a local error rather than a reply.
	pub(super) fn give_back_unoffered(
		&self,
		envelope: &Envelope,
		group: Group,
		conversation: &Conversation,
		now: u64,
	) {
		let Some(warmup) = &self.warmup else {
			return;
		};
		let unoffered = conversation
			.results
			.iter()
			.filter(
				|(_, result)| matches!(result, Err(DeliveryError::Transient(reason)) if !is_reply(reason)),
			)
			.count();
		warmup.give_back(group, Sender::of(envelope).as_str(), unoffered, now);
	}

	/// When the cap a waiting recipient waits for opens for `sender`, while
	/// it is closed; `None` when it is open, gone, or the recipient does not
	/// wait for one.
	fn cap_closed(&self, state: &RecipientState, sender: &Sender, now: u64) -> Option<u64> {
		let warmup = self.warmup.as_ref()?;
		let group = Group::parse(state.warmup.as_deref()?)?;
		warmup.blocked(group, sender.as_str(), now)
	}

	/// The pending recipients of `envelope` to try at `now`: those due, and
	/// those waiting for a cap that has opened, less those waiting for a cap
	/// still closed.
	pub(super) fn due_now(&self, envelope: &Envelope, now: u64) -> Vec<String> {
		let sender = Sender::of(envelope);
		let due: HashSet<String> = envelope.due(now).into_iter().collect();
		envelope
			.pending()
			.into_iter()
			.filter(|recipient| {
				let state = envelope.recipient_state(recipient);
				match state.warmup {
					Some(_) => self.cap_closed(&state, &sender, now).is_none(),
					None => due.contains(recipient),
				}
			})
			.collect()
	}

	/// Whether `envelope` has a recipient to look at now: one due, or one
	/// waiting for a cap that has opened before its retry time.
	pub(super) fn wakes(&self, envelope: &Envelope, now: u64) -> bool {
		if envelope.next_attempt <= now {
			return true;
		}
		let sender = Sender::of(envelope);
		envelope.pending().iter().any(|recipient| {
			let state = envelope.recipient_state(recipient);
			state.warmup.is_some() && self.cap_closed(&state, &sender, now).is_none()
		})
	}

	/// The group every one of `recipients` waits for, when they all wait for
	/// the same one.
	pub(super) fn waiting_group(envelope: &Envelope, recipients: &[String]) -> Option<Group> {
		let mut groups = recipients.iter().map(|recipient| {
			envelope
				.recipient_state(recipient)
				.warmup
				.as_deref()
				.and_then(Group::parse)
		});
		let first = groups.next()??;
		groups.all(|group| group == Some(first)).then_some(first)
	}

	/// Whether a job for `group` would find its cap closed to `sender`.
	pub(super) fn job_capped(&self, group: Option<Group>, sender: &Sender, now: u64) -> bool {
		match (&self.warmup, group) {
			(Some(warmup), Some(group)) => warmup.blocked(group, sender.as_str(), now).is_some(),
			_ => false,
		}
	}

	/// The seconds of the give-up window `recipient` of entry `id` has used
	/// at `now`: the message's age, less the time an operator held it and
	/// the time the recipient waited for the warm-up cap.
	pub(super) fn window_used(
		&self,
		id: uuid::Uuid,
		envelope: &Envelope,
		recipient: &str,
		now: u64,
	) -> u64 {
		self.message_age(id, now)
			.saturating_sub(envelope.held_secs)
			.saturating_sub(envelope.recipient_state(recipient).warmup_wait(now))
	}
}

#[cfg(test)]
#[path = "worker_tests_warmup.rs"]
mod tests;
