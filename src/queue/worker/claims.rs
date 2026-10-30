//! The recipients in conversation and the conversation slots in use, in
//! one worker, and the guard that keeps a panicking conversation from
//! taking the worker down with it.
//!
//! Everything here is sized by what is in conversation right now, never by
//! the spool: a claim is released when its conversation ends, is dropped,
//! or panics, and a domain with no conversation left has no entry.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

use uuid::Uuid;

use crate::queue::limits::Limits;

/// The recipients in conversation and the slots in use, in this worker.
#[derive(Default)]
pub(super) struct Claims {
	state: Mutex<ClaimState>,
}

#[derive(Default)]
struct ClaimState {
	/// Claimed recipients, by entry. An entry with none has no key.
	recipients: HashMap<Uuid, HashSet<String>>,
	/// Conversations running per recipient domain. A domain with none has
	/// no key.
	domains: HashMap<String, usize>,
	/// Conversations running per sender. A sender with none has no key.
	senders: HashMap<String, usize>,
	running: usize,
}

/// Which cap kept a conversation from starting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Full {
	/// Every slot is in use.
	Total,
	/// The recipient domain has its share.
	Domain,
	/// The sender has its share.
	Sender,
}

/// Count one more conversation under `key`.
fn count_in(counts: &mut HashMap<String, usize>, key: &str) {
	*counts.entry(key.to_string()).or_default() += 1;
}

/// Count one conversation less under `key`, forgetting it at zero.
fn count_out(counts: &mut HashMap<String, usize>, key: &str) {
	if let Some(count) = counts.get_mut(key) {
		*count = count.saturating_sub(1);
		if *count == 0 {
			counts.remove(key);
		}
	}
}

/// Recipients of one entry claimed for one conversation, and its slot.
/// Dropping it releases both.
pub(super) struct Claim<'a> {
	claims: &'a Claims,
	id: Uuid,
	domain: String,
	sender: String,
	pub(super) recipients: Vec<String>,
}

impl Claims {
	fn state(&self) -> std::sync::MutexGuard<'_, ClaimState> {
		self.state
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// Whether `recipient` of entry `id` is in a conversation.
	pub(super) fn holds(&self, id: Uuid, recipient: &str) -> bool {
		self.state()
			.recipients
			.get(&id)
			.is_some_and(|held| held.contains(recipient))
	}

	/// Whether any recipient of entry `id` is in a conversation.
	pub(super) fn holds_any(&self, id: Uuid) -> bool {
		self.state().recipients.contains_key(&id)
	}

	/// Whether a conversation can start at all under `limits`.
	pub(super) fn has_room(&self, limits: Limits) -> bool {
		self.state().running < limits.total
	}

	/// Take a slot for a conversation of `sender` with `domain`, and claim
	/// those of `recipients` nobody holds. The cap that is full when no
	/// slot is free; the claim may hold no recipient.
	pub(super) fn take(
		&self,
		limits: Limits,
		id: Uuid,
		(domain, sender): (&str, &str),
		recipients: &[String],
	) -> Result<Claim<'_>, Full> {
		let mut state = self.state();
		if state.running >= limits.total {
			return Err(Full::Total);
		}
		if state.domains.get(domain).copied().unwrap_or(0) >= limits.per_domain {
			return Err(Full::Domain);
		}
		if state.senders.get(sender).copied().unwrap_or(0) >= limits.per_sender() {
			return Err(Full::Sender);
		}
		let held = state.recipients.entry(id).or_default();
		let free: Vec<String> = recipients
			.iter()
			.filter(|recipient| held.insert((*recipient).clone()))
			.cloned()
			.collect();
		if held.is_empty() {
			state.recipients.remove(&id);
		}
		state.running += 1;
		count_in(&mut state.domains, domain);
		count_in(&mut state.senders, sender);
		Ok(Claim {
			claims: self,
			id,
			domain: domain.to_string(),
			sender: sender.to_string(),
			recipients: free,
		})
	}
}

impl Drop for Claim<'_> {
	fn drop(&mut self) {
		let mut state = self.claims.state();
		if let Some(held) = state.recipients.get_mut(&self.id) {
			for recipient in &self.recipients {
				held.remove(recipient);
			}
			if held.is_empty() {
				state.recipients.remove(&self.id);
			}
		}
		state.running = state.running.saturating_sub(1);
		count_out(&mut state.domains, &self.domain);
		count_out(&mut state.senders, &self.sender);
	}
}

/// A conversation that cannot unwind past itself: a panic inside it ends
/// it with `Err(())`, and whatever it held (its claim, its connection) is
/// dropped then, so the worker keeps running and the slot is free again.
pub(super) struct Guarded<F>(pub(super) Pin<Box<F>>);

impl<F: Future> Future for Guarded<F> {
	type Output = Result<F::Output, ()>;

	fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
		let inner = self.0.as_mut();
		match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.poll(context))) {
			Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
			Ok(Poll::Pending) => Poll::Pending,
			Err(_) => Poll::Ready(Err(())),
		}
	}
}
