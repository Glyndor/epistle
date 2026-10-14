//! Reading and recording the holds of destinations that asked the queue
//! to slow down, failing closed: holds that cannot be read stop the queue
//! from starting anything, and a hold that cannot be written is kept in
//! memory, applied, and written again at the next read.

use super::Worker;
use super::conversation::Conversation;
use super::waiting::Job;
use crate::queue::backoff;
use crate::storage::DestinationHolds;
use std::collections::HashSet;

/// Add to `into` every hold of `from` that holds longer than the one
/// `into` has under the same key.
fn merge(into: &mut DestinationHolds, from: &DestinationHolds) {
	for (key, hold) in from {
		if into.get(key).is_none_or(|known| known.until < hold.until) {
			into.insert(key.clone(), hold.clone());
		}
	}
}

impl Worker {
	/// The holds in force: those stored, plus any that could not be
	/// written yet. `None` when the stored ones cannot be read, and then
	/// nothing may be sent.
	pub(super) fn holds(&self) -> Option<DestinationHolds> {
		let mut holds = match self.spool.load_holds() {
			Ok(holds) => holds,
			Err(error) => {
				tracing::error!(%error, "cannot read destination holds; sending nothing until they can be read");
				return None;
			}
		};
		let mut unwritten = self.unwritten_holds();
		if !unwritten.is_empty() {
			match self.spool.update_holds(|stored| merge(stored, &unwritten)) {
				Ok(stored) => {
					unwritten.clear();
					holds = stored;
				}
				Err(_) => merge(&mut holds, &unwritten),
			}
		}
		Some(holds)
	}

	fn unwritten_holds(&self) -> std::sync::MutexGuard<'_, DestinationHolds> {
		self.unwritten_holds
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// Forget the holds that ran out and have nothing left to slow down
	/// ([`backoff::prune_idle`]); `queued` names the domains mail waits
	/// for. Writes only when one goes.
	pub(super) fn prune_holds(&self, holds: &DestinationHolds, queued: &HashSet<String>, now: u64) {
		let idle = |key: &str| !key.starts_with("mx:") && !queued.contains(key);
		if !holds
			.iter()
			.any(|(key, hold)| !hold.active(now) && idle(key))
		{
			return;
		}
		let pruned = self.spool.update_holds(|holds| {
			backoff::prune_idle(holds, |key| queued.contains(key), now);
		});
		if let Err(error) = pruned {
			tracing::warn!(%error, "cannot forget idle destination holds");
		}
	}

	/// Hold off the job's domain, and the exchanger that answered, when the
	/// conversation was asked to slow down; forget their holds once they
	/// have run out and a conversation delivered.
	pub(super) fn pace(&self, job: &Job, conversation: &Conversation, now: u64) {
		let domain = job.domain.as_str();
		if conversation.held_until.is_some() {
			return;
		}
		let exchanger = conversation.remote.as_deref().map(backoff::exchanger_key);
		let keys: Vec<&str> = std::iter::once(domain)
			.chain(exchanger.as_deref())
			.collect();
		if conversation.delivered() {
			let Some(holds) = self.holds() else {
				return;
			};
			if !keys.iter().any(|key| holds.contains_key(*key)) {
				return;
			}
			let cleared = self.spool.update_holds(|holds| {
				for key in &keys {
					if backoff::clear_after_success(holds, key, now) {
						tracing::info!(destination = %key, "destination delivered again; hold ended");
					}
				}
			});
			if let Err(error) = cleared {
				tracing::warn!(%domain, %error, "cannot end destination hold");
			}
			return;
		}
		let Some((_, reason)) = conversation.throttled_by() else {
			return;
		};
		let hold = |holds: &mut DestinationHolds| {
			for key in &keys {
				let whose = (*key, job.sender.as_str());
				let (held, hold) =
					backoff::record_hold(holds, &self.backoff_steps, whose, reason, now);
				tracing::warn!(destination = %key, held = %held, until = hold.until, level = hold.level, %reason, "destination asked to slow down; holding it off");
			}
		};
		if let Err(error) = self.spool.update_holds(hold) {
			// Fail closed: the hold applies from memory until it is written.
			tracing::error!(%domain, %error, "cannot record destination hold; keeping it in memory");
			let mut holds = self.spool.load_holds().unwrap_or_default();
			let mut unwritten = self.unwritten_holds();
			merge(&mut holds, &unwritten);
			hold(&mut holds);
			*unwritten = holds;
		}
	}
}
