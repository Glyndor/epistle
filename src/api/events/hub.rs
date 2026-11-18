//! The notifications in flight: a bounded ring the sampler appends to and
//! every stream reads from, and the count of open streams.
//!
//! A stream keeps only a position in the ring, never a queue of its own, so a
//! reader that does not keep up costs nothing: when the ring has moved past
//! its position it is dropped, and it resumes with `Last-Event-ID`.

use std::collections::VecDeque;
use std::sync::Mutex;

use super::limits::EventLimits;
use super::topic::{Reach, Topic};
use crate::api::Principal;
use crate::api::state::ApiState;

/// One notification: what changed and whom it concerns. No data.
#[derive(Debug, Clone)]
pub(super) struct Entry {
	pub seq: u64,
	pub topic: Topic,
	pub reach: Reach,
}

/// What a stream finds in the ring past its position.
pub(super) enum Window {
	/// The ring moved past the position: the reader is too slow.
	Lagged,
	/// The notifications past the position that concern the reader, oldest first.
	Entries(Vec<(u64, Topic)>),
}

struct Shared {
	ring: VecDeque<Entry>,
	/// The sequence number the next entry gets.
	next: u64,
	/// Streams open now.
	open: usize,
	/// Whether the sampler task is running.
	sampling: bool,
}

/// The ring, the stream count and the limits, one per server.
pub struct Hub {
	limits: EventLimits,
	/// Tells a resumed id from a previous run of the server apart.
	boot: u64,
	shared: Mutex<Shared>,
}

impl Hub {
	pub(crate) fn new(limits: EventLimits) -> Self {
		let boot = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|elapsed| elapsed.as_secs())
			.unwrap_or(0);
		Self {
			limits,
			boot,
			shared: Mutex::new(Shared {
				ring: VecDeque::new(),
				next: 1,
				open: 0,
				sampling: false,
			}),
		}
	}

	pub(super) fn limits(&self) -> &EventLimits {
		&self.limits
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, Shared> {
		self.shared.lock().unwrap_or_else(|p| p.into_inner())
	}

	/// Count one more open stream, or `false` when the server holds all it may.
	pub(super) fn admit(&self) -> bool {
		let mut shared = self.lock();
		if shared.open >= self.limits.per_server {
			return false;
		}
		shared.open += 1;
		true
	}

	/// Give back a stream [`Self::admit`] counted.
	pub(super) fn release(&self) {
		let mut shared = self.lock();
		shared.open = shared.open.saturating_sub(1);
	}

	/// Streams open now.
	#[cfg(test)]
	pub(crate) fn open_streams(&self) -> usize {
		self.lock().open
	}

	/// Notifications the ring holds.
	#[cfg(test)]
	pub(crate) fn held(&self) -> usize {
		self.lock().ring.len()
	}

	/// Whether the sampler task is running.
	#[cfg(test)]
	pub(crate) fn is_sampling(&self) -> bool {
		self.lock().sampling
	}

	/// Mark the sampler as needed, and say whether the caller has to start it.
	/// Nothing samples while nobody listens.
	pub(super) fn needs_sampler(&self) -> bool {
		let mut shared = self.lock();
		!std::mem::replace(&mut shared.sampling, true)
	}

	/// Whether the sampler goes on. It stops, under the same lock a new
	/// stream counts itself under, once the last stream is gone. Nothing is
	/// watched from then until the next stream opens, so the ring cannot
	/// vouch for what happened in between: it is emptied and the numbering
	/// skips one, which makes every id handed out before unresumable.
	pub(super) fn keep_sampling(&self) -> bool {
		let mut shared = self.lock();
		if shared.open == 0 {
			shared.sampling = false;
			shared.ring.clear();
			shared.next += 1;
		}
		shared.sampling
	}

	/// Append notifications. The oldest ones fall out of the ring.
	pub(super) fn publish(&self, changes: Vec<(Topic, Reach)>) {
		let mut shared = self.lock();
		for (topic, reach) in changes {
			let seq = shared.next;
			shared.next += 1;
			shared.ring.push_back(Entry { seq, topic, reach });
			while shared.ring.len() > self.limits.ring {
				shared.ring.pop_front();
			}
		}
	}

	/// The position a stream opened now starts from: it is told about what
	/// happens from here on.
	pub(super) fn head(&self) -> u64 {
		self.lock().next
	}

	/// The position after the notification `id` names, when this run of the
	/// server can still replay from it. `None` for an id of another run, one
	/// from the future, one the ring no longer reaches, or one that is not an
	/// id this server sent.
	pub(super) fn resume_from(&self, id: &str) -> Option<u64> {
		let (boot, seq) = id.split_once('.')?;
		if boot.parse::<u64>().ok()? != self.boot {
			return None;
		}
		let seq: u64 = seq.parse().ok()?;
		let shared = self.lock();
		let first = shared.next - shared.ring.len() as u64;
		(seq < shared.next && seq + 1 >= first).then_some(seq + 1)
	}

	/// The id to send with the notification `seq`.
	pub(super) fn id(&self, seq: u64) -> String {
		format!("{}.{seq}", self.boot)
	}

	/// What `principal` has not yet been told, from `cursor`; the new cursor
	/// is [`Self::head`] as read under the same lock.
	pub(super) fn since(&self, cursor: u64, principal: &Principal) -> (u64, Window) {
		let shared = self.lock();
		let first = shared.next - shared.ring.len() as u64;
		if cursor < first {
			return (shared.next, Window::Lagged);
		}
		let skip = (cursor - first) as usize;
		let entries = shared
			.ring
			.iter()
			.skip(skip)
			.filter(|entry| entry.reach.admits(entry.topic, principal))
			.map(|entry| (entry.seq, entry.topic))
			.collect();
		(shared.next, Window::Entries(entries))
	}
}

impl ApiState {
	/// Start the sampler when nothing runs it yet.
	pub(super) fn ensure_sampler(&self) {
		if self.events().needs_sampler() {
			tokio::spawn(super::sampler::run(self.clone()));
		}
	}
}
