//! The jobs waiting for a conversation slot, kept so that starting what
//! fits is fair and cheap.
//!
//! Jobs are grouped by sender (the account that submitted the message, or
//! the domain of an unauthenticated reverse path), and within a sender by
//! recipient domain. Senders take turns: each turn starts one job and sends
//! the sender to the back, so a sender with thousands of messages queued
//! ahead of another's one does not make it wait for all of them. Within a
//! sender, its domains take turns the same way. A sender or a domain at its
//! cap is set aside after one look, so filling slots never walks the queue.

use std::collections::{HashMap, VecDeque};

use uuid::Uuid;

/// The recipients of one entry in one domain, waiting for a slot.
pub(super) struct Job {
	pub(super) id: Uuid,
	pub(super) domain: String,
	/// Whose message it is, for the per-sender share of the slots.
	pub(super) sender: String,
	pub(super) recipients: Vec<String>,
}

/// One sender's waiting jobs, by domain.
#[derive(Default)]
pub(super) struct SenderJobs {
	pub(super) by_domain: HashMap<String, VecDeque<Job>>,
	/// Domains with waiting jobs, each once, in turn.
	pub(super) order: VecDeque<String>,
}

impl SenderJobs {
	fn is_empty(&self) -> bool {
		self.order.is_empty()
	}

	fn push(&mut self, job: Job, front: bool) {
		let waiting = self.by_domain.entry(job.domain.clone()).or_default();
		if waiting.is_empty() {
			match front {
				true => self.order.push_front(job.domain.clone()),
				false => self.order.push_back(job.domain.clone()),
			}
		}
		match front {
			true => waiting.push_front(job),
			false => waiting.push_back(job),
		}
	}
}

/// Every waiting job, by sender.
#[derive(Default)]
pub(super) struct Waiting {
	senders: HashMap<String, SenderJobs>,
	/// Senders with waiting jobs, each once, in turn.
	turn: VecDeque<String>,
}

impl Waiting {
	pub(super) fn is_empty(&self) -> bool {
		self.turn.is_empty()
	}

	/// Queue `job` after the others of its sender and domain.
	pub(super) fn push_back(&mut self, job: Job) {
		self.push(job, false);
	}

	/// Queue `job` before the others of its sender and domain, its sender
	/// next in turn.
	pub(super) fn push_front(&mut self, job: Job) {
		self.push(job, true);
	}

	fn push(&mut self, job: Job, front: bool) {
		if !self.senders.contains_key(&job.sender) {
			match front {
				true => self.turn.push_front(job.sender.clone()),
				false => self.turn.push_back(job.sender.clone()),
			}
		}
		self.senders
			.entry(job.sender.clone())
			.or_default()
			.push(job, front);
	}

	/// Take out the sender whose turn it is, with its jobs.
	pub(super) fn next_sender(&mut self) -> Option<(String, SenderJobs)> {
		let sender = self.turn.pop_front()?;
		let jobs = self.senders.remove(&sender).unwrap_or_default();
		Some((sender, jobs))
	}

	/// Put back a sender taken out with [`Waiting::next_sender`]: last in
	/// turn after it started a job, first when it is set aside. A sender
	/// with nothing left is forgotten.
	pub(super) fn put_back(&mut self, sender: String, jobs: SenderJobs, last: bool) {
		if jobs.is_empty() {
			return;
		}
		match last {
			true => self.turn.push_back(sender.clone()),
			false => self.turn.push_front(sender.clone()),
		}
		self.senders.insert(sender, jobs);
	}

	/// How many jobs wait, all senders together.
	#[cfg(test)]
	pub(super) fn len(&self) -> usize {
		self.senders
			.values()
			.flat_map(|jobs| jobs.by_domain.values())
			.map(VecDeque::len)
			.sum()
	}
}
