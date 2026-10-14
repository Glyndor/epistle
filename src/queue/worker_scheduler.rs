//! Running outbound conversations side by side.
//!
//! A scan of the spool turns each due entry into jobs, one per recipient
//! domain. A job starts when a conversation slot is free, overall and for
//! its domain (see [`crate::queue::limits`]), and it first claims its
//! recipients. A claim lives in memory, in this worker only, and is released
//! when the conversation ends or is dropped; a recipient already claimed is
//! never put in a second conversation, so two passes that overlap cannot
//! deliver it twice.
//!
//! Nothing about a conversation is written to the spool until it ends: the
//! outcome of each recipient is recorded under the spool lock (see
//! [`FsSpool::update_envelope`]) only once the remote has answered. A crash
//! or a shutdown mid-conversation therefore leaves its recipients pending,
//! with no attempt counted, and the claim goes with the process, so the next
//! worker retries them. The one window for a second copy is between the
//! remote's reply to the final dot and that write, as before.
//!
//! An entry is settled ([`Worker::finish`]) once every job it had in the
//! scan has ended: expiry, failure reports, the delay warning, removal.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

use uuid::Uuid;

use super::Worker;
use super::claims::{Claim, Full, Guarded};
use super::conversation::Conversation;
use super::waiting::{Job, SenderJobs, Waiting};
use crate::queue::backoff;
use crate::queue::client::DeliveryError;
use crate::smtp::address::Address;
use crate::storage::{RecipientStatus, SpoolEntry};

/// What a finished conversation hands back to the scheduler.
pub(super) struct Done<'a> {
	job: Job,
	entry: SpoolEntry,
	conversation: Conversation,
	_claim: Claim<'a>,
}

type Running<'a> = Pin<Box<dyn Future<Output = Done<'a>> + Send + 'a>>;

/// Jobs still to start, and the conversations running, of one scheduler.
/// The waiting jobs are kept so that starting what fits is fair across
/// senders and never walks the queue (see [`Waiting`]).
#[derive(Default)]
pub(super) struct Schedule<'a> {
	waiting: Waiting,
	/// Jobs not yet ended per entry, and whether any delivered.
	rounds: HashMap<Uuid, (usize, bool)>,
	running: Vec<Running<'a>>,
	/// Entries settled with at least one recipient delivered.
	pub(super) delivered: usize,
	/// The first spool error, reported once the pass is over.
	pub(super) error: Option<std::io::Error>,
	/// Waiting jobs looked at when filling slots, over the schedule's life.
	pub(super) examined: usize,
}

impl<'a> Schedule<'a> {
	pub(super) fn is_idle(&self) -> bool {
		self.running.is_empty()
	}

	pub(super) fn running_mut(&mut self) -> &mut Vec<Running<'a>> {
		&mut self.running
	}
}

/// Whose message an entry is, for the per-sender share of the slots and
/// of the holds: the account the server recorded as submitting it when it
/// accepted the message (from the authenticated session or API key, never
/// from anything the client wrote). Mail the server sends on its own
/// (bounces, delay warnings, auto-replies, forwards, alerts) has no account
/// and shares one system bucket, with one share like any account: nothing
/// a remote sender writes, such as the reverse path, picks the bucket.
pub(super) fn sender_of(envelope: &crate::storage::Envelope) -> String {
	match envelope
		.account
		.as_deref()
		.filter(|account| !account.is_empty())
	{
		Some(account) => format!("account:{account}"),
		None => "system".to_string(),
	}
}

/// The next conversation of `running` to end, or `None` when none runs.
pub(super) fn next_done<'a, 'b>(
	running: &'b mut Vec<Running<'a>>,
) -> impl Future<Output = Option<Done<'a>>> + 'b {
	std::future::poll_fn(move |context| {
		if running.is_empty() {
			return Poll::Ready(None);
		}
		for index in 0..running.len() {
			if let Poll::Ready(done) = running[index].as_mut().poll(context) {
				drop(running.swap_remove(index));
				return Poll::Ready(Some(done));
			}
		}
		Poll::Pending
	})
}

impl Worker {
	/// Queue a job for every due recipient of every entry that has no jobs
	/// in `schedule` yet, grouped by domain.
	pub(super) fn scan<'a>(&'a self, schedule: &mut Schedule<'a>) -> std::io::Result<()> {
		let now = self.now_epoch();
		// Holds that cannot be read hold everything.
		let Some(holds) = self.holds() else {
			return Ok(());
		};
		// The domains some mail still waits for: a hold that ran out on any
		// other has nothing left to slow down.
		let mut queued: HashSet<String> = HashSet::new();
		for id in self.spool.list()? {
			// The CLI edits entries on disk while this runs, so `held` and
			// `next_attempt` are read from the file on every scan, never kept
			// in memory.
			let envelope = match self.spool.load_envelope(id) {
				Ok(envelope) => envelope,
				Err(error) => {
					tracing::warn!(%id, %error, "cannot read spool entry");
					continue;
				}
			};
			for recipient in envelope.pending() {
				if let Some((_, domain)) = recipient.rsplit_once('@') {
					queued.insert(domain.to_ascii_lowercase());
				}
			}
			// Skip entries already in hand, held, or still backing off.
			if schedule.rounds.contains_key(&id)
				|| envelope.held.is_some()
				|| envelope.next_attempt > now
			{
				continue;
			}
			// A sender on hold (its mail filled the room for holds) waits.
			let sender = sender_of(&envelope);
			if backoff::is_held(&holds, &backoff::sender_key(&sender), now) {
				continue;
			}
			let due: Vec<String> = envelope
				.due(now)
				.into_iter()
				.filter(|recipient| !self.claims.holds(id, recipient))
				.collect();
			if due.is_empty() && self.claims.holds_any(id) {
				// Another pass has this entry in hand and will settle it.
				continue;
			}
			let count = due.len();
			let due = self.skip_suppressed(id, &envelope, due)?;
			let mut changed = due.len() != count;
			let mut by_domain: Vec<(String, Vec<String>)> = Vec::new();
			let mut index: HashMap<String, usize> = HashMap::new();
			let mut unparseable = Vec::new();
			for recipient in due {
				let Ok(address) = Address::parse(&recipient) else {
					unparseable.push(recipient);
					continue;
				};
				let domain = address.domain().to_ascii_lowercase();
				// A destination on hold is not contacted, and its recipients
				// wait without an attempt counted.
				if backoff::is_held(&holds, &domain, now) {
					continue;
				}
				match index.get(&domain) {
					Some(&at) => by_domain[at].1.push(recipient),
					None => {
						index.insert(domain.clone(), by_domain.len());
						by_domain.push((domain, vec![recipient]));
					}
				}
			}
			if !unparseable.is_empty() {
				self.refuse_unparseable(id, &unparseable)?;
				changed = true;
			}
			if by_domain.is_empty() && !changed && count > 0 {
				// Everything due waits for a destination on hold.
				continue;
			}
			if by_domain.is_empty() {
				self.settle(schedule, id, false);
				continue;
			}
			schedule.rounds.insert(id, (by_domain.len(), false));
			for (domain, recipients) in by_domain {
				schedule.waiting.push_back(Job {
					id,
					domain,
					sender: sender.clone(),
					recipients,
				});
			}
		}
		self.prune_holds(&holds, &queued, now);
		Ok(())
	}

	/// Record unparseable recipients as refused for good: no server could
	/// ever be asked about them.
	fn refuse_unparseable(&self, id: Uuid, recipients: &[String]) -> std::io::Result<()> {
		let entry = self.spool.load(id)?;
		let reason = DeliveryError::Permanent("unparseable recipient address".into());
		let conversation = Conversation::all(recipients, None, reason);
		self.record(id, &entry, &conversation, self.now_epoch())
	}

	/// Start every waiting job a slot is free for, one per sender in turn
	/// (see [`Waiting`]). A sender at its share, or whose every domain is
	/// at its cap, is set aside after one look, and filling stops as soon
	/// as no slot is free at all.
	pub(super) fn fill<'a>(&'a self, schedule: &mut Schedule<'a>) {
		if schedule.waiting.is_empty() {
			return;
		}
		let now = self.now_epoch();
		let Some(holds) = self.holds() else {
			return;
		};
		let mut aside = Vec::new();
		while self.claims.has_room(self.limits) {
			let Some((sender, mut jobs)) = schedule.waiting.next_sender() else {
				break;
			};
			if backoff::is_held(&holds, &backoff::sender_key(&sender), now) {
				for job in jobs.by_domain.into_values().flatten() {
					schedule.examined += 1;
					self.job_ended(schedule, job.id, false);
				}
				continue;
			}
			match self.start_next(schedule, &mut jobs, &holds, now) {
				true => schedule.waiting.put_back(sender, jobs, true),
				false => aside.push((sender, jobs)),
			}
		}
		for (sender, jobs) in aside.into_iter().rev() {
			schedule.waiting.put_back(sender, jobs, false);
		}
	}

	/// Start the next job of one sender's `jobs`, its domains in turn.
	/// `false` when none can start now: the sender has its share, no slot
	/// is free, or each of its domains is at its cap or on hold.
	fn start_next<'a>(
		&'a self,
		schedule: &mut Schedule<'a>,
		jobs: &mut SenderJobs,
		holds: &crate::storage::DestinationHolds,
		now: u64,
	) -> bool {
		let mut at_cap = Vec::new();
		let started = loop {
			let Some(domain) = jobs.order.pop_front() else {
				break false;
			};
			let mut waiting = jobs.by_domain.remove(&domain).unwrap_or_default();
			// A conversation of this pass may have put the destination on
			// hold since its jobs were queued.
			if backoff::is_held(holds, &domain, now) {
				for job in waiting {
					schedule.examined += 1;
					self.job_ended(schedule, job.id, false);
				}
				continue;
			}
			let mut outcome = None;
			while let Some(job) = waiting.pop_front() {
				schedule.examined += 1;
				match self.start(job) {
					Started::Running(conversation) => {
						schedule.running.push(conversation);
						outcome = Some(true);
						break;
					}
					Started::Dropped(id) => self.job_ended(schedule, id, false),
					Started::Waiting(job, Full::Domain) => {
						waiting.push_front(job);
						break;
					}
					Started::Waiting(job, Full::Sender | Full::Total) => {
						waiting.push_front(job);
						outcome = Some(false);
						break;
					}
				}
			}
			if !waiting.is_empty() {
				jobs.by_domain.insert(domain.clone(), waiting);
				match outcome {
					Some(true) => jobs.order.push_back(domain),
					Some(false) => jobs.order.push_front(domain),
					None => at_cap.push(domain),
				}
			}
			if let Some(started) = outcome {
				break started;
			}
		};
		for domain in at_cap.into_iter().rev() {
			jobs.order.push_front(domain);
		}
		started
	}

	/// Claim the recipients of `job` and start its conversation, unless no
	/// slot is free or nothing is left to send.
	fn start(&self, job: Job) -> Started<'_> {
		let taken = self.claims.take(
			self.limits,
			job.id,
			(&job.domain, &job.sender),
			&job.recipients,
		);
		let claim = match taken {
			Ok(claim) => claim,
			Err(full) => return Started::Waiting(job, full),
		};
		// The entry may have been delivered, held or removed since the scan.
		let entry = match self.spool.load(job.id) {
			Ok(entry) if entry.envelope.held.is_none() => entry,
			Ok(_) => return Started::Dropped(job.id),
			Err(error) => {
				if error.kind() != std::io::ErrorKind::NotFound {
					tracing::warn!(id = %job.id, %error, "cannot read spool entry");
				}
				return Started::Dropped(job.id);
			}
		};
		let recipients: Vec<String> = claim
			.recipients
			.iter()
			.filter(|recipient| {
				entry.envelope.recipient_state(recipient).status == RecipientStatus::Pending
			})
			.cloned()
			.collect();
		if recipients.is_empty() {
			return Started::Dropped(job.id);
		}
		Started::Running(Box::pin(async move {
			let talk = Guarded(Box::pin(self.converse(&entry, &job.domain, &recipients)));
			let conversation = talk.await.unwrap_or_else(|()| {
				tracing::error!(id = %job.id, domain = %job.domain, "outbound conversation panicked; its recipients wait for the next attempt");
				let reason = DeliveryError::Transient("internal error during delivery".into());
				Conversation::all(&recipients, None, reason)
			});
			Done {
				job,
				entry,
				conversation,
				_claim: claim,
			}
		}))
	}

	/// Record what a conversation decided, then settle its entry if it was
	/// the entry's last job.
	pub(super) fn complete<'a>(&'a self, schedule: &mut Schedule<'a>, done: Done<'a>) {
		let Done {
			job,
			entry,
			conversation,
			_claim,
		} = done;
		let delivered = conversation.delivered();
		let now = self.now_epoch();
		self.pace(&job, &conversation, now);
		match self.record(job.id, &entry, &conversation, now) {
			Ok(()) => {}
			// An operator removed the entry while it was in conversation.
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
				tracing::info!(id = %job.id, "queue entry removed during delivery");
			}
			Err(error) => {
				tracing::warn!(id = %job.id, %error, "cannot record delivery outcome");
				schedule.error.get_or_insert(error);
			}
		}
		drop(_claim);
		let retry_now = conversation.retry_now();
		if !retry_now.is_empty() {
			// The remote took part of the recipients: the rest go out in
			// another conversation right away.
			if let Some((left, _)) = schedule.rounds.get_mut(&job.id) {
				*left += 1;
				schedule.waiting.push_front(Job {
					id: job.id,
					domain: job.domain.clone(),
					sender: job.sender.clone(),
					recipients: retry_now,
				});
			}
		}
		self.job_ended(schedule, job.id, delivered);
	}

	/// One job of entry `id` has ended; settle the entry after its last.
	fn job_ended<'a>(&'a self, schedule: &mut Schedule<'a>, id: Uuid, delivered: bool) {
		let Some((left, any)) = schedule.rounds.get_mut(&id) else {
			return;
		};
		*left = left.saturating_sub(1);
		*any |= delivered;
		if *left == 0 {
			let any = *any;
			schedule.rounds.remove(&id);
			self.settle(schedule, id, any);
		}
	}

	/// Settle entry `id` once nothing of it is in conversation here.
	fn settle(&self, schedule: &mut Schedule<'_>, id: Uuid, delivered: bool) {
		match self.finish(id, self.now_epoch(), delivered) {
			Ok(()) => {}
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => {
				tracing::warn!(%id, %error, "cannot settle queue entry");
				schedule.error.get_or_insert(error);
			}
		}
		if delivered {
			schedule.delivered += 1;
		}
	}

	/// Start what fits, then take each conversation as it ends until none
	/// runs and none can start.
	pub(super) async fn drain<'a>(&'a self, schedule: &mut Schedule<'a>) {
		self.fill(schedule);
		while let Some(done) = next_done(&mut schedule.running).await {
			self.complete(schedule, done);
			self.fill(schedule);
		}
	}
}

/// What became of a job offered a slot.
enum Started<'a> {
	/// No slot is free, for the reason given: try again later.
	Waiting(Job, Full),
	/// The conversation is under way.
	Running(Running<'a>),
	/// Nothing is left to send for this job.
	Dropped(Uuid),
}

#[cfg(test)]
#[path = "worker_scheduler_tests.rs"]
mod tests;
