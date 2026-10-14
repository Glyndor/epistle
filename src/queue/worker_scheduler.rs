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

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::Poll;

use uuid::Uuid;

use super::Worker;
use super::conversation::Conversation;
use crate::queue::backoff;
use crate::queue::client::DeliveryError;
use crate::queue::limits::Limits;
use crate::smtp::address::Address;
use crate::storage::{RecipientStatus, SpoolEntry};

/// The recipients of one entry in one domain, waiting for a slot.
pub(super) struct Job {
	id: Uuid,
	domain: String,
	recipients: Vec<String>,
}

/// What a finished conversation hands back to the scheduler.
pub(super) struct Done<'a> {
	job: Job,
	entry: SpoolEntry,
	conversation: Conversation,
	_claim: Claim<'a>,
}

type Running<'a> = Pin<Box<dyn Future<Output = Done<'a>> + Send + 'a>>;

/// Jobs still to start, and the conversations running, of one scheduler.
#[derive(Default)]
pub(super) struct Schedule<'a> {
	queued: VecDeque<Job>,
	/// Jobs not yet ended per entry, and whether any delivered.
	rounds: HashMap<Uuid, (usize, bool)>,
	running: Vec<Running<'a>>,
	/// Entries settled with at least one recipient delivered.
	pub(super) delivered: usize,
	/// The first spool error, reported once the pass is over.
	pub(super) error: Option<std::io::Error>,
}

impl<'a> Schedule<'a> {
	pub(super) fn is_idle(&self) -> bool {
		self.running.is_empty()
	}

	pub(super) fn running_mut(&mut self) -> &mut Vec<Running<'a>> {
		&mut self.running
	}
}

/// The recipients in conversation and the slots in use, in this worker.
#[derive(Default)]
pub(super) struct Claims {
	state: Mutex<ClaimState>,
}

#[derive(Default)]
struct ClaimState {
	recipients: HashSet<(Uuid, String)>,
	domains: HashMap<String, usize>,
	running: usize,
}

/// Recipients of one entry claimed for one conversation, and its slot.
/// Dropping it releases both.
pub(super) struct Claim<'a> {
	claims: &'a Claims,
	id: Uuid,
	domain: String,
	recipients: Vec<String>,
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
			.contains(&(id, recipient.to_string()))
	}

	/// Whether any recipient of entry `id` is in a conversation.
	fn holds_any(&self, id: Uuid) -> bool {
		self.state().recipients.iter().any(|(held, _)| *held == id)
	}

	/// Take a slot for `domain` and claim those of `recipients` nobody holds.
	/// `None` when no slot is free; the claim may hold no recipient.
	fn take(
		&self,
		limits: Limits,
		id: Uuid,
		domain: &str,
		recipients: &[String],
	) -> Option<Claim<'_>> {
		let mut state = self.state();
		let in_domain = state.domains.get(domain).copied().unwrap_or(0);
		if state.running >= limits.total || in_domain >= limits.per_domain {
			return None;
		}
		let free: Vec<String> = recipients
			.iter()
			.filter(|recipient| !state.recipients.contains(&(id, (*recipient).clone())))
			.cloned()
			.collect();
		for recipient in &free {
			state.recipients.insert((id, recipient.clone()));
		}
		state.running += 1;
		*state.domains.entry(domain.to_string()).or_default() += 1;
		Some(Claim {
			claims: self,
			id,
			domain: domain.to_string(),
			recipients: free,
		})
	}
}

impl Drop for Claim<'_> {
	fn drop(&mut self) {
		let mut state = self.claims.state();
		for recipient in self.recipients.drain(..) {
			state.recipients.remove(&(self.id, recipient));
		}
		state.running = state.running.saturating_sub(1);
		if let Some(count) = state.domains.get_mut(&self.domain) {
			*count = count.saturating_sub(1);
			if *count == 0 {
				state.domains.remove(&self.domain);
			}
		}
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
		let holds = self.holds();
		for id in self.spool.list()? {
			if schedule.rounds.contains_key(&id) {
				continue;
			}
			// The CLI edits entries on disk while this runs, so `held` and
			// `next_attempt` are read from the file on every scan, never kept
			// in memory. Skip held entries and entries still backing off.
			let envelope = match self.spool.load_envelope(id) {
				Ok(envelope) if envelope.held.is_some() || envelope.next_attempt > now => continue,
				Ok(envelope) => envelope,
				Err(error) => {
					tracing::warn!(%id, %error, "cannot read spool entry");
					continue;
				}
			};
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
				match by_domain.iter_mut().find(|(known, _)| *known == domain) {
					Some((_, recipients)) => recipients.push(recipient),
					None => by_domain.push((domain, vec![recipient])),
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
				schedule.queued.push_back(Job {
					id,
					domain,
					recipients,
				});
			}
		}
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

	/// Start every queued job a slot is free for, oldest entry first.
	pub(super) fn fill<'a>(&'a self, schedule: &mut Schedule<'a>) {
		if schedule.queued.is_empty() {
			return;
		}
		let now = self.now_epoch();
		let holds = self.holds();
		let mut waiting = VecDeque::new();
		while let Some(job) = schedule.queued.pop_front() {
			// A conversation of this pass may have put the destination on
			// hold since the job was queued.
			if backoff::is_held(&holds, &job.domain, now) {
				self.job_ended(schedule, job.id, false);
				continue;
			}
			match self.start(job) {
				Started::Waiting(job) => waiting.push_back(job),
				Started::Running(conversation) => schedule.running.push(conversation),
				Started::Dropped(id) => self.job_ended(schedule, id, false),
			}
		}
		schedule.queued = waiting;
	}

	/// Claim the recipients of `job` and start its conversation, unless no
	/// slot is free or nothing is left to send.
	fn start(&self, job: Job) -> Started<'_> {
		let Some(claim) = self
			.claims
			.take(self.limits, job.id, &job.domain, &job.recipients)
		else {
			return Started::Waiting(job);
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
			let conversation = self.converse(&entry, &job.domain, &recipients).await;
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
		self.pace(&job.domain, &conversation, now);
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
				schedule.queued.push_front(Job {
					id: job.id,
					domain: job.domain.clone(),
					recipients: retry_now,
				});
			}
		}
		self.job_ended(schedule, job.id, delivered);
	}

	/// The destination holds as stored; none when they cannot be read.
	fn holds(&self) -> crate::storage::DestinationHolds {
		self.spool.load_holds().unwrap_or_else(|error| {
			tracing::warn!(%error, "cannot read destination holds");
			Default::default()
		})
	}

	/// Hold off `domain` when the conversation was asked to slow down, and
	/// end its hold when the conversation delivered.
	fn pace(&self, domain: &str, conversation: &Conversation, now: u64) {
		let written = if conversation.delivered() {
			if !self.holds().contains_key(domain) {
				return;
			}
			tracing::info!(%domain, "destination delivered again; hold ended");
			self.spool.update_holds(|holds| {
				holds.remove(domain);
			})
		} else if let Some(reason) = conversation.throttle() {
			self.spool.update_holds(|holds| {
				let hold = backoff::next_hold(&self.backoff_steps, holds.get(domain), reason, now);
				tracing::warn!(%domain, until = hold.until, level = hold.level, %reason, "destination asked to slow down; holding it off");
				holds.insert(domain.to_string(), hold);
			})
		} else {
			return;
		};
		if let Err(error) = written {
			tracing::warn!(%domain, %error, "cannot record destination hold");
		}
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
	/// No slot is free: try again later.
	Waiting(Job),
	/// The conversation is under way.
	Running(Running<'a>),
	/// Nothing is left to send for this job.
	Dropped(Uuid),
}
