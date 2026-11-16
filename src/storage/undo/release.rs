//! Handing held submissions on once their time has come.

use std::sync::Arc;
use std::time::Duration;

use super::UndoStore;
use super::frame::Held;
use crate::smtp::sink::{MessageSink, SinkError};

/// How often the releaser looks for submissions that are due.
const TICK: Duration = Duration::from_secs(1);

/// A submission the sink kept failing to take is given up on after this
/// long, and its sender told, rather than retried for ever.
const GIVE_UP_SECS: u64 = 86_400;

/// How the notice to a sender whose message could not be handed on is
/// written: the same hostname and headers as every other report.
#[derive(Debug, Clone)]
pub struct NoticeStyle {
	/// The host name the notice says it comes from.
	pub hostname: String,
	/// Write `Auto-Submitted: auto-generated`.
	pub auto_submitted: bool,
	/// Write `X-Auto-Response-Suppress`.
	pub auto_response_suppress: bool,
}

/// What one pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Pass {
	/// Submissions handed on.
	pub released: usize,
	/// Submissions given up on, whose sender was told.
	pub refused: usize,
	/// Submissions left for the next pass: the sink could not take them yet.
	pub waiting: usize,
}

/// Releases what is due from an [`UndoStore`] into the sink the submission
/// path ends in.
pub struct Releaser {
	store: Arc<UndoStore>,
	inner: Arc<dyn MessageSink>,
	style: NoticeStyle,
}

/// Whether a refusal is the message's own and will come again.
fn permanent(error: &SinkError) -> bool {
	!matches!(
		error,
		SinkError::Unavailable(_) | SinkError::ScanUnavailable | SinkError::EvidenceUnavailable(_)
	)
}

impl Releaser {
	/// Release from `store` into `inner`.
	pub fn new(store: Arc<UndoStore>, inner: Arc<dyn MessageSink>, style: NoticeStyle) -> Self {
		// A claim left by a process that died is retried by this one.
		if let Err(error) = store.recover() {
			tracing::warn!(%error, "claimed held submissions could not be put back");
		}
		Self {
			store,
			inner,
			style,
		}
	}

	/// Hand on every submission whose release time is `now` or before.
	///
	/// Each message is claimed (moved to `inflight/` under the store's lock)
	/// before the sink sees it, so a cancel and a release cannot both win and
	/// two releasers cannot both send it. Then it is handed to the sink and the
	/// claim forgotten, so a crash in between hands it on a second time at the
	/// next start (see [`UndoStore::recover`]) rather than never. That window
	/// is the one place a recipient can get a copy twice.
	pub fn release_due(&self, now: u64) -> std::io::Result<Pass> {
		let mut pass = Pass::default();
		for pending in self.store.due(now)? {
			// Claimed under the store's lock before anything is handed on:
			// a cancel that comes later is refused, and one that came first
			// has already removed the file, so the claim finds nothing.
			let Some(held) = self.store.claim(&pending)? else {
				continue;
			};
			match self.release_one(&held, now) {
				Ok(Outcome::Released) => pass.released += 1,
				Ok(Outcome::Refused) => pass.refused += 1,
				Ok(Outcome::Waiting) => {
					self.store.requeue(&held)?;
					pass.waiting += 1;
				}
				Err(error) => {
					tracing::warn!(id = %pending.id, %error, "held submission cannot be released");
					self.store.requeue(&held)?;
					pass.waiting += 1;
				}
			}
		}
		self.store.prune(now)?;
		Ok(pass)
	}

	fn release_one(&self, held: &Held, now: u64) -> std::io::Result<Outcome> {
		let copy = held.message.clone();
		match self
			.inner
			.submit(copy, held.id, &held.account, &held.submission)
		{
			Ok(()) => {
				self.store.finish(held, now)?;
				Ok(Outcome::Released)
			}
			Err(error)
				if permanent(&error) || now.saturating_sub(held.release_at) > GIVE_UP_SECS =>
			{
				tracing::warn!(id = %held.id, %error, "a held submission was refused when released");
				self.tell_sender(&held.message, &error);
				self.store.finish(held, now)?;
				Ok(Outcome::Refused)
			}
			Err(error) => {
				tracing::warn!(id = %held.id, %error, "a held submission could not be handed on yet");
				Ok(Outcome::Waiting)
			}
		}
	}

	/// The message was accepted and the sender told so, so a refusal found
	/// at release is reported to the sender like any other failure.
	fn tell_sender(&self, message: &crate::smtp::session::AcceptedMessage, error: &SinkError) {
		let reason =
			format!("550 5.7.0 the message could not be delivered after the send delay: {error}");
		let notice = crate::queue::bounce::build(
			&self.style.hostname,
			&message.reverse_path,
			&message.recipients,
			&reason,
			&message.data,
			std::time::SystemTime::now(),
			self.style.auto_submitted,
			self.style.auto_response_suppress,
		);
		match notice {
			Some(notice) => {
				if let Err(error) = self.inner.deliver_report(notice) {
					tracing::error!(%error, "the notice of a refused held submission was not delivered");
				}
			}
			None => tracing::error!("a refused held submission has no sender to tell"),
		}
	}

	/// Run [`release_due`](Self::release_due) every [`TICK`] for as long as
	/// the process lives. The store is on disk, so a restart picks up what
	/// was waiting.
	pub fn spawn(self: Arc<Self>) {
		tokio::spawn(async move {
			let mut ticker = tokio::time::interval(TICK);
			ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
			loop {
				ticker.tick().await;
				let releaser = Arc::clone(&self);
				let now = crate::storage::delivery_log::now_epoch();
				let result = tokio::task::spawn_blocking(move || releaser.release_due(now)).await;
				match result {
					Ok(Ok(_)) => {}
					Ok(Err(error)) => tracing::warn!(%error, "held submissions cannot be listed"),
					Err(error) => tracing::error!(%error, "the release pass panicked"),
				}
			}
		});
	}
}

enum Outcome {
	Released,
	Refused,
	Waiting,
}
