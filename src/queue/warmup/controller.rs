//! The warm-up the running server consults: which recipients may go now,
//! the day's end, and the operator's orders.
//!
//! Everything goes through one lock and every change is written to the
//! state file before it takes effect. When the write fails, nothing is let
//! through: a share that could not be recorded would be given again after a
//! restart.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use super::Group;
use super::health::{DayTally, tally_day};
use super::pacing;
use super::schedule;
use super::settings::{self, Settings};
use super::state::{self, Closing, State};
use crate::storage::DeliveryLog;

/// How long recipients wait when the state could not be written.
const RETRY_AFTER_ERROR_SECS: u64 = 60;

/// What the warm-up allows a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
	/// No cap applies: the warm-up is off or the group is warmed up.
	Unlimited,
	/// The first `granted` recipients may go; the rest wait until `until`
	/// (epoch seconds).
	Limited {
		/// How many may go now.
		granted: usize,
		/// When the rest may be tried again.
		until: u64,
	},
}

/// The UTC day of `now` (epoch seconds), as days since 1970-01-01.
pub fn day_of(now: u64) -> i64 {
	i64::try_from(now / 86_400).unwrap_or(i64::MAX)
}

/// The share of a group's day one sender may take while another sender
/// has mail waiting for the same cap: three quarters of the cap, at least
/// one, so one sender queueing thousands of messages leaves room for
/// everyone else's mail to the same provider. A sender alone may use the
/// whole cap.
pub fn sender_share(cap: u32) -> u32 {
	(u64::from(cap) * 3 / 4).max(1).min(u64::from(cap)) as u32
}

/// How long a sender told to wait for a group's cap still counts as
/// waiting. The queue asks again for every waiting recipient at each scan,
/// every 30 seconds, so a sender with mail still waiting is seen again
/// well within it.
const WAITING_SECS: u64 = 900;

struct Inner {
	settings: Settings,
	state: State,
	/// When each sender was last told to wait for each group's cap.
	waiting: BTreeMap<Group, HashMap<String, u64>>,
}

impl Inner {
	/// Whether a sender other than `sender` has mail waiting for the cap
	/// of `group` at `now`.
	fn contested(&self, group: Group, sender: &str, now: u64) -> bool {
		self.waiting.get(&group).is_some_and(|senders| {
			senders
				.iter()
				.any(|(other, at)| other != sender && now.saturating_sub(*at) < WAITING_SECS)
		})
	}

	/// The share of `cap` that `sender` may use today in `group`.
	fn share(&self, group: Group, sender: &str, cap: u32, now: u64) -> u32 {
		match self.contested(group, sender, now) {
			true => sender_share(cap),
			false => cap,
		}
	}

	/// Bring the pace of `group` back within reach of `now`: only a clock
	/// set back leaves it further ahead (see [`pacing::bounded`]).
	fn settle_pace(&mut self, group: Group, now: u64) {
		let schedule = self.state.group_mut(group);
		if let Some(cap) = schedule.cap {
			schedule.tat_ms = pacing::bounded(cap, schedule.tat_ms, now.saturating_mul(1000));
		}
	}

	/// Remember that `sender` has mail waiting for the cap of `group`. At
	/// most [`state::MAX_SENDERS`] senders are told apart; past it, those no
	/// longer waiting are forgotten, and then the rest share one entry.
	fn note_waiting(&mut self, group: Group, sender: &str, now: u64) {
		let senders = self.waiting.entry(group).or_default();
		if !senders.contains_key(sender) && senders.len() >= state::MAX_SENDERS {
			senders.retain(|_, at| now.saturating_sub(*at) < WAITING_SECS);
		}
		let key = match senders.contains_key(sender) || senders.len() < state::MAX_SENDERS {
			true => sender,
			false => state::OVERFLOW_SENDER,
		};
		senders.insert(key.to_string(), now);
	}
}

/// The warm-up of one server.
pub struct Warmup {
	data_dir: PathBuf,
	log: Option<DeliveryLog>,
	inner: Mutex<Inner>,
	notify: super::events::Notify,
}

impl Warmup {
	/// Open the warm-up under `data_dir`, judging days from `log`. A
	/// settings or state file that cannot be trusted is replaced by its
	/// most restrictive reading, and said so in the log.
	pub fn open(data_dir: &Path, log: Option<DeliveryLog>, now: u64) -> Self {
		let today = day_of(now);
		let settings = match settings::load(data_dir) {
			Ok(found) => found.unwrap_or_default(),
			Err(error) => {
				tracing::error!(%error, "warm-up settings not trusted; caps apply until `epistle warmup` rewrites them");
				Settings::distrusted()
			}
		};
		let state = match state::load(data_dir) {
			Ok(found) => found.unwrap_or_else(|| State::new(today)),
			Err(error) => {
				tracing::error!(%error, "warm-up state not trusted; every group starts over and today's share counts as used");
				State::distrusted(today)
			}
		};
		let warmup = Warmup {
			data_dir: data_dir.to_path_buf(),
			log,
			inner: Mutex::new(Inner {
				settings,
				state,
				waiting: BTreeMap::new(),
			}),
			notify: super::events::Notify::default(),
		};
		{
			let mut inner = warmup.lock();
			if warmup.apply_orders(&mut inner, today) {
				warmup.save(&inner.state);
			}
		}
		warmup
	}

	/// Report judged days to this webhook.
	pub fn with_webhook(mut self, webhook: Arc<crate::webhook::Webhook>) -> Self {
		self.notify.webhook = Some(webhook);
		self
	}

	/// Count judged days in these metrics, for `[[alerts]]` rules.
	pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
		self.notify.metrics = Some(metrics);
		self
	}

	fn lock(&self) -> MutexGuard<'_, Inner> {
		self.inner
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	fn save(&self, state: &State) -> bool {
		match state::save(&self.data_dir, state) {
			Ok(()) => true,
			Err(error) => {
				tracing::error!(%error, "cannot write the warm-up state");
				false
			}
		}
	}

	/// The lock, after closing any day that ended. Closing a day reads
	/// nothing: what each group sent is kept for [`Self::tick`] to judge.
	fn current(&self, now: u64) -> MutexGuard<'_, Inner> {
		let mut inner = self.lock();
		self.roll(&mut inner, now);
		inner
	}

	/// Close the day the counts belong to when it has ended, keeping what
	/// each group sent for the judgement, and open today. Days the server
	/// did not run had no mail from it and are not judged.
	fn roll(&self, inner: &mut Inner, now: u64) {
		let today = day_of(now);
		let day = inner.state.day;
		if day > today {
			// The clock went back past midnight. Today's use carries on
			// under today, rather than shutting every cap until the clock
			// catches up with the day it had reached.
			tracing::warn!(
				day,
				today,
				"the clock went back; the warm-up day follows it"
			);
			inner.state.day = today;
			self.save(&inner.state);
			return;
		}
		if day == today {
			return;
		}
		if inner.settings.enabled {
			let closing = Closing::of(&inner.state, day, inner.settings.paused);
			if !closing.sent.is_empty()
				&& let Some(earlier) = inner.state.closing.replace(closing)
			{
				tracing::warn!(
					day = earlier.day,
					"a warm-up day ended before the one before it was judged; it is not judged"
				);
			}
		}
		schedule::open_day(&mut inner.state, today);
		self.save(&inner.state);
	}

	/// The tally of `day`, empty when the log is off or unreadable.
	fn tally(&self, day: i64) -> DayTally {
		let Some(log) = &self.log else {
			return DayTally::default();
		};
		tally_day(log, day).unwrap_or_else(|error| {
			tracing::warn!(%error, "cannot read the delivery log to judge the warm-up day");
			DayTally::default()
		})
	}

	/// Apply the operator orders not applied yet, in order. Whether any was.
	fn apply_orders(&self, inner: &mut Inner, today: i64) -> bool {
		let mut orders: Vec<_> = inner
			.settings
			.orders
			.iter()
			.filter(|order| order.seq > inner.state.applied)
			.copied()
			.collect();
		orders.sort_by_key(|order| order.seq);
		for order in &orders {
			schedule::apply(inner.state.group_mut(order.group), order.action, today);
			inner.state.applied = order.seq;
			tracing::info!(group = %order.group, seq = order.seq, "warm-up order applied");
		}
		!orders.is_empty()
	}

	/// Whether caps apply.
	pub fn enabled(&self) -> bool {
		self.lock().settings.enabled
	}

	/// When `sender` may next send to `group`, or `None` when one recipient
	/// may go now (or no cap applies). Takes nothing.
	pub fn blocked(&self, group: Group, sender: &str, now: u64) -> Option<u64> {
		let mut inner = self.current(now);
		if !inner.settings.enabled {
			return None;
		}
		inner.settle_pace(group, now);
		let schedule = inner.state.group(group);
		let share = schedule.cap.map(|cap| inner.share(group, sender, cap, now));
		let until = wait(&schedule, sender, share, now);
		if until.is_some() {
			inner.note_waiting(group, sender, now);
		}
		until
	}

	/// Let up to `wanted` recipients of `sender` go to `group` now.
	pub fn grant(&self, group: Group, sender: &str, wanted: usize, now: u64) -> Grant {
		let mut inner = self.current(now);
		if !inner.settings.enabled {
			return Grant::Unlimited;
		}
		inner.settle_pace(group, now);
		let before = inner.state.group(group);
		let Some(cap) = before.cap else {
			return Grant::Unlimited;
		};
		let share = inner.share(group, sender, cap, now);
		let schedule = inner.state.group_mut(group);
		let key = schedule.sender_key(sender).to_string();
		let used = schedule.senders.get(&key).copied().unwrap_or(0);
		let room = cap
			.saturating_sub(schedule.sent)
			.min(share.saturating_sub(used));
		let wanted32 = u32::try_from(wanted).unwrap_or(u32::MAX).min(room);
		let (taken, tat) = pacing::take(cap, schedule.tat_ms, now.saturating_mul(1000), wanted32);
		if taken > 0 {
			schedule.tat_ms = tat;
			schedule.sent += taken;
			*schedule.senders.entry(key).or_default() += taken;
			if !self.save(&inner.state) {
				*inner.state.group_mut(group) = before;
				return Grant::Limited {
					granted: 0,
					until: now.saturating_add(RETRY_AFTER_ERROR_SECS),
				};
			}
		}
		let granted = taken as usize;
		if granted < wanted {
			inner.note_waiting(group, sender, now);
		}
		let until = match granted < wanted {
			true => wait(&inner.state.group(group), sender, Some(share), now)
				.unwrap_or(now.saturating_add(RETRY_AFTER_ERROR_SECS)),
			false => now,
		};
		Grant::Limited { granted, until }
	}

	/// Give back `count` recipients granted today and never offered to the
	/// remote, so a destination that does not answer does not use up the
	/// cap of the group.
	pub fn give_back(&self, group: Group, sender: &str, count: usize, now: u64) {
		let mut inner = self.lock();
		if count == 0 || inner.state.day != day_of(now) {
			return;
		}
		let schedule = inner.state.group_mut(group);
		let Some(cap) = schedule.cap else {
			return;
		};
		let count = u32::try_from(count).unwrap_or(u32::MAX).min(schedule.sent);
		let key = schedule.sender_key(sender).to_string();
		schedule.sent -= count;
		if let Some(used) = schedule.senders.get_mut(&key) {
			*used = used.saturating_sub(count);
		}
		schedule.tat_ms = pacing::give_back(cap, schedule.tat_ms, count);
		self.save(&inner.state);
	}

	/// Close a day that ended, if one did, judge the day waiting to be
	/// judged, and report it. The server calls this on a timer, off the
	/// runtime, so a day is reported even when no mail is waiting. The day
	/// of the delivery log is read without the lock: the queue goes on
	/// meanwhile.
	pub fn tick(&self, now: u64) {
		let Some(closing) = self.current(now).state.closing.clone() else {
			return;
		};
		let tally = self.tally(closing.day);
		let events = {
			let mut inner = self.lock();
			if inner.state.closing.as_ref() != Some(&closing) {
				return;
			}
			inner.state.closing = None;
			let events = schedule::judge_day(&mut inner.state, &closing, &tally);
			self.save(&inner.state);
			events
		};
		self.notify.send(&events);
	}

	/// Read the settings file again, after `epistle warmup` wrote it, and
	/// apply its new orders. A file that cannot be trusted or read leaves
	/// the running settings as they were.
	pub fn reload(&self, now: u64) -> std::io::Result<()> {
		let found = settings::load(&self.data_dir)
			.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
		let mut inner = self.current(now);
		inner.settings = found.unwrap_or_default();
		if self.apply_orders(&mut inner, day_of(now)) {
			self.save(&inner.state);
		}
		Ok(())
	}

	/// The settings and state as they are now.
	pub fn snapshot(&self) -> (Settings, State) {
		let inner = self.lock();
		(inner.settings.clone(), inner.state.clone())
	}
}

impl crate::directory_store::file_watcher::WarmupReloader for Warmup {
	fn reload_warmup(&self) -> std::io::Result<()> {
		self.reload(crate::storage::delivery_log::now_epoch())
	}
}

/// When `sender`, whose share of the day is `share`, may next send to a
/// group in `schedule`, or `None` when a recipient may go now or the group
/// has no cap.
fn wait(schedule: &state::GroupState, sender: &str, share: Option<u32>, now: u64) -> Option<u64> {
	let cap = schedule.cap?;
	let used = schedule
		.senders
		.get(schedule.sender_key(sender))
		.copied()
		.unwrap_or(0);
	if schedule.sent >= cap || used >= share.unwrap_or(cap) {
		let tomorrow = day_of(now).saturating_add(1);
		return Some(
			u64::try_from(tomorrow)
				.unwrap_or(u64::MAX)
				.saturating_mul(86_400),
		);
	}
	let now_ms = now.saturating_mul(1000);
	let next = pacing::next_ms(cap, schedule.tat_ms, now_ms);
	(next > now_ms).then(|| next.div_ceil(1000))
}

#[cfg(test)]
#[path = "controller_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "controller_tests_share.rs"]
mod share_tests;

#[cfg(test)]
#[path = "controller_tests_clock.rs"]
mod clock_tests;

#[cfg(test)]
#[path = "controller_tests_judge.rs"]
mod judge_tests;
