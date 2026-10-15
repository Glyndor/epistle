//! The warm-up the running server consults: which recipients may go now,
//! the day's end, and the operator's orders.
//!
//! Everything goes through one lock and every change is written to the
//! state file before it takes effect. When the write fails, nothing is let
//! through: a share that could not be recorded would be given again after a
//! restart.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use super::Group;
use super::health::{DayTally, tally_day};
use super::pacing;
use super::schedule::{self, Event};
use super::settings::{self, Settings};
use super::state::{self, State};
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

/// The share of a group's day one sender may take: three quarters of the
/// cap, at least one, so one sender queueing thousands of messages leaves
/// room for everyone else's mail to the same provider.
pub fn sender_share(cap: u32) -> u32 {
	(u64::from(cap) * 3 / 4).max(1).min(u64::from(cap)) as u32
}

struct Inner {
	settings: Settings,
	state: State,
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
			inner: Mutex::new(Inner { settings, state }),
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

	/// The lock, after closing any day that ended and reporting it.
	fn current(&self, now: u64) -> MutexGuard<'_, Inner> {
		let mut inner = self.lock();
		let events = self.roll(&mut inner, now);
		self.notify.send(&events);
		inner
	}

	/// Close the day the counts belong to when it has ended. Days the
	/// server did not run had no mail from it and are not judged.
	fn roll(&self, inner: &mut Inner, now: u64) -> Vec<Event> {
		let today = day_of(now);
		let day = inner.state.day;
		if day >= today {
			return Vec::new();
		}
		let events = match inner.settings.enabled {
			true => {
				let tally = self.tally(day);
				schedule::close_day(&mut inner.state, day, &tally, inner.settings.paused)
			}
			false => Vec::new(),
		};
		schedule::open_day(&mut inner.state, today);
		self.save(&inner.state);
		events
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
		let inner = self.current(now);
		if !inner.settings.enabled {
			return None;
		}
		wait(&inner.state.group(group), sender, now)
	}

	/// Let up to `wanted` recipients of `sender` go to `group` now.
	pub fn grant(&self, group: Group, sender: &str, wanted: usize, now: u64) -> Grant {
		let mut inner = self.current(now);
		if !inner.settings.enabled {
			return Grant::Unlimited;
		}
		let before = inner.state.group(group);
		let Some(cap) = before.cap else {
			return Grant::Unlimited;
		};
		let schedule = inner.state.group_mut(group);
		let key = schedule.sender_key(sender).to_string();
		let used = schedule.senders.get(&key).copied().unwrap_or(0);
		let room = cap
			.saturating_sub(schedule.sent)
			.min(sender_share(cap).saturating_sub(used));
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
		let until = match granted < wanted {
			true => wait(&inner.state.group(group), sender, now)
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

	/// Close a day that ended, if one did, and report it. The server calls
	/// this on a timer so a day is reported even when no mail is waiting.
	pub fn tick(&self, now: u64) {
		drop(self.current(now));
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

/// When `sender` may next send to a group in `schedule`, or `None` when a
/// recipient may go now or the group has no cap.
fn wait(schedule: &state::GroupState, sender: &str, now: u64) -> Option<u64> {
	let cap = schedule.cap?;
	let used = schedule
		.senders
		.get(schedule.sender_key(sender))
		.copied()
		.unwrap_or(0);
	if schedule.sent >= cap || used >= sender_share(cap) {
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
