//! The warm-up report `epistle warmup status` and `epistle status` print:
//! per receiver group, today's cap and use, today's health so far, the
//! verdict the day would get now and the cap it would leave, the mail
//! waiting for the cap, and the last judged day.
//!
//! Everything is read from disk, so the report works with the server
//! stopped: the settings and state files, today's delivery log and the
//! spool. Nothing here writes.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use crate::config::Storage;
use crate::queue::warmup::events::percent;
use crate::queue::warmup::health::tally_day;
use crate::queue::warmup::schedule::close_day;
use crate::queue::warmup::settings::{self, Action, Order};
use crate::queue::warmup::state::{self, DayRecord, State};
use crate::queue::warmup::{Group, day_of};
use crate::storage::{DeliveryLog, FsSpool, RecipientStatus};

/// One group's line.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub(in crate::cli) struct GroupView {
	pub(in crate::cli) group: &'static str,
	pub(in crate::cli) cap: Option<u32>,
	pub(in crate::cli) sent: u32,
	pub(in crate::cli) attempted: u32,
	pub(in crate::cli) deferred_percent: f64,
	pub(in crate::cli) bounced_percent: f64,
	pub(in crate::cli) spam_blocks: u32,
	pub(in crate::cli) verdict: &'static str,
	pub(in crate::cli) next_cap: Option<u32>,
	pub(in crate::cli) raise: Option<&'static str>,
	pub(in crate::cli) waiting: u64,
	pub(in crate::cli) last: Option<DayRecord>,
}

/// The whole report.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub(in crate::cli) struct View {
	pub(in crate::cli) enabled: bool,
	pub(in crate::cli) paused: bool,
	pub(in crate::cli) day: String,
	pub(in crate::cli) groups: Vec<GroupView>,
	/// Orders written that the server has not applied yet.
	pub(in crate::cli) pending: Vec<Order>,
	/// Why the state could not be read, when it could not.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub(in crate::cli) problem: Option<String>,
}

/// Recipients waiting for the cap of each group, from the spool.
fn waiting(data_dir: &Path, storage: Option<&Storage>) -> BTreeMap<Group, u64> {
	let mut counts = BTreeMap::new();
	if !data_dir.join("spool").join("new").is_dir() {
		return counts;
	}
	let Ok(spool) = FsSpool::open_configured(data_dir, storage) else {
		return counts;
	};
	for id in spool.list().unwrap_or_default() {
		let Ok(envelope) = spool.load_envelope(id) else {
			continue;
		};
		for recipient in &envelope.recipients {
			let state = envelope.recipient_state(recipient);
			if state.status != RecipientStatus::Pending {
				continue;
			}
			if let Some(group) = state.warmup.as_deref().and_then(Group::parse) {
				*counts.entry(group).or_default() += 1;
			}
		}
	}
	counts
}

/// Build the report as of `now`.
pub(in crate::cli) fn build(
	data_dir: &Path,
	storage: Option<&Storage>,
	delivery_log_days: u64,
	now: u64,
) -> Result<View, String> {
	let settings = settings::load(data_dir)
		.map_err(|error| error.to_string())?
		.unwrap_or_default();
	let today = day_of(now);
	let (mut state, problem) = match state::load(data_dir) {
		Ok(found) => (found.unwrap_or_else(|| State::new(today)), None),
		Err(error) => (State::distrusted(today), Some(error.to_string())),
	};
	if state.day != today {
		// The server has not opened today yet: nothing went out today.
		crate::queue::warmup::schedule::open_day(&mut state, today);
	}
	let log = DeliveryLog::open(data_dir, delivery_log_days);
	let tally =
		tally_day(&log, today).map_err(|error| format!("reading the delivery log: {error}"))?;
	let mut projected = state.clone();
	let projection = close_day(&mut projected, today, &tally, settings.paused);
	let waiting = waiting(data_dir, storage);
	let groups = Group::ALL
		.into_iter()
		.map(|group| {
			let schedule = state.group(group);
			let counts = tally.of(group);
			let judged = projection.iter().find(|event| event.group == group);
			GroupView {
				group: group.label(),
				cap: schedule.cap,
				sent: schedule.sent,
				attempted: counts.attempted,
				deferred_percent: percent(counts.deferred, counts.attempted),
				bounced_percent: percent(counts.bounced, counts.attempted),
				spam_blocks: counts.spam_blocks,
				verdict: judged.map_or("idle", |event| event.record.verdict.label()),
				next_cap: judged.map_or(schedule.cap, |event| event.record.next_cap),
				raise: schedule.raise.map(|_| "on trial"),
				waiting: waiting.get(&group).copied().unwrap_or(0),
				last: schedule.history.back().cloned(),
			}
		})
		.collect();
	let pending = settings
		.orders
		.iter()
		.filter(|order| order.seq > state.applied)
		.copied()
		.collect();
	Ok(View {
		enabled: settings.enabled,
		paused: settings.paused,
		day: crate::storage::delivery_log::day_name(today),
		groups,
		pending,
		problem,
	})
}

/// A cap as printed: a number, or `none` when the group has no cap.
pub(in crate::cli) fn cap(cap: Option<u32>) -> String {
	cap.map_or_else(|| "none".to_string(), |cap| cap.to_string())
}

/// `on`, `on, paused` or `off`.
pub(in crate::cli) fn mode(view: &View) -> &'static str {
	match (view.enabled, view.paused) {
		(false, _) => "off",
		(true, false) => "on",
		(true, true) => "on, paused",
	}
}

fn order_text(order: &Order) -> String {
	match order.action {
		Action::Set { cap } => format!("{} set {cap}", order.group),
		Action::Next => format!("{} next", order.group),
		Action::Reset => format!("{} reset", order.group),
		Action::Start { cap } => format!("{} start {}", order.group, self::cap(cap)),
		Action::Force { cap } => format!("{} start {} --force", order.group, self::cap(cap)),
	}
}

/// The last judged day of a group, in one phrase.
fn last_text(group: &str, record: &DayRecord) -> String {
	let mut text = format!(
		"{group} {} {}: {} -> {}",
		crate::storage::delivery_log::day_name(record.day),
		record.verdict.label(),
		cap(record.cap),
		cap(record.next_cap)
	);
	if let Some(raise) = record.raise {
		text.push_str(&format!(" (raise {})", raise.label()));
	}
	if !record.causes.is_empty() {
		let causes: Vec<String> = record
			.causes
			.iter()
			.map(|cause| {
				format!(
					"{}={}",
					crate::cli::term::sanitize(&cause.account),
					cause.bad
				)
			})
			.collect();
		text.push_str(&format!(" (most bad replies: {})", causes.join(", ")));
	}
	text
}

/// Print `view` as text lines.
pub(in crate::cli) fn render(view: &View, out: &mut impl Write) -> std::io::Result<()> {
	writeln!(out, "warm-up: {} (UTC day {})", mode(view), view.day)?;
	if let Some(problem) = &view.problem {
		writeln!(
			out,
			"state not trusted: {}",
			crate::cli::term::sanitize(problem)
		)?;
	}
	for group in &view.groups {
		writeln!(
			out,
			"{}\tcap={}\tsent={}\tdeferred={:.1}%\tbounced={:.1}%\tspam={}\tverdict={}\tnext={}\twaiting={}{}",
			group.group,
			cap(group.cap),
			group.sent,
			group.deferred_percent,
			group.bounced_percent,
			group.spam_blocks,
			group.verdict,
			cap(group.next_cap),
			group.waiting,
			group
				.raise
				.map_or(String::new(), |raise| format!("\traise {raise}")),
		)?;
	}
	for group in &view.groups {
		if let Some(record) = &group.last {
			writeln!(out, "last {}", last_text(group.group, record))?;
		}
	}
	for order in &view.pending {
		writeln!(
			out,
			"pending: {} (the server has not applied it yet)",
			order_text(order)
		)?;
	}
	Ok(())
}
