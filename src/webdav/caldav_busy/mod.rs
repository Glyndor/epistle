//! The free-busy scan: reading a calendar's events and turning their
//! occurrences into busy periods, with a bound on the work one request may
//! cause.
//!
//! A request is refused (`BusyError::TooMuchWork`, answered `403` with
//! `DAV:number-of-matches-within-limits`) rather than answered with a partial
//! picture, because a free-busy answer that silently omits busy time reads as
//! free time. The same holds for an event that repeats by a rule this server
//! does not evaluate (`403`) and for a calendar that cannot be read (`500`).
//! The bounds are [`MAX_WINDOW_SECS`] (how wide the range may be),
//! [`MAX_ITEMS`] (calendar files plus events examined), [`MAX_FILE_BYTES`]
//! (one calendar file; a larger one counts as busy for the whole range) and [`MAX_PERIODS`] (busy periods in the answer, after
//! overlapping ones are merged).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::caldav::{Period, vevents};
use super::rrule;

/// The widest range, in seconds, one free-busy request may cover (400 days).
pub const MAX_WINDOW_SECS: i64 = 400 * 86_400;

/// The most calendar files plus events one free-busy request examines.
pub const MAX_ITEMS: usize = 50_000;

/// The largest calendar file, in bytes, a free-busy request reads; a larger
/// one counts as busy for the whole range.
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// The most busy periods one free-busy answer holds once overlapping periods
/// are merged.
pub const MAX_PERIODS: usize = 10_000;

/// Why a free-busy request was not answered.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum BusyError {
	/// The request asks for more work than one request may take.
	TooMuchWork,
	/// An event repeats by a rule this server cannot evaluate, so the answer
	/// would read as free time that may be busy.
	Unsupported,
	/// A calendar could not be read; the answer would omit its events.
	Unreadable,
}

/// The bounds one scan runs under. Production uses [`Limits::standard`]; the
/// tests shrink them so abuse cases stay small.
#[derive(Clone, Copy)]
pub(super) struct Limits {
	pub(super) window_secs: i64,
	pub(super) items: usize,
	pub(super) file_bytes: u64,
	pub(super) periods: usize,
	/// Called on the thread that scans a file; the tests use it to see where
	/// the scan runs.
	pub(super) observe: Option<fn()>,
}

impl Limits {
	pub(super) const fn standard() -> Self {
		Self {
			window_secs: MAX_WINDOW_SECS,
			items: MAX_ITEMS,
			file_bytes: MAX_FILE_BYTES,
			periods: MAX_PERIODS,
			observe: None,
		}
	}
}

/// What a scan has gathered so far.
#[derive(Default)]
pub(super) struct Scan {
	periods: Vec<Period>,
	/// Calendar files plus events examined.
	items: usize,
	/// Periods handed to merges, to show the merging is amortised.
	#[cfg_attr(not(test), allow(dead_code))]
	merged: u64,
	/// Set when the request is gone: the scan stops at its next event.
	cancel: Arc<AtomicBool>,
}

/// Sets the flag when dropped, so the scan of a request that was abandoned
/// (or has finished) does not run on.
struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
	fn drop(&mut self) {
		self.0.store(true, Ordering::Relaxed);
	}
}

/// Scan every `.ics` in each calendar in `calendars`, expand each `VEVENT`'s
/// recurrence over `[start, end)`, and return the busy periods (clamped to the
/// window). Each occurrence contributes `[occurrence, occurrence + duration)`,
/// and an occurrence that starts before the window and runs into it counts.
/// A calendar file larger than the size bound is not read: it is counted as
/// busy for the whole window, the safe answer for something unknown.
/// Children that are themselves symlinks are skipped, they may have been
/// planted in the user's tree, and following them would read events that
/// belong to no account. A directory or file that cannot be read fails the
/// request rather than reading as free.
pub(super) async fn busy_periods(
	calendars: &[PathBuf],
	start: i64,
	end: i64,
) -> Result<Vec<Period>, BusyError> {
	busy_periods_within(calendars, start, end, Limits::standard()).await
}

fn missing(error: &std::io::Error) -> bool {
	error.kind() == std::io::ErrorKind::NotFound
}

pub(super) async fn busy_periods_within(
	calendars: &[PathBuf],
	start: i64,
	end: i64,
	limits: Limits,
) -> Result<Vec<Period>, BusyError> {
	if end.saturating_sub(start) > limits.window_secs {
		return Err(BusyError::TooMuchWork);
	}
	let mut scan = Scan::default();
	let _cancel = CancelOnDrop(Arc::clone(&scan.cancel));
	for calendar in calendars {
		let mut dir = match tokio::fs::read_dir(calendar).await {
			Ok(dir) => dir,
			Err(error) if missing(&error) => continue,
			Err(_) => return Err(BusyError::Unreadable),
		};
		loop {
			let child = match dir.next_entry().await {
				Ok(Some(child)) => child,
				Ok(None) => break,
				Err(_) => return Err(BusyError::Unreadable),
			};
			let kind = match child.file_type().await {
				Ok(kind) => kind,
				Err(error) if missing(&error) => continue,
				Err(_) => return Err(BusyError::Unreadable),
			};
			if !crate::util::fs_walk::allowed(&child.path(), kind) {
				continue;
			}
			let name = child.file_name();
			if !super::caldav::is_ics_path(&name.to_string_lossy()) {
				continue;
			}
			if let Ok(sym) = std::fs::symlink_metadata(child.path())
				&& sym.file_type().is_symlink()
			{
				continue;
			}
			scan.items += 1;
			if scan.items > limits.items {
				return Err(BusyError::TooMuchWork);
			}
			let length = match child.metadata().await {
				Ok(meta) => meta.len(),
				Err(error) if missing(&error) => continue,
				Err(_) => return Err(BusyError::Unreadable),
			};
			if length > limits.file_bytes {
				scan.periods.push((start, end));
				continue;
			}
			let data = match tokio::fs::read(child.path()).await {
				Ok(data) => data,
				Err(error) if missing(&error) => continue,
				Err(_) => return Err(BusyError::Unreadable),
			};
			// Parsing and expanding are CPU work: keep them off the async workers.
			let (back, outcome) = tokio::task::spawn_blocking(move || {
				let mut scan = scan;
				let text = String::from_utf8_lossy(&data);
				let outcome = collect_busy(&text, start, end, &mut scan, limits);
				(scan, outcome)
			})
			.await
			.map_err(|_| BusyError::Unreadable)?;
			scan = back;
			outcome?;
		}
	}
	scan.periods.sort_unstable();
	if scan.periods.len() > limits.periods {
		merge_overlapping(&mut scan.periods);
		if scan.periods.len() > limits.periods {
			return Err(BusyError::TooMuchWork);
		}
	}
	Ok(scan.periods)
}

/// Parse the `VEVENT`s in one iCalendar object and add the busy periods their
/// occurrences produce within `[start, end)` to `scan`. The periods are
/// merged only once they pass twice the bound, and the request fails if the
/// merged ones still pass the bound itself, so each merge is paid for by at
/// least as many new periods as it holds. Every event and every occurrence
/// expanded counts against the item bound.
///
/// An event whose repetition this server does not evaluate is refused, unless
/// it cannot reach the range (it starts after it, or its `UNTIL` is before
/// it): then it is not looked at, so a finished series never spoils a
/// calendar.
pub(super) fn collect_busy(
	ics: &str,
	start: i64,
	end: i64,
	scan: &mut Scan,
	limits: Limits,
) -> Result<(), BusyError> {
	if let Some(observe) = limits.observe {
		observe();
	}
	for event in vevents(ics) {
		if scan.cancel.load(Ordering::Relaxed) {
			return Err(BusyError::Unreadable);
		}
		scan.items += 1;
		if scan.items > limits.items {
			return Err(BusyError::TooMuchWork);
		}
		let Some(dtstart) = event.dtstart else {
			continue;
		};
		let duration = event.duration().max(0);
		// An occurrence that starts before the window can still run into it.
		let from = start.saturating_sub(duration);
		if event.rdate_unreadable {
			return Err(BusyError::Unsupported);
		}
		let mut instants = Vec::new();
		let budget = limits.items.saturating_sub(scan.items);
		scan.items = scan.items.saturating_add(event.rdates.len());
		instants.extend(
			event
				.rdates
				.iter()
				.copied()
				.filter(|at| *at >= from && *at < end),
		);
		match event.rrule.as_deref() {
			None => {
				instants.extend(rrule::expand_bounded(dtstart, None, from, end, budget).0);
			}
			Some(text) => {
				let rule = rrule::parse_rule(text);
				match rule.as_ref().filter(|rule| !rule.unsupported) {
					Some(rule) => {
						let (found, exceeded) =
							rrule::expand_bounded(dtstart, Some(rule), from, end, budget);
						scan.items = scan.items.saturating_add(found.len());
						if exceeded || scan.items > limits.items {
							return Err(BusyError::TooMuchWork);
						}
						instants.extend(found);
					}
					None => {
						let until = rule
							.as_ref()
							.and_then(|r| r.until)
							.or_else(|| rrule::until_of(text));
						let reaches = dtstart < end && until.is_none_or(|until| until >= from);
						if reaches {
							return Err(BusyError::Unsupported);
						}
					}
				}
			}
		}
		if scan.items > limits.items {
			return Err(BusyError::TooMuchWork);
		}
		for occ in instants {
			let busy_end = occ.saturating_add(duration).min(end);
			let busy_start = occ.max(start);
			if busy_end > busy_start {
				scan.periods.push((busy_start, busy_end));
			}
		}
		if scan.periods.len() > limits.periods.saturating_mul(2) {
			scan.merged += scan.periods.len() as u64;
			merge_overlapping(&mut scan.periods);
			if scan.periods.len() > limits.periods {
				return Err(BusyError::TooMuchWork);
			}
		}
	}
	Ok(())
}

/// Sort `periods` and merge the ones that overlap or touch.
fn merge_overlapping(periods: &mut Vec<Period>) {
	periods.sort_unstable();
	let mut merged: Vec<Period> = Vec::with_capacity(periods.len());
	for &(start, end) in periods.iter() {
		match merged.last_mut() {
			Some(last) if start <= last.1 => last.1 = last.1.max(end),
			_ => merged.push((start, end)),
		}
	}
	*periods = merged;
}

#[cfg(test)]
mod tests;
