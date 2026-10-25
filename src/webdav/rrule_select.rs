//! Expansion of a rule that selects days: `BYDAY`, `BYMONTHDAY`, `BYMONTH`.
//!
//! Each period of the rule (a day, a week, a month, a year, every
//! `INTERVAL`) yields its selected days, in order, at the time of day of
//! `DTSTART`. Instants before `DTSTART` are not occurrences. `COUNT` counts the
//! occurrences from `DTSTART`, so a rule with one is walked from its first
//! period; one without is entered close to the window.

use super::{ByDay, DAY, Freq, Rule, civil_from_secs, days_from_civil, days_in_month, first_index};

/// The weekday of a day number: `0` Monday to `6` Sunday (1970-01-01 was a
/// Thursday).
fn weekday(day: i64) -> u32 {
	(day + 3).rem_euclid(7) as u32
}

/// The days of month `(year, month)` the rule selects, as day numbers.
fn month_days(rule: &Rule, year: i64, month: i64, default_day: i64) -> Vec<i64> {
	let len = days_in_month(year, month);
	let first = days_from_civil(year, month, 1);
	let by_month_day: Vec<i64> = rule
		.by_month_day
		.iter()
		.filter_map(|&d| {
			let d = i64::from(d);
			let day = if d > 0 { d } else { len + 1 + d };
			(1..=len).contains(&day).then_some(first + day - 1)
		})
		.collect();
	let by_day: Vec<i64> = (0..len)
		.filter(|offset| matches_by_day(&rule.by_day, first + offset, *offset, len))
		.map(|offset| first + offset)
		.collect();
	let mut days = match (rule.by_month_day.is_empty(), rule.by_day.is_empty()) {
		(false, false) => by_month_day
			.into_iter()
			.filter(|day| by_day.contains(day))
			.collect(),
		(false, true) => by_month_day,
		(true, false) => by_day,
		(true, true) => {
			if default_day <= len {
				vec![first + default_day - 1]
			} else {
				Vec::new()
			}
		}
	};
	days.sort_unstable();
	days.dedup();
	days
}

/// Whether the day at `offset` in a month of `len` days is selected by one of
/// the `BYDAY` entries (an ordinal counts from the start or the end).
fn matches_by_day(entries: &[ByDay], day: i64, offset: i64, len: i64) -> bool {
	entries.iter().any(|entry| {
		if weekday(day) != entry.weekday {
			return false;
		}
		match entry.ordinal {
			None => true,
			Some(n) if n > 0 => offset / 7 + 1 == i64::from(n),
			Some(n) => (len - 1 - offset) / 7 + 1 == i64::from(-n),
		}
	})
}

/// The days of period `k` and the first day the period can reach.
fn period(rule: &Rule, dtstart: i64, k: i64) -> (i64, Vec<i64>) {
	let interval = i64::from(rule.interval);
	let start_day = dtstart.div_euclid(DAY);
	let (year0, month0, dom0) = civil_from_secs(dtstart);
	let month_ok = |day: i64| {
		rule.by_month.is_empty()
			|| rule
				.by_month
				.contains(&(civil_from_secs(day * DAY).1 as u32))
	};
	match rule.freq {
		Freq::Daily => {
			let day = start_day.saturating_add(k.saturating_mul(interval));
			let (_, month, dom) = civil_from_secs(day.saturating_mul(DAY));
			let len = days_in_month(civil_from_secs(day.saturating_mul(DAY)).0, month);
			let day_ok =
				rule.by_day.is_empty() || rule.by_day.iter().any(|d| d.weekday == weekday(day));
			let dom_ok = rule.by_month_day.is_empty()
				|| rule
					.by_month_day
					.iter()
					.any(|&d| i64::from(d) == dom || i64::from(d) == dom - len - 1);
			(
				day,
				if day_ok && dom_ok && month_ok(day) {
					vec![day]
				} else {
					Vec::new()
				},
			)
		}
		Freq::Weekly => {
			let first = start_day - i64::from((weekday(start_day) + 7 - rule.wkst) % 7)
				+ k.saturating_mul(interval).saturating_mul(7);
			let wanted: Vec<u32> = if rule.by_day.is_empty() {
				vec![weekday(start_day)]
			} else {
				rule.by_day.iter().map(|d| d.weekday).collect()
			};
			let mut days: Vec<i64> = wanted
				.iter()
				.map(|&w| first + i64::from((w + 7 - rule.wkst) % 7))
				.filter(|&day| month_ok(day))
				.collect();
			days.sort_unstable();
			days.dedup();
			(first, days)
		}
		Freq::Monthly => {
			let index = year0 * 12 + (month0 - 1) + k.saturating_mul(interval);
			let (year, month) = (index.div_euclid(12), index.rem_euclid(12) + 1);
			let first = days_from_civil(year, month, 1);
			let listed = rule.by_month.is_empty() || rule.by_month.contains(&(month as u32));
			(
				first,
				if listed {
					month_days(rule, year, month, dom0)
				} else {
					Vec::new()
				},
			)
		}
		Freq::Yearly => {
			let year = year0.saturating_add(k.saturating_mul(interval));
			let months: Vec<i64> = if !rule.by_month.is_empty() {
				rule.by_month.iter().map(|&m| i64::from(m)).collect()
			} else if rule.by_month_day.is_empty() && rule.by_day.is_empty() {
				vec![month0]
			} else {
				(1..=12).collect()
			};
			let mut days: Vec<i64> = months
				.into_iter()
				.flat_map(|month| month_days(rule, year, month, dom0))
				.collect();
			days.sort_unstable();
			days.dedup();
			(days_from_civil(year, 1, 1), days)
		}
	}
}

pub(super) fn expand(
	dtstart: i64,
	rule: &Rule,
	window_start: i64,
	window_end: i64,
	budget: usize,
) -> (Vec<i64>, bool) {
	let time = dtstart.rem_euclid(DAY);
	let walked_from = if rule.count.is_some() {
		0
	} else {
		i64::from(first_index(dtstart, rule.freq, rule.interval, window_start))
	};
	let mut out = Vec::new();
	let mut left = budget;
	let mut seen = 0u64;
	for k in walked_from.. {
		if left == 0 {
			return (out, true);
		}
		left -= 1;
		let (period_start, days) = period(rule, dtstart, k);
		if period_start.saturating_mul(DAY) >= window_end
			|| rule
				.until
				.is_some_and(|until| period_start.saturating_mul(DAY) > until)
		{
			break;
		}
		for day in days {
			let at = day.saturating_mul(DAY).saturating_add(time);
			if at < dtstart {
				continue;
			}
			if rule.until.is_some_and(|until| at > until)
				|| rule.count.is_some_and(|count| seen >= u64::from(count))
				|| at >= window_end
			{
				return (out, false);
			}
			seen += 1;
			if at >= window_start {
				if left == 0 {
					return (out, true);
				}
				left -= 1;
				out.push(at);
			}
		}
	}
	(out, false)
}
