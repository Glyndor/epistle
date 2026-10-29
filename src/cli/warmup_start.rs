//! `epistle warmup plan` and `epistle warmup start`: set each group's
//! starting cap from what the operator says about the sending address,
//! how long it has sent mail and how much it sends a day (see
//! [`crate::queue::warmup::stages`]).
//!
//! `plan` prints the caps, how many good days each group needs to reach
//! the daily volume and on which day, and changes nothing. `start` turns
//! the warm-up on and writes those caps. Neither lowers a cap that is
//! already higher, or lifted, unless `--force` says to.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::queue::warmup::policy::MAX_CAP;
use crate::queue::warmup::settings::{self, Action};
use crate::queue::warmup::stages::{days_to_reach, stage, starting_cap};
use crate::queue::warmup::state::{self, State};
use crate::queue::warmup::{Group, day_of, schedule};

/// The longest age taken, in days: a century.
const MAX_AGE_DAYS: u64 = 36_500;

/// Parse an age: a whole number of days, weeks, months (30 days) or
/// years (365 days), `0d`, `3w`, `6m`, `1y`.
fn age(value: &str) -> Result<u64, String> {
	let refuse = || {
		format!(
			"{value:?} is not an age: a number of days, weeks, months or years, like 0d, 3w, 6m or 1y"
		)
	};
	let unit = value.chars().last().ok_or_else(refuse)?;
	let days = match unit {
		'd' => 1,
		'w' => 7,
		'm' => 30,
		'y' => 365,
		_ => return Err(refuse()),
	};
	let count: u64 = value[..value.len() - 1].parse().map_err(|_| refuse())?;
	count
		.checked_mul(days)
		.filter(|total| *total <= MAX_AGE_DAYS)
		.ok_or_else(refuse)
}

/// Parse a daily volume: recipients a day.
fn volume(value: &str) -> Result<u32, String> {
	value
		.parse::<u32>()
		.ok()
		.filter(|volume| (1..=MAX_CAP).contains(volume))
		.ok_or_else(|| {
			format!("the daily volume is a number of recipients a day, from 1 to {MAX_CAP}")
		})
}

/// What the sending address is like, and which groups to start.
#[derive(Debug, clap::Args)]
pub struct StartArgs {
	/// How long the address has sent mail: days, weeks, months or years
	/// (`0d`, `3w`, `6m`, `1y`).
	#[arg(long, value_parser = age, default_value = "0d")]
	ip_age: u64,
	/// Recipients a day the address sends, or is to send.
	#[arg(long, value_parser = volume)]
	daily_volume: Option<u32>,
	/// Only this receiver group: gmail, outlook, yahoo, icloud or other.
	#[arg(long, value_parser = super::group, conflicts_with = "all")]
	group: Option<Group>,
	/// Every receiver group (the default).
	#[arg(long)]
	all: bool,
	/// Lower a cap that is already higher, or lifted.
	#[arg(long)]
	force: bool,
	/// Skip the confirmation (`start`).
	#[arg(long, short = 'y')]
	yes: bool,
	/// Print one JSON object.
	#[arg(long)]
	json: bool,
}

/// One group's plan.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct Row {
	group: &'static str,
	stage: &'static str,
	cap: Option<u32>,
	current: Option<u32>,
	days: u32,
	reach: String,
	applies: bool,
}

/// The caps the groups have once the orders not yet applied are.
fn current(data_dir: &Path, today: i64) -> Result<State, String> {
	let mut state = state::load(data_dir)
		.map_err(|error| error.to_string())?
		.unwrap_or_else(|| State::new(today));
	let settings = settings::load(data_dir)
		.map_err(|error| error.to_string())?
		.unwrap_or_default();
	let mut pending: Vec<_> = settings
		.orders
		.iter()
		.filter(|order| order.seq > state.applied)
		.collect();
	pending.sort_by_key(|order| order.seq);
	for order in pending {
		schedule::apply(state.group_mut(order.group), order.action, today);
	}
	Ok(state)
}

/// The plan for `args` as of `now`.
fn plan(data_dir: &Path, args: &StartArgs, now: u64) -> Result<Vec<Row>, String> {
	let today = day_of(now);
	let state = current(data_dir, today)?;
	let groups: Vec<Group> = match args.group {
		Some(group) => vec![group],
		None => Group::ALL.to_vec(),
	};
	Ok(groups
		.into_iter()
		.map(|group| {
			let cap = starting_cap(args.ip_age, args.daily_volume);
			let current = state.group(group).cap;
			let lowers = schedule::lowers(cap, current);
			let days = days_to_reach(cap, args.daily_volume);
			Row {
				group: group.label(),
				stage: stage(args.ip_age).name,
				cap,
				current,
				days,
				reach: crate::storage::delivery_log::day_name(
					today.saturating_add(i64::from(days)),
				),
				applies: !lowers || args.force,
			}
		})
		.collect())
}

fn heading(args: &StartArgs, now: u64) -> String {
	let volume = match args.daily_volume {
		Some(volume) => format!("{volume} recipients a day"),
		None => "no daily volume given: days until the cap is lifted".to_string(),
	};
	format!(
		"plan: IP {} days old, {volume} (UTC day {})",
		args.ip_age,
		crate::storage::delivery_log::day_name(day_of(now))
	)
}

fn line(row: &Row) -> String {
	let cap = super::view::cap;
	let mut text = format!(
		"{}\tstage={}\tcap={}\tnow={}\tdays={}\treach={}",
		row.group,
		row.stage,
		cap(row.cap),
		cap(row.current),
		row.days,
		row.reach
	);
	if !row.applies {
		text.push_str(&format!(
			"\tkept={} (lower only with --force)",
			cap(row.current)
		));
	}
	text
}

/// `warmup plan`: print the plan, change nothing.
pub(super) fn run_plan(
	data_dir: &Path,
	args: &StartArgs,
	now: u64,
	out: &mut impl Write,
) -> ExitCode {
	let rows = match plan(data_dir, args, now) {
		Ok(rows) => rows,
		Err(error) => return crate::cli::exit::refused(crate::cli::term::sanitize(&error)),
	};
	let written = match args.json {
		true => writeln!(
			out,
			"{}",
			serde_json::json!({
				"ip_age_days": args.ip_age,
				"daily_volume": args.daily_volume,
				"day": crate::storage::delivery_log::day_name(day_of(now)),
				"groups": rows,
			})
		),
		false => std::iter::once(heading(args, now))
			.chain(rows.iter().map(line))
			.try_for_each(|text| writeln!(out, "{text}")),
	};
	match written {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			crate::cli::style::error(format_args!("writing the plan: {error}"));
			ExitCode::FAILURE
		}
	}
}

/// `warmup start`: turn the warm-up on at the planned caps.
pub(super) fn run_start(
	data_dir: &Path,
	delivery_log_days: u64,
	args: &StartArgs,
	now: u64,
	out: &mut impl Write,
) -> ExitCode {
	if delivery_log_days == 0 {
		return crate::cli::exit::refused(
			"the warm-up judges each day from the delivery log, which is off; \
			 set [storage] delivery_log_days above 0 first",
		);
	}
	let rows = match plan(data_dir, args, now) {
		Ok(rows) => rows,
		Err(error) => return crate::cli::exit::refused(crate::cli::term::sanitize(&error)),
	};
	let mut settings = match settings::load(data_dir) {
		Ok(found) => found.unwrap_or_default(),
		Err(error) => {
			return crate::cli::exit::refused(crate::cli::term::sanitize(&error.to_string()));
		}
	};
	let caps: Vec<String> = rows
		.iter()
		.filter(|row| row.applies)
		.map(|row| format!("{} {}", row.group, super::view::cap(row.cap)))
		.collect();
	let question = format!(
		"Start the IP warm-up with these daily caps: {}? [y/N]",
		if caps.is_empty() {
			"none changed".to_string()
		} else {
			caps.join(", ")
		}
	);
	if let Err(code) = crate::cli::prompt::confirm_destructive("warmup start", &question, args.yes)
	{
		return code;
	}
	settings.enabled = true;
	for row in rows.iter().filter(|row| row.applies) {
		if let Some(group) = Group::parse(row.group) {
			let action = match args.force {
				true => Action::Force { cap: row.cap },
				false => Action::Start { cap: row.cap },
			};
			settings.order(group, action);
		}
	}
	if let Err(error) = settings::save(data_dir, &settings) {
		crate::cli::style::error(format_args!("writing the warm-up settings: {error}"));
		return ExitCode::FAILURE;
	}
	let written = match args.json {
		true => writeln!(
			out,
			"{}",
			serde_json::json!({"result": "saved", "enabled": true, "groups": rows})
		),
		false => rows.iter().try_for_each(|row| {
			let cap = super::view::cap;
			match row.applies {
				true => writeln!(
					out,
					"{}: cap {} (was {})",
					row.group,
					cap(row.cap),
					cap(row.current)
				),
				false => writeln!(
					out,
					"{}: kept {} (--force lowers it to {})",
					row.group,
					cap(row.current),
					cap(row.cap)
				),
			}
		}),
	};
	if let Err(error) = written {
		crate::cli::style::error(format_args!("writing the result: {error}"));
		return ExitCode::FAILURE;
	}
	crate::cli::account::reload::wait_after_write(
		&settings::path(data_dir),
		&mut crate::cli::style::stderr(),
	)
}

#[cfg(test)]
#[path = "warmup_tests_start.rs"]
mod tests;
