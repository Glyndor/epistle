//! `epistle warmup`: see and steer the IP warm-up (see
//! [`crate::queue::warmup`]).
//!
//! Every change is written to `<data_dir>/warmup.json` and the command then
//! waits, like the account commands, until the running server reports in
//! `reload.status` that it has loaded it; a server that is not running
//! applies it when it starts. A change to what mail may go asks for
//! confirmation on a terminal and needs `--yes` otherwise.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use clap::Subcommand;

use crate::config::Storage;
use crate::queue::warmup::Group;
use crate::queue::warmup::policy::{MAX_CAP, START_CAP};
use crate::queue::warmup::settings::{self, Action, Settings};

#[path = "warmup_view.rs"]
mod view;

/// Parse a receiver group name.
fn group(value: &str) -> Result<Group, String> {
	Group::parse(value)
		.ok_or_else(|| format!("unknown group {value:?}: gmail, outlook, yahoo, icloud or other"))
}

/// Parse a cap: a whole number of recipients a day.
fn cap(value: &str) -> Result<u32, String> {
	value
		.parse::<u32>()
		.ok()
		.filter(|cap| (1..=MAX_CAP).contains(cap))
		.ok_or_else(|| format!("the cap is a number of recipients a day, from 1 to {MAX_CAP}"))
}

/// Warm-up actions.
#[derive(Debug, Subcommand)]
pub enum WarmupCli {
	/// Show each group's cap, use, health and verdict.
	///
	/// Per group: the cap, today's use and health, the verdict so far, the
	/// cap it would leave, the mail waiting, and the last judged day.
	Status {
		/// Print one JSON object instead of text lines.
		#[arg(long)]
		json: bool,
	},
	/// Turn the warm-up on: mail over a group's daily cap waits in the queue.
	Enable {
		/// Skip the confirmation.
		#[arg(long, short = 'y')]
		yes: bool,
		/// Print one JSON object on success.
		#[arg(long)]
		json: bool,
	},
	/// Turn the warm-up off: every cap is lifted and waiting mail goes out.
	Disable {
		/// Skip the confirmation.
		#[arg(long, short = 'y')]
		yes: bool,
		/// Print one JSON object on success.
		#[arg(long)]
		json: bool,
	},
	/// Keep the caps where they are: they still apply, but no day moves them.
	Pause {
		/// Print one JSON object on success.
		#[arg(long)]
		json: bool,
	},
	/// Let the days move the caps again.
	Resume {
		/// Print one JSON object on success.
		#[arg(long)]
		json: bool,
	},
	/// Set a group's daily cap, or skip ahead one step.
	///
	/// A raise is judged on its first full day: kept when the day goes
	/// well, reverted otherwise.
	Set {
		/// The receiver group: gmail, outlook, yahoo, icloud or other.
		#[arg(value_parser = group)]
		group: Group,
		/// Recipients a day.
		#[arg(long, value_parser = cap, required_unless_present = "next", conflicts_with = "next")]
		cap: Option<u32>,
		/// Skip ahead one growth step (x1.5).
		#[arg(long)]
		next: bool,
		/// Skip the confirmation.
		#[arg(long, short = 'y')]
		yes: bool,
		/// Print one JSON object on success.
		#[arg(long)]
		json: bool,
	},
	/// Start a group over at its starting cap.
	Reset {
		/// The receiver group: gmail, outlook, yahoo, icloud or other.
		#[arg(value_parser = group)]
		group: Group,
		/// Skip the confirmation.
		#[arg(long, short = 'y')]
		yes: bool,
		/// Print one JSON object on success.
		#[arg(long)]
		json: bool,
	},
}

/// Run one warm-up action against the files under `data_dir` as of `now`.
pub(super) fn run(
	data_dir: &Path,
	storage: Option<&Storage>,
	delivery_log_days: u64,
	action: WarmupCli,
	now: u64,
	out: &mut impl Write,
) -> ExitCode {
	let (change, yes, json) = match action {
		WarmupCli::Status { json } => {
			return status(data_dir, storage, delivery_log_days, now, json, out);
		}
		WarmupCli::Enable { yes, json } => {
			if delivery_log_days == 0 {
				return super::exit::refused(
					"the warm-up judges each day from the delivery log, which is off; \
					 set [storage] delivery_log_days above 0 first",
				);
			}
			(Change::Enable, yes, json)
		}
		WarmupCli::Disable { yes, json } => (Change::Disable, yes, json),
		WarmupCli::Pause { json } => (Change::Pause, true, json),
		WarmupCli::Resume { json } => (Change::Resume, true, json),
		WarmupCli::Set {
			group,
			cap: Some(cap),
			yes,
			json,
			..
		} => (Change::Order(group, Action::Set { cap }), yes, json),
		WarmupCli::Set {
			group, yes, json, ..
		} => (Change::Order(group, Action::Next), yes, json),
		WarmupCli::Reset { group, yes, json } => (Change::Order(group, Action::Reset), yes, json),
	};
	change.run(data_dir, yes, json, out)
}

fn status(
	data_dir: &Path,
	storage: Option<&Storage>,
	delivery_log_days: u64,
	now: u64,
	json: bool,
	out: &mut impl Write,
) -> ExitCode {
	let report = match view::build(data_dir, storage, delivery_log_days, now) {
		Ok(report) => report,
		Err(error) => {
			super::style::error(format_args!(
				"reading the warm-up: {}",
				super::term::sanitize(&error)
			));
			return ExitCode::FAILURE;
		}
	};
	if json {
		let value = serde_json::to_value(&report).unwrap_or_default();
		return super::json_out::print(out, &value);
	}
	match view::render(&report, out) {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			super::style::error(format_args!("writing the report: {error}"));
			ExitCode::FAILURE
		}
	}
}

/// What a command changes.
enum Change {
	Enable,
	Disable,
	Pause,
	Resume,
	Order(Group, Action),
}

impl Change {
	fn name(&self) -> &'static str {
		match self {
			Change::Enable => "enable",
			Change::Disable => "disable",
			Change::Pause => "pause",
			Change::Resume => "resume",
			Change::Order(_, Action::Set { .. }) => "set",
			Change::Order(_, Action::Next) => "next",
			Change::Order(_, Action::Reset) => "reset",
		}
	}

	/// The question asked before a change to what mail may go.
	fn question(&self) -> String {
		match self {
			Change::Enable => format!(
				"Turn the IP warm-up on? Mail to each receiver group is held to a daily cap \
				 ({START_CAP} to start) and the rest waits in the queue. [y/N]"
			),
			Change::Disable => "Turn the IP warm-up off? Every cap is lifted and the mail \
				 waiting for one goes out at once. [y/N]"
				.to_string(),
			Change::Order(group, Action::Set { cap }) => format!(
				"Set the {group} cap to {cap} recipients a day? A raise is judged tomorrow and \
				 reverted if the day goes badly. [y/N]"
			),
			Change::Order(group, Action::Next) => format!(
				"Move the {group} cap ahead one step? It is judged tomorrow and reverted if the \
				 day goes badly. [y/N]"
			),
			Change::Order(group, Action::Reset) => {
				format!("Start the {group} cap over at {START_CAP} recipients a day? [y/N]")
			}
			Change::Pause | Change::Resume => String::new(),
		}
	}

	/// Apply the change to `settings`; whether anything changed.
	fn apply(&self, settings: &mut Settings) -> bool {
		let before = settings.clone();
		match self {
			Change::Enable => settings.enabled = true,
			Change::Disable => settings.enabled = false,
			Change::Pause => settings.paused = true,
			Change::Resume => settings.paused = false,
			Change::Order(group, action) => {
				settings.order(*group, *action);
			}
		}
		*settings != before
	}

	fn run(self, data_dir: &Path, yes: bool, json: bool, out: &mut impl Write) -> ExitCode {
		let mut settings = match settings::load(data_dir) {
			Ok(found) => found.unwrap_or_default(),
			Err(error) => {
				return super::exit::refused(format_args!(
					"{}; fix the file's owner and mode (0600) or remove it",
					super::term::sanitize(&error.to_string())
				));
			}
		};
		let changed = self.apply(&mut settings);
		if changed
			&& let Err(code) = super::prompt::confirm_destructive(
				&format!("warmup {}", self.name()),
				&self.question(),
				yes,
			) {
			return code;
		}
		if changed && let Err(error) = settings::save(data_dir, &settings) {
			super::style::error(format_args!("writing the warm-up settings: {error}"));
			return ExitCode::FAILURE;
		}
		let result = if changed { "saved" } else { "unchanged" };
		let written = match json {
			true => writeln!(
				out,
				"{}",
				serde_json::json!({
					"result": result,
					"action": self.name(),
					"enabled": settings.enabled,
					"paused": settings.paused,
					"order": settings.orders.iter().max_by_key(|order| order.seq).filter(|_| matches!(self, Change::Order(..))),
				})
			),
			false => writeln!(out, "warm-up {}: {result}", self.name()),
		};
		if let Err(error) = written {
			super::style::error(format_args!("writing the result: {error}"));
			return ExitCode::FAILURE;
		}
		if !changed {
			return ExitCode::SUCCESS;
		}
		super::account_reload::wait_after_write(
			&settings::path(data_dir),
			&mut super::style::stderr(),
		)
	}
}

#[cfg(test)]
#[path = "warmup_tests.rs"]
mod tests;
