//! `epistle evidence clock accept`: tell the running server what day it is.
//!
//! A server that was stopped for more than a day, or that could not read its
//! log, seals, purges and expires nothing until a timestamp authority (or you)
//! vouches for the clock. This is the "you".

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use super::evidence::ClockCli;
use super::term::sanitize;
use crate::evidence::clock_accept;
use crate::evidence::day::Day;

/// Run one clock action.
pub(super) fn run(root: &Path, action: ClockCli, now: u64, out: &mut impl Write) -> ExitCode {
	match action {
		ClockCli::Accept { yes, json } => accept(root, yes, now, json, out),
	}
}

fn accept(root: &Path, yes: bool, now: u64, as_json: bool, out: &mut impl Write) -> ExitCode {
	let date = Day::of_epoch(now).name();
	let question = format!(
		"This machine's clock reads {date} {:02}:{:02} UTC. Is that the real date? The server \
		 then seals closed days and purges expired evidence by it; a wrong answer deletes \
		 evidence early. [y/N] ",
		now % 86_400 / 3600,
		now % 3600 / 60
	);
	if let Err(code) = super::prompt::confirm_destructive("accepting the clock", &question, yes) {
		return code;
	}
	if let Err(error) = clock_accept::request(root, now) {
		super::style::error(format_args!(
			"accepting the clock: {}",
			sanitize(&error.to_string())
		));
		return ExitCode::FAILURE;
	}
	if as_json {
		return super::evidence::json(out, &json!({ "accepted": now, "date": date }));
	}
	let _ = writeln!(
		out,
		"clock accepted ({date}); the server takes it at its next check (within five minutes), \
		 or when the request is an hour old, not at all"
	);
	ExitCode::SUCCESS
}
