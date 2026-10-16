//! `epistle evidence verify` and `epistle evidence acknowledge`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use super::term::sanitize;
use crate::evidence::ack::{self, Operator};
use crate::evidence::audit::{self, Options, Report};
use crate::evidence::day::Day;
use crate::evidence::key::EvidenceKey;

fn audited(root: &Path, from: Option<Day>, to: Option<Day>, now: u64) -> Result<Report, ExitCode> {
	let settings = crate::evidence::tsa::settings::load(root).map_err(|error| {
		super::style::error(format_args!("timestamp settings refused: {}", error.kind()));
		ExitCode::FAILURE
	})?;
	let options = Options {
		from,
		to,
		anchors: crate::evidence::tasks::anchors(&settings),
		now,
	};
	audit::verify(root, &options).map_err(|error| {
		super::style::error(format_args!("reading the evidence: {}", error.kind()));
		ExitCode::FAILURE
	})
}

/// Verify the evidence under `root`.
pub(super) fn verify(
	root: &Path,
	from: Option<Day>,
	to: Option<Day>,
	now: u64,
	as_json: bool,
	out: &mut impl Write,
) -> ExitCode {
	let report = match audited(root, from, to, now) {
		Ok(report) => report,
		Err(code) => return code,
	};
	let code = match report.first_break {
		None => ExitCode::SUCCESS,
		Some(_) => ExitCode::FAILURE,
	};
	let breaks: Vec<String> = report
		.acknowledged
		.iter()
		.map(|at| sanitize(&at.to_string()))
		.collect();
	let open: Vec<String> = report.open.iter().map(|day| day.name()).collect();
	let first = report
		.first_break
		.as_ref()
		.map(|at| sanitize(&at.to_string()));
	if as_json {
		let printed = super::evidence::json(
			out,
			&json!({
				// A break somebody accepted is still a break: "verified" is
				// true only when there is none, accepted or not, and
				// "no_open_break" is what lets transactional mail through.
				"verified": first.is_none() && breaks.is_empty(),
				"no_open_break": first.is_none(),
				"days": report.days,
				"records": report.records,
				"sealed": report.sealed,
				"stamped": report.stamped,
				"open": open,
				"acknowledged": breaks,
				"break": first,
			}),
		);
		return if printed == ExitCode::SUCCESS {
			code
		} else {
			printed
		};
	}
	let _ = writeln!(
		out,
		"{} days, {} records; {} sealed, {} timestamped; open: {}",
		report.days,
		report.records,
		report.sealed,
		report.stamped,
		if open.is_empty() {
			"none".to_string()
		} else {
			open.join(", ")
		}
	);
	for at in &breaks {
		let _ = writeln!(out, "acknowledged: {at}");
	}
	let _ = match &first {
		None if breaks.is_empty() => writeln!(out, "the evidence verifies"),
		None => writeln!(
			out,
			"the evidence verifies except for {} acknowledged break(s), listed above",
			breaks.len()
		),
		Some(at) => writeln!(
			out,
			"BREAK: {at}\ntransactional mail is held until it is understood and acknowledged: \
			 epistle evidence acknowledge --reason <why>"
		),
	};
	code
}

/// Acknowledge the first break under `root`.
pub(super) fn acknowledge(
	root: &Path,
	reason: &str,
	yes: bool,
	now: u64,
	as_json: bool,
	out: &mut impl Write,
) -> ExitCode {
	let reason = reason.trim();
	if reason.is_empty() {
		return super::exit::refused("--reason must say why the break is accepted");
	}
	let operator = match Operator::current(root) {
		Ok(operator) => operator,
		Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
			return super::exit::refused(error);
		}
		Err(error) => {
			super::style::error(format_args!("evidence: {}", error.kind()));
			return ExitCode::FAILURE;
		}
	};
	let report = match audited(root, None, None, now) {
		Ok(report) => report,
		Err(code) => return code,
	};
	let Some(at) = report.first_break else {
		if as_json {
			return super::evidence::json(out, &json!({ "acknowledged": null }));
		}
		let _ = writeln!(out, "the evidence verifies: nothing to acknowledge");
		return ExitCode::SUCCESS;
	};
	let described = sanitize(&at.to_string());
	let question = format!(
		"Break: {described}\nAcknowledge it? Transactional mail is taken again; the break stays \
		 in the evidence with your reason. [y/N] "
	);
	if let Err(code) = super::prompt::confirm_destructive("acknowledging the break", &question, yes)
	{
		return code;
	}
	let signed = EvidenceKey::load_or_create(root)
		.and_then(|key| ack::acknowledge(root, &key, &at, reason, &operator));
	if let Err(error) = signed {
		super::style::error(format_args!(
			"acknowledging: {}",
			sanitize(&error.to_string())
		));
		return ExitCode::FAILURE;
	}
	if as_json {
		return super::evidence::json(
			out,
			&json!({ "acknowledged": described, "id": ack::id(&at), "operator": operator.as_str() }),
		);
	}
	let _ = writeln!(
		out,
		"acknowledged: {described}\nthe server lifts the hold at its next check (within five minutes); \
		 run epistle evidence verify to see whether another break remains"
	);
	ExitCode::SUCCESS
}
