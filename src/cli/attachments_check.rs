//! `epistle attachments check <file>`: what the policy in effect would do
//! with one message, without delivering anything.
//!
//! The file is the operator's, but its content is a message: every name
//! and type printed comes from a sender, so the text form escapes control
//! and formatting characters and the JSON form escapes everything outside
//! ASCII. The file is read only up to the message size limit, the same
//! bound the server puts on what it receives, and the inspection runs
//! under the server's own byte and time budget.

use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use super::policy::mode_name;
use super::print_json;
use crate::antispam::attachments::policy::{Action, Decision, Policy};
use crate::antispam::attachments::walk::Stop;
use crate::antispam::attachments::{PartReport, Report};
use crate::cli::resource::ResourceError;
use crate::config::{AttachmentMode, Attachments, Config};

/// Inspect the message in `file` under the policy of the configuration at
/// `config_path`, and print each part and the verdict.
pub(super) fn execute(
	config_path: &Path,
	file: &Path,
	json: bool,
	out: &mut impl Write,
) -> Result<ExitCode, ResourceError> {
	let config =
		Config::load(config_path).map_err(|error| ResourceError::Failure(error.to_string()))?;
	let limit = match config.max_message_size.unwrap_or(0) {
		0 => crate::smtp::session::MAX_MESSAGE_SIZE,
		size => usize::try_from(size).unwrap_or(usize::MAX),
	};
	let raw = read_bounded(file, limit)?;
	let section = &config.attachments;
	let off = section.mode == AttachmentMode::Off;
	// With the policy off the server inspects nothing. The parts are still
	// judged here, as `flag` would judge them, so the operator sees what
	// turning it on would find.
	let probe = Attachments {
		mode: if off {
			AttachmentMode::Flag
		} else {
			section.mode
		},
		..section.clone()
	};
	let policy = Policy::from_config(&probe, limit)
		.ok_or_else(|| ResourceError::Failure("the attachment policy is off".into()))?;
	let (report, decision) = policy.check(&raw);
	let decision = if off {
		Decision {
			action: Action::Deliver,
			reasons: Vec::new(),
		}
	} else {
		decision
	};
	// A submission is refused when the policy would quarantine or reject,
	// and only if the server inspects what its accounts submit.
	let inspected = config.antispam.scan_authenticated;
	let refused = inspected && decision.action >= Action::Quarantine;
	if json {
		print_json(
			out,
			&serde_json::json!({
				"mode": mode_name(section.mode),
				"verdict": action_name(decision.action),
				"reasons": decision.reasons.iter().map(|reason| reason.code()).collect::<Vec<_>>(),
				"submission": if refused { "refused" } else { "accepted" },
				"parts": report.parts.iter().map(part_json).collect::<Vec<_>>(),
				"stopped": report.stopped.map(stop_code),
				"ambiguous-mime": report.ambiguous,
			}),
		)?;
		return Ok(ExitCode::SUCCESS);
	}
	write_text(out, &report, &decision, off, refused, inspected)
		.map_err(|error| ResourceError::Failure(error.to_string()))?;
	Ok(ExitCode::SUCCESS)
}

/// Read `file`, refusing anything but a regular file and anything over
/// `limit` bytes. The size is checked before reading and the read itself
/// stops one byte past the limit, so a file that grows meanwhile is still
/// refused without being read whole.
fn read_bounded(file: &Path, limit: usize) -> Result<Vec<u8>, ResourceError> {
	// Run by root, the account reads a staged copy: messages name the file
	// the operator typed.
	let named = crate::cli::staging::shown(&file.display().to_string());
	let cannot =
		|error: std::io::Error| ResourceError::Failure(format!("cannot read {named}: {error}"));
	let too_large = || {
		ResourceError::refused(format!(
			"{named} is larger than the message size limit ({limit} bytes)"
		))
	};
	let metadata = std::fs::metadata(file).map_err(cannot)?;
	if !metadata.is_file() {
		return Err(ResourceError::refused(format!(
			"{named} is not a regular file"
		)));
	}
	if metadata.len() > limit as u64 {
		return Err(too_large());
	}
	let mut raw = Vec::new();
	std::fs::File::open(file)
		.map_err(cannot)?
		.take(limit as u64 + 1)
		.read_to_end(&mut raw)
		.map_err(cannot)?;
	if raw.len() > limit {
		return Err(too_large());
	}
	Ok(raw)
}

fn write_text(
	out: &mut impl Write,
	report: &Report,
	decision: &Decision,
	off: bool,
	refused: bool,
	inspected: bool,
) -> std::io::Result<()> {
	if report.parts.is_empty() {
		writeln!(out, "no attachments")?;
	}
	for (index, part) in report.parts.iter().enumerate() {
		writeln!(out, "part {}", index + 1)?;
		writeln!(out, "  names: {}", listed(&part.names))?;
		writeln!(out, "  declared types: {}", listed(&part.declared_types))?;
		writeln!(out, "  real type: {}", part.real_type.as_str())?;
		let reasons: Vec<&str> = part.reasons.iter().map(|reason| reason.code()).collect();
		writeln!(out, "  reasons: {}", none_or(&reasons))?;
	}
	if let Some(stop) = report.stopped {
		writeln!(out, "inspection stopped early: {}", stop_code(stop))?;
	}
	if report.ambiguous {
		writeln!(out, "the MIME structure reads two ways")?;
	}
	let reasons: Vec<&str> = decision
		.reasons
		.iter()
		.map(|reason| reason.code())
		.collect();
	let action = action_name(decision.action);
	if off {
		writeln!(out, "verdict: {action} (mode = \"off\" inspects nothing)")?;
	} else if reasons.is_empty() {
		writeln!(out, "verdict: {action}")?;
	} else {
		writeln!(out, "verdict: {action} ({})", reasons.join(", "))?;
	}
	let note = if inspected {
		""
	} else {
		" (scan_authenticated = false)"
	};
	writeln!(
		out,
		"a submission would be {}{note}",
		if refused { "refused" } else { "accepted" }
	)
}

fn part_json(part: &PartReport) -> serde_json::Value {
	serde_json::json!({
		"names": part.names,
		"declared-types": part.declared_types,
		"real-type": part.real_type.as_str(),
		"reasons": part.reasons.iter().map(|reason| reason.code()).collect::<Vec<_>>(),
	})
}

/// Values from the message, each escaped for a terminal, comma separated.
fn listed(values: &[String]) -> String {
	let shown: Vec<String> = values.iter().map(|value| escaped(value)).collect();
	none_or(&shown)
}

fn none_or<T: AsRef<str>>(values: &[T]) -> String {
	if values.is_empty() {
		return "(none)".to_string();
	}
	values
		.iter()
		.map(AsRef::as_ref)
		.collect::<Vec<_>>()
		.join(", ")
}

/// `text` with control, formatting and other invisible characters written
/// as `\u{..}` escapes, as Rust's `Debug` writes them, and nothing else
/// changed except `"` and `\`.
fn escaped(text: &str) -> String {
	let quoted = format!("{text:?}");
	quoted[1..quoted.len() - 1].to_string()
}

fn action_name(action: Action) -> &'static str {
	match action {
		Action::Deliver => "deliver",
		Action::Flag => "flag",
		Action::Quarantine => "quarantine",
		Action::Reject => "reject",
	}
}

fn stop_code(stop: Stop) -> &'static str {
	match stop {
		Stop::TooDeep => "too-deep",
		Stop::TooManyParts => "too-many-parts",
		Stop::HeaderTooLarge => "header-too-large",
		Stop::OutOfTime => "out-of-time",
	}
}
