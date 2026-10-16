//! `epistle evidence key show|rotate`: the key that signs the daily seals,
//! which a third party anchors with `epistle evidence check --key`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use super::evidence::KeyCli;
use super::term::sanitize;
use crate::evidence::ack::Operator;
use crate::evidence::key;
use crate::evidence::rotation;

/// Run one key action.
pub(super) fn run(root: &Path, action: KeyCli, now: u64, out: &mut impl Write) -> ExitCode {
	match action {
		KeyCli::Show { json } => show(root, json, out),
		KeyCli::Rotate { yes, json } => rotate(root, yes, now, json, out),
	}
}

fn show(root: &Path, as_json: bool, out: &mut impl Write) -> ExitCode {
	let periods = match rotation::periods(root) {
		Ok(periods) => periods,
		Err(error) => {
			super::style::error(format_args!("evidence key: {}", error.kind()));
			return ExitCode::FAILURE;
		}
	};
	let Some((current, _)) = periods.first() else {
		return super::exit::refused(
			"no evidence key yet: it is made when the first message is accepted",
		);
	};
	let pem = std::fs::read_to_string(key::public_key_path(root, current)).unwrap_or_default();
	let previous: Vec<_> = periods[1..]
		.iter()
		.map(|(id, until)| json!({ "key": id, "until": until }))
		.collect();
	if as_json {
		return super::evidence::json(
			out,
			&json!({ "key": current, "public_key": pem, "previous": previous }),
		);
	}
	let _ = writeln!(out, "evidence key: {current}");
	for (previous, until) in &periods[1..] {
		let until = until.as_deref().unwrap_or("?");
		let _ = writeln!(out, "took over from: {previous} (until {until})");
	}
	let _ = writeln!(out, "{pem}");
	let _ = writeln!(
		out,
		"publish the key above with the period of each earlier one, and give them \
		 to epistle evidence check --key: the current one bare, each earlier one as KEY@UNTIL"
	);
	ExitCode::SUCCESS
}

fn rotate(root: &Path, yes: bool, now: u64, as_json: bool, out: &mut impl Write) -> ExitCode {
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
	let question = "Rotate the evidence key? The old key signs the hand-over, so anyone who anchored it \
	                still follows the new one. Publish the new key's id afterwards. [y/N] ";
	if let Err(code) =
		super::prompt::confirm_destructive("rotating the evidence key", question, yes)
	{
		return code;
	}
	let timestamp = crate::evidence::tsa::settings::load(root)
		.map(|settings| settings.enabled)
		.unwrap_or(true);
	let new = match rotation::rotate(root, timestamp, now) {
		Ok(new) => new,
		Err(error) => {
			super::style::error(format_args!(
				"rotating the evidence key: {}",
				sanitize(&error.to_string())
			));
			return ExitCode::FAILURE;
		}
	};
	if as_json {
		return super::evidence::json(out, &json!({ "key": new, "operator": operator.as_str() }));
	}
	let _ = writeln!(out, "evidence key rotated; the new key is {new}");
	ExitCode::SUCCESS
}
