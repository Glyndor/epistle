//! `epistle evidence export` and `epistle evidence check`.

use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use super::term::sanitize;
use crate::evidence::bundle::{self, BundleError, Selector};
use crate::evidence::record::hash_from_hex;
use crate::evidence::tsa::settings::DEFAULT_TSA_ANCHOR;
use crate::storage::MessageCrypto;

/// The anchors a check trusts: the default authority's and `extra`.
pub(super) fn anchors(extra: &[String]) -> Result<Vec<[u8; 32]>, String> {
	let mut anchors: Vec<[u8; 32]> = hash_from_hex(DEFAULT_TSA_ANCHOR).into_iter().collect();
	for anchor in extra {
		anchors.push(
			hash_from_hex(anchor)
				.ok_or_else(|| format!("{:?} is not a hex SHA-256", sanitize(anchor)))?,
		);
	}
	Ok(anchors)
}

/// The ids of the evidence keys the operator named: each is a key id, or a
/// file holding the public key (PEM) or its id.
pub(super) fn evidence_keys(given: &[String]) -> Result<Vec<String>, String> {
	given.iter().map(|value| evidence_key(value)).collect()
}

fn evidence_key(value: &str) -> Result<String, String> {
	let value = value.trim();
	// `KEY@YYYY-MM-DD`: the day an older key's period ended.
	let (target, period) = match value.rsplit_once('@') {
		Some((target, day)) if crate::evidence::day::Day::parse(day).is_some() => {
			(target, format!("@{day}"))
		}
		_ => (value, String::new()),
	};
	if hash_from_hex(target).is_some() {
		return Ok(format!("{target}{period}"));
	}
	let bytes = crate::evidence::checkpoint::read_bounded(Path::new(target), 64 * 1024)
		.ok()
		.flatten()
		.ok_or_else(|| {
			format!(
				"{:?} is neither a key id (64 hex digits) nor a readable file",
				sanitize(value)
			)
		})?;
	let text = String::from_utf8(bytes).map_err(|_| "the key file is not text".to_string())?;
	if let Some(public) = crate::evidence::key::parse_public_pem(&text) {
		return Ok(format!("{}{period}", crate::evidence::key::key_id(&public)));
	}
	match text.trim() {
		id if hash_from_hex(id).is_some() => Ok(format!("{id}{period}")),
		_ => Err(format!(
			"{:?} holds neither a PEM public key nor a key id",
			sanitize(value)
		)),
	}
}

/// Check the bundle in `dir`.
pub(super) fn check(
	dir: &Path,
	keys: &[String],
	extra: &[String],
	as_json: bool,
	out: &mut impl Write,
) -> ExitCode {
	let anchors = match anchors(extra) {
		Ok(anchors) => anchors,
		Err(why) => return super::exit::refused(why),
	};
	let keys = match evidence_keys(keys) {
		Ok(keys) => keys,
		Err(why) => return super::exit::refused(why),
	};
	let report = match bundle::check(dir, &anchors, &keys) {
		Ok(report) => report,
		Err(error) => return failed(&error),
	};
	let passed = report.passed();
	let code = match passed {
		true => ExitCode::SUCCESS,
		false => ExitCode::FAILURE,
	};
	if as_json {
		let findings: Vec<_> = report
			.findings
			.iter()
			.map(|finding| {
				json!({
					"check": sanitize(&finding.name),
					"ok": finding.result.is_ok(),
					"detail": finding.result.as_ref().err().map(|why| sanitize(why)),
				})
			})
			.collect();
		let printed = super::evidence::json(
			out,
			&json!({ "passed": passed, "findings": findings, "notes": report.notes }),
		);
		return if printed == ExitCode::SUCCESS {
			code
		} else {
			printed
		};
	}
	for finding in &report.findings {
		let _ = match &finding.result {
			Ok(()) => writeln!(out, "ok    {}", sanitize(&finding.name)),
			Err(why) => writeln!(out, "FAIL  {}: {}", sanitize(&finding.name), sanitize(why)),
		};
	}
	for note in &report.notes {
		let _ = writeln!(out, "note  {note}");
	}
	let _ = match passed {
		true => writeln!(out, "the bundle verifies"),
		false => writeln!(out, "the bundle does NOT verify"),
	};
	code
}

/// Export what `selector` names into `dir`.
pub(super) fn export(
	root: &Path,
	crypto: &MessageCrypto,
	selector: &Selector,
	dir: &Path,
	as_json: bool,
	out: &mut impl Write,
) -> ExitCode {
	let done = match bundle::export(root, crypto, selector, dir) {
		Ok(done) => done,
		Err(error) => return failed(&error),
	};
	let unsealed: Vec<String> = done.unsealed.iter().map(|day| day.name()).collect();
	if as_json {
		let messages: Vec<String> = done.messages.iter().map(ToString::to_string).collect();
		return super::evidence::json(
			out,
			&json!({
				"bundle": dir.display().to_string(),
				"messages": messages,
				"records": done.records,
				"unsealed": unsealed,
			}),
		);
	}
	let _ = writeln!(
		out,
		"exported {} records of {} messages to {}",
		done.records,
		done.messages.len(),
		sanitize(&dir.display().to_string())
	);
	if !unsealed.is_empty() {
		let _ = writeln!(
			out,
			"not included, not sealed yet: {}; export again after the day is sealed and stamped",
			unsealed.join(", ")
		);
	}
	let _ = writeln!(
		out,
		"check it with: epistle evidence check <bundle> (see its README.md)"
	);
	ExitCode::SUCCESS
}

fn failed(error: &BundleError) -> ExitCode {
	match error {
		BundleError::Refused(why) => super::exit::refused(sanitize(why)),
		BundleError::Io(error) => {
			super::style::error(format_args!("evidence bundle: {}", error.kind()));
			ExitCode::FAILURE
		}
	}
}
