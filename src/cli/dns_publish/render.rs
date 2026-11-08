//! The text and JSON `epistle dns publish` prints. Pure functions over the
//! survey, so a test reads exactly what the operator reads. Every value read
//! from a zone is escaped before it reaches a terminal.

use std::fmt::Write as _;

use crate::cli::term::sanitize;
use crate::dns::provider::{DnsRecord, RecordKind};
use crate::dns::reconcile::survey::Survey;
use crate::dns::reconcile::undo::UndoReport;

/// A record as a zone-file line: `name TTL IN KIND value`.
fn record_line(record: &DnsRecord) -> String {
	let value = match record.kind {
		RecordKind::Txt => crate::dns::records::txt_zone_form(&record.value),
		_ => record.value.clone(),
	};
	format!(
		"{} {} IN {} {}",
		sanitize(&record.name),
		record.ttl,
		sanitize(record.kind.as_str()),
		sanitize(&value)
	)
}

/// The plan as text: one block per zone, then the zones left alone, then
/// the records left to the operator.
pub(super) fn plan_text(survey: &Survey) -> String {
	let mut text = String::new();
	for zone in &survey.zones {
		let _ = writeln!(text, "Zone {}", sanitize(&zone.plan.zone));
		if zone.plan.entries.is_empty() {
			text.push_str("  (nothing needed here)\n");
		}
		for entry in &zone.plan.entries {
			let _ = writeln!(
				text,
				"  {:<8} {}",
				entry.action_word(),
				record_line(&entry.record)
			);
			let _ = writeln!(text, "           {}", sanitize(&entry.reason));
			for value in &entry.current {
				let _ = writeln!(text, "           now: {}", sanitize(value));
			}
		}
		text.push('\n');
	}
	if !survey.failures.is_empty() {
		text.push_str("Left alone (the zone could not be read):\n");
		for failure in &survey.failures {
			let _ = writeln!(text, "  {}", sanitize(&failure.zone));
			let _ = writeln!(text, "           {}", sanitize(&failure.reason));
		}
		text.push('\n');
	}
	if !survey.by_hand.is_empty() {
		text.push_str("By hand (no [dns] entry writes these):\n");
		for item in &survey.by_hand {
			let _ = writeln!(text, "  {}", record_line(&item.record));
			let _ = writeln!(text, "           {}", sanitize(&item.reason));
		}
	}
	text
}

/// The plan as the JSON document `--json` prints.
pub(super) fn plan_json(survey: &Survey) -> serde_json::Value {
	let zones: Vec<&crate::dns::reconcile::ZonePlan> =
		survey.zones.iter().map(|z| &z.plan).collect();
	serde_json::json!({
		"zones": zones,
		"by_hand": survey.by_hand,
		"failures": survey.failures,
	})
}

/// The undo report, as text or JSON.
pub(super) fn undo_text(report: &UndoReport, json: bool) -> String {
	if json {
		return serde_json::to_string_pretty(report)
			.map(|text| text + "\n")
			.unwrap_or_default();
	}
	let mut text = String::new();
	if report.entries.is_empty() {
		text.push_str("The ledgers list nothing epistle published.\n");
	}
	for entry in &report.entries {
		let _ = writeln!(
			text,
			"  {:<8} {}",
			entry.outcome,
			record_line(&entry.record)
		);
		let _ = writeln!(text, "           {}", sanitize(&entry.reason));
	}
	text
}
