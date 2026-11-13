//! The text and JSON `epistle dns publish` prints. Pure functions over the
//! survey, so a test reads exactly what the operator reads. Every value read
//! from a zone is escaped before it reaches a terminal.

use std::fmt::Write as _;

use crate::cli::term::sanitize;
use crate::dns::provider::{DnsRecord, RecordKind};
use crate::dns::publish::provider::Guard;
use crate::dns::reconcile::survey::{Survey, ZoneRun};
use crate::dns::reconcile::undo::UndoReport;
use crate::dns::skip::SkippedGroup;

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

/// What the operator reads under a zone whose provider takes no condition on
/// a write.
const UNGUARDED_NOTE: &str = "  note: this provider takes no precondition on a write. A record another account adds to one of these names between the listing and the write can be overwritten or lost; there is no way to close that window with this provider.\n";

/// Whether the plan writes to a zone whose provider checks no precondition.
fn unguarded(zone: &ZoneRun) -> bool {
	zone.snapshot.guard == Guard::Unchecked && zone.plan.writes() > 0
}

/// The plan as text: one block per zone, then the groups the configuration
/// skips, then the zones left alone, then the records left to the operator.
pub(super) fn plan_text(survey: &Survey, skipped: &[SkippedGroup]) -> String {
	let mut text = String::new();
	for zone in &survey.zones {
		let _ = writeln!(text, "Zone {}", sanitize(&zone.plan.zone));
		if zone.plan.entries.is_empty() {
			text.push_str("  (nothing needed here)\n");
		}
		if unguarded(zone) {
			text.push_str(UNGUARDED_NOTE);
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
	if !skipped.is_empty() {
		text.push_str("Skipped by configuration (epistle publishes none of these):\n");
		for entry in skipped {
			let _ = writeln!(text, "  {}", sanitize(entry.group.name()));
			for record in &entry.records {
				let _ = writeln!(text, "    {}", record_line(&record.record));
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
pub(super) fn plan_json(survey: &Survey, skipped: &[SkippedGroup]) -> serde_json::Value {
	let zones: Vec<&crate::dns::reconcile::ZonePlan> =
		survey.zones.iter().map(|z| &z.plan).collect();
	serde_json::json!({
		"zones": zones,
		"by_hand": survey.by_hand,
		"failures": survey.failures,
		"unguarded": survey.zones.iter().filter(|z| unguarded(z)).map(|z| z.plan.zone.as_str()).collect::<Vec<_>>(),
		"skipped": skipped_json(skipped),
	})
}

/// The groups the configuration skips, and the records they hold.
fn skipped_json(skipped: &[SkippedGroup]) -> serde_json::Value {
	serde_json::Value::Array(
		skipped
			.iter()
			.map(|entry| {
				serde_json::json!({
					"group": entry.group.name(),
					"records": entry.records.iter().map(|record| serde_json::json!({
						"name": record.record.name, "ttl": record.record.ttl,
						"type": record.record.kind.as_str(), "value": record.record.value,
					})).collect::<Vec<_>>(),
				})
			})
			.collect(),
	)
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
