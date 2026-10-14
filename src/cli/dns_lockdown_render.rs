//! The text `epistle dns lockdown` prints: the plan (the same fields
//! `--json` prints) and the undo report. Pure functions over the plan, so
//! a test reads exactly what the operator reads.

use std::fmt::Write as _;

use crate::dns::lockdown::{
	DmarcAction, DmarcPlan, DmarcStep, Plan, REPORT_WINDOW_DAYS, UndoReport, WildcardDecision,
};
use crate::dns::provider::{DnsRecord, RecordKind};

/// One record as a zone-file line: `name TTL IN KIND value`.
pub(super) fn record_line(record: &DnsRecord) -> String {
	format!(
		"{} {} IN {} {}",
		record.name,
		record.ttl,
		record.kind.as_str(),
		value_text(record)
	)
}

/// A record value as a zone file writes it: TXT quoted and split.
fn value_text(record: &DnsRecord) -> String {
	match record.kind {
		RecordKind::Txt => crate::dns::records::txt_zone_form(&record.value),
		_ => record.value.clone(),
	}
}

/// The plan as text.
pub(crate) fn plan_text(plan: &Plan) -> String {
	let mut text = format!("Lockdown plan for {}\n\n", plan.domain);
	let _ = writeln!(
		text,
		"DMARC at {}: {}",
		plan.dmarc.name,
		dmarc_line(&plan.dmarc)
	);
	reports_lines(&mut text, &plan.domain, &plan.dmarc);
	text.push_str("\nRecords to add or change:\n");
	if plan.entries.is_empty() {
		text.push_str("  (none)\n");
	}
	for entry in &plan.entries {
		let _ = writeln!(text, "  + {}", record_line(&entry.record));
		let _ = writeln!(text, "      reason: {}", entry.reason);
		if let Some(old) = &entry.replaces {
			let _ = writeln!(text, "      replaces: {}", value_text(old));
		}
	}
	text.push_str("\nLeft as is:\n");
	if plan.skipped.is_empty() {
		text.push_str("  (none)\n");
	}
	for skip in &plan.skipped {
		let _ = writeln!(text, "  = {}", skip.name);
		let _ = writeln!(text, "      reason: {}", skip.reason);
	}
	let verdict = match plan.wildcard {
		WildcardDecision::Added { .. } => "added",
		WildcardDecision::Skipped { .. } => "not added",
		WildcardDecision::AlreadyPresent { .. } => "already there",
	};
	let _ = writeln!(
		text,
		"\nWildcard *.{}: {verdict}; {}",
		plan.domain,
		plan.wildcard.reason()
	);
	text
}

fn dmarc_line(dmarc: &DmarcPlan) -> String {
	let next = dmarc.next.as_str();
	match &dmarc.action {
		DmarcAction::LeftAlone { reason } => format!("left as is: {reason}"),
		DmarcAction::Unchanged => {
			format!("already at p={next} with sp={next} and np=reject; nothing to change")
		}
		DmarcAction::Publish => {
			let start = match dmarc.current {
				None => format!("no record yet; this run publishes p={next}"),
				Some(current) => format!("p={} now; this run sets p={next}", current.as_str()),
			};
			let why = if dmarc.jumped { " as --dmarc asks" } else { "" };
			let then = if dmarc.next == DmarcStep::Reject {
				"p=reject is the last step"
			} else {
				"the next run moves it one more step, to p=reject"
			};
			format!("{start}{why} (sp={next}, np=reject); {then}")
		}
	}
}

fn reports_lines(text: &mut String, domain: &str, dmarc: &DmarcPlan) {
	let window = format!("for {domain} in the last {REPORT_WINDOW_DAYS} days");
	if !dmarc.has_reports {
		let _ = writeln!(
			text,
			"DMARC aggregate reports: none received {window}, so no sender can be checked before the policy changes."
		);
		return;
	}
	if dmarc.failing_sources.is_empty() {
		let _ = writeln!(
			text,
			"DMARC aggregate reports: no sender failed DMARC {window}."
		);
		return;
	}
	if dmarc.steps_up() {
		let _ = writeln!(
			text,
			"warning: these senders failed DMARC {window}; authorise each one that is yours (SPF or DKIM) before the policy gets stricter, or its mail will be quarantined or rejected:"
		);
	} else {
		let _ = writeln!(
			text,
			"DMARC aggregate reports: these senders failed DMARC {window}:"
		);
	}
	for source in &dmarc.failing_sources {
		let _ = writeln!(
			text,
			"  - {} ({} messages)",
			source.source_ip, source.messages
		);
	}
}

/// The undo report as text. `dry_run` words it as what would happen.
pub(super) fn undo_text(domain: &str, report: &UndoReport, dry_run: bool) -> String {
	let mut text = format!(
		"Undo lockdown for {domain}{}\n",
		if dry_run { " (dry run)" } else { "" }
	);
	let (deleted, restored) = if dry_run {
		("would be deleted", "would be restored to")
	} else {
		("deleted", "restored to")
	};
	for record in &report.deleted {
		let _ = writeln!(text, "  - {}: {deleted}", record_line(record));
	}
	for record in &report.restored {
		let _ = writeln!(
			text,
			"  - {} {}: {restored} {}",
			record.kind.as_str(),
			record.name,
			value_text(record)
		);
	}
	for changed in &report.changed {
		let _ = writeln!(
			text,
			"  = {}: changed since the lockdown (now {}); left as is",
			record_line(&changed.record),
			changed.now.join(" | ")
		);
	}
	for record in &report.absent {
		let _ = writeln!(text, "  = {}: already gone", record_line(record));
	}
	if report == &UndoReport::default() {
		text.push_str("  (nothing in the journal)\n");
	}
	text
}
