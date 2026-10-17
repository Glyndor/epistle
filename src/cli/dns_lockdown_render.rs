//! The text `epistle dns lockdown` prints: the plan (the same fields
//! `--json` prints) and the undo report. Pure functions over the plan, so
//! a test reads exactly what the operator reads.

use std::fmt::Write as _;

use crate::cli::term::sanitize;
use crate::dns::lockdown::{
	DmarcAction, DmarcPlan, DmarcStep, Plan, REPORT_WINDOW_DAYS, UndoReport, WildcardDecision,
};
use crate::dns::provider::{DnsRecord, RecordKind};

/// One record as a zone-file line: `name TTL IN KIND value`.
pub(super) fn record_line(record: &DnsRecord) -> String {
	format!(
		"{} {} IN {} {}",
		sanitize(&record.name),
		record.ttl,
		sanitize(record.kind.as_str()),
		value_text(record)
	)
}

/// A record value as a zone file writes it: TXT quoted and split. Zone
/// text is hostile, so a control character is escaped before it is printed.
fn value_text(record: &DnsRecord) -> String {
	sanitize(&match record.kind {
		RecordKind::Txt => crate::dns::records::txt_zone_form(&record.value),
		_ => record.value.clone(),
	})
}

/// The plan as text.
pub(crate) fn plan_text(plan: &Plan) -> String {
	let mut text = format!("Lockdown plan for {}\n\n", sanitize(&plan.domain));
	let _ = writeln!(
		text,
		"DMARC at {}: {}",
		sanitize(&plan.dmarc.name),
		dmarc_line(&plan.dmarc)
	);
	reports_lines(&mut text, &plan.domain, &plan.dmarc);
	text.push_str("\nRecords to add or change:\n");
	if plan.entries.is_empty() {
		text.push_str("  (none)\n");
	}
	for entry in &plan.entries {
		let _ = writeln!(text, "  + {}", record_line(&entry.record));
		let _ = writeln!(text, "      reason: {}", sanitize(&entry.reason));
		if let Some(old) = &entry.replaces {
			let _ = writeln!(text, "      replaces: {}", value_text(old));
		}
	}
	text.push_str("\nLeft as is:\n");
	if plan.skipped.is_empty() {
		text.push_str("  (none)\n");
	}
	for skip in &plan.skipped {
		let _ = writeln!(text, "  = {}", sanitize(&skip.name));
		let _ = writeln!(text, "      reason: {}", sanitize(&skip.reason));
	}
	let verdict = match plan.wildcard {
		WildcardDecision::Added { .. } => "added",
		WildcardDecision::Skipped { .. } => "not added",
		WildcardDecision::AlreadyPresent { .. } => "already there",
	};
	let _ = writeln!(
		text,
		"\nWildcard *.{}: {verdict}; {}",
		sanitize(&plan.domain),
		sanitize(plan.wildcard.reason())
	);
	text
}

fn dmarc_line(dmarc: &DmarcPlan) -> String {
	let next = dmarc.next.as_str();
	let sp = dmarc.sp.as_str();
	match &dmarc.action {
		DmarcAction::LeftAlone { reason } => format!("left as is: {}", sanitize(reason)),
		DmarcAction::Unchanged => {
			format!("already at p={next} with sp={sp} and np=reject; nothing to change")
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
			format!("{start}{why} (sp={sp}, np=reject); {then}")
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
			sanitize(&source.source_ip),
			source.messages
		);
	}
}

/// Which undo report is printed: the dry run, the preview a real run asks
/// about, or what a run that stopped partway did.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum UndoView {
	/// `--undo --dry-run`: nothing is changed.
	DryRun,
	/// What a real run is about to do, before it asks.
	Preview,
	/// What a run did before it stopped.
	Done,
}

/// The undo report as text, worded for `view`.
pub(super) fn undo_text(domain: &str, report: &UndoReport, view: UndoView) -> String {
	let mut text = format!(
		"Undo lockdown for {}{}\n",
		sanitize(domain),
		if view == UndoView::DryRun {
			" (dry run)"
		} else {
			""
		}
	);
	let (deleted, restored) = match view {
		UndoView::DryRun => ("would be deleted", "would be restored to"),
		UndoView::Preview => ("will be deleted", "will be restored to"),
		UndoView::Done => ("deleted", "restored to"),
	};
	for record in &report.deleted {
		let _ = writeln!(text, "  - {}: {deleted}", record_line(record));
	}
	for record in &report.restored {
		let _ = writeln!(
			text,
			"  - {} {}: {restored} {}",
			sanitize(record.kind.as_str()),
			sanitize(&record.name),
			value_text(record)
		);
	}
	for changed in &report.changed {
		let _ = writeln!(
			text,
			"  = {}: changed since the lockdown (now {}); left as is",
			record_line(&changed.record),
			sanitize(&changed.now.join(" | "))
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
