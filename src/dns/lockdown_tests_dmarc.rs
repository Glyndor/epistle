//! Tests for the DMARC part of the plan: one step per run, `sp` following
//! `p`, `np=reject` at once, `--dmarc reject`, the operator's tags kept,
//! and records that cannot be rewritten left alone.

use super::tests_support::*;
use super::*;

const DMARC: &str = "_dmarc.example.org";

fn dmarc(value: &str) -> DnsRecord {
	txt(DMARC, value)
}

fn dmarc_write(plan: &Plan) -> Option<&PlanEntry> {
	plan.entries.iter().find(|e| e.record.name == DMARC)
}

fn jump() -> DmarcInputs {
	DmarcInputs {
		jump_to: Some(DmarcStep::Reject),
		..DmarcInputs::default()
	}
}

#[test]
fn the_rewrite_keeps_every_operator_tag_and_drops_pct() {
	let existing = dmarc(
		"v=DMARC1; p=none; rua=mailto:d@example.org; ruf=mailto:f@example.org; adkim=s; aspf=r; fo=1; ri=3600; pct=50; t=y",
	);
	let plan = plan(std::slice::from_ref(&existing));
	let entry = dmarc_write(&plan).expect("DMARC is rewritten");
	assert_eq!(
		entry.record.value,
		"v=DMARC1; p=quarantine; sp=quarantine; np=reject; rua=mailto:d@example.org; ruf=mailto:f@example.org; adkim=s; aspf=r; fo=1; ri=3600; t=y"
	);
	assert_eq!(entry.replaces, Some(existing));
	assert_eq!(
		entry.reason,
		"move _dmarc.example.org from p=none to p=quarantine; sp follows p; np=reject; the other tags stay as written; pct is dropped (DMARCbis)"
	);
}

#[test]
fn no_record_starts_at_quarantine() {
	let plan = plan(&[]);
	let entry = dmarc_write(&plan).expect("DMARC is published");
	assert_eq!(
		entry.record.value,
		"v=DMARC1; p=quarantine; sp=quarantine; np=reject"
	);
	assert_eq!(entry.replaces, None);
	assert_eq!(plan.dmarc.current, None);
	assert_eq!(plan.dmarc.next, DmarcStep::Quarantine);
}

#[test]
fn quarantine_moves_to_reject_and_sp_follows() {
	let plan = plan(&[dmarc(
		"v=DMARC1; p=quarantine; sp=none; rua=mailto:d@example.org",
	)]);
	assert_eq!(
		dmarc_write(&plan).expect("rewrite").record.value,
		"v=DMARC1; p=reject; sp=reject; np=reject; rua=mailto:d@example.org"
	);
	assert_eq!(plan.dmarc.current, Some(DmarcStep::Quarantine));
	assert_eq!(plan.dmarc.next, DmarcStep::Reject);
	assert!(plan.dmarc.steps_up());
}

#[test]
fn a_complete_reject_is_unchanged() {
	let plan = plan(&[dmarc(
		"v=DMARC1;p=REJECT;sp=reject;np=reject;rua=mailto:d@example.org",
	)]);
	assert!(dmarc_write(&plan).is_none(), "{plan:?}");
	assert_eq!(plan.dmarc.action, DmarcAction::Unchanged);
	assert!(!plan.dmarc.steps_up());
}

#[test]
fn reject_without_np_or_with_pct_is_completed_not_moved() {
	for value in [
		"v=DMARC1; p=reject; sp=reject",
		"v=DMARC1; p=reject; sp=reject; np=reject; pct=100",
	] {
		let plan = plan(&[dmarc(value)]);
		assert_eq!(
			dmarc_write(&plan).expect("rewrite").record.value,
			"v=DMARC1; p=reject; sp=reject; np=reject",
			"{value}"
		);
		assert!(!plan.dmarc.steps_up(), "{value}");
	}
}

#[test]
fn dmarc_reject_jumps_straight_there() {
	let plan = plan_with(&[dmarc("v=DMARC1; p=none")], None, &jump());
	assert_eq!(
		dmarc_write(&plan).expect("rewrite").record.value,
		"v=DMARC1; p=reject; sp=reject; np=reject"
	);
	assert!(plan.dmarc.jumped);
}

#[test]
fn a_record_that_cannot_be_read_is_left_alone() {
	let cases = [
		(
			"v=DMARC1; p=rejcet",
			"p=rejcet is not none, quarantine or reject",
		),
		(
			"v=DMARC1; p=none; sp=strict",
			"sp=strict is not none, quarantine or reject",
		),
		("v=DMARC1; rua=mailto:d@example.org", "it has no p= tag"),
		("v=DMARC1; p=none; rua", "\"rua\" has no ="),
		("v=DMARC1; p=none; p=reject", "the p tag is written twice"),
	];
	for (value, problem) in cases {
		let plan = plan(&[dmarc(value)]);
		assert!(dmarc_write(&plan).is_none(), "{value}: {plan:?}");
		assert_eq!(
			plan.dmarc.action,
			DmarcAction::LeftAlone {
				reason: format!(
					"_dmarc.example.org is not a DMARC record this command can rewrite ({problem}); fix it by hand"
				)
			},
			"{value}"
		);
	}
}

#[test]
fn a_value_that_does_not_open_with_the_version_is_refused() {
	// Receivers ignore such a TXT, so the plan writes a real DMARC record
	// next to it; read on its own, it is refused.
	assert_eq!(
		parse_dmarc("p=none; v=DMARC1"),
		Err("it does not start with v=DMARC1".to_string())
	);
}

#[test]
fn a_dmarc_name_that_is_a_cname_is_left_alone() {
	// DMARC handed to a reporting service by CNAME: a TXT next to it would
	// be invalid DNS.
	let plan = plan(&[rec(
		DMARC,
		RecordKind::Cname,
		"example-org.dmarc.example.net",
	)]);
	assert!(dmarc_write(&plan).is_none(), "{plan:?}");
	assert_eq!(
		plan.dmarc.action,
		DmarcAction::LeftAlone {
			reason: "_dmarc.example.org is a CNAME (the DMARC policy is published where it points), and no other record may sit next to a CNAME (RFC 1034 section 3.6.2); change it there".into()
		}
	);
}

#[test]
fn two_dmarc_records_are_left_alone() {
	let plan = plan(&[dmarc("v=DMARC1; p=none"), dmarc("v=DMARC1; p=reject")]);
	assert!(dmarc_write(&plan).is_none());
	assert_eq!(
		plan.dmarc.action,
		DmarcAction::LeftAlone {
			reason: "_dmarc.example.org has 2 DMARC records, and receivers ignore all of them (RFC 7489 section 6.6.3); remove all but one by hand".into()
		}
	);
}

#[test]
fn a_dmarc_record_this_command_wrote_is_not_the_one_to_restore() {
	let ours = dmarc("v=DMARC1; p=quarantine; sp=quarantine; np=reject");
	let journal = Journal {
		domain: "example.org".into(),
		entries: vec![JournalEntry {
			record: ours.clone(),
			replaced: Some(dmarc("v=DMARC1; p=none")),
		}],
	};
	let plan = plan_with(&[ours], Some(&journal), &DmarcInputs::default());
	let entry = dmarc_write(&plan).expect("next step");
	assert_eq!(
		entry.record.value,
		"v=DMARC1; p=reject; sp=reject; np=reject"
	);
	assert_eq!(entry.replaces, None);
}

#[test]
fn failing_senders_are_carried_into_the_plan() {
	let inputs = DmarcInputs {
		jump_to: None,
		has_reports: true,
		failing_sources: vec![FailingSource {
			source_ip: "198.51.100.7".into(),
			messages: 12,
		}],
	};
	let plan = plan_with(&[dmarc("v=DMARC1; p=none")], None, &inputs);
	assert!(plan.dmarc.has_reports);
	assert_eq!(plan.dmarc.failing_sources, inputs.failing_sources);
	assert!(plan.dmarc.steps_up());
}
