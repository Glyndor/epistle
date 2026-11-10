//! The records the configuration needs: create what is missing, never
//! replace what somebody else wrote, repair epistle's own.

use super::support::*;
use super::*;
use crate::dns::skip::SkipSet;

#[test]
fn an_empty_zone_gets_every_needed_record() {
	let needed = basics();
	let plan = plan(&needed, &[], &Ledger::new(ZONE));
	for record in &needed {
		assert_eq!(action_for(&plan, record), Action::Create);
	}
	assert_eq!(plan.writes(), 3);
}

#[test]
fn a_zone_that_already_matches_plans_nothing() {
	let needed = basics();
	let plan = plan(&needed, &needed, &ledger_of(&needed));
	for record in &needed {
		assert_eq!(action_for(&plan, record), Action::Present);
	}
	assert!(!plan.changes(), "a second run must change nothing");
}

#[test]
fn a_record_somebody_else_wrote_with_the_needed_value_is_adopted_not_claimed() {
	let needed = basics();
	let plan = plan(&needed, &needed, &Ledger::new(ZONE));
	for record in &needed {
		assert_eq!(action_for(&plan, record), Action::Adopted);
	}
	assert_eq!(plan.writes(), 0);
}

#[test]
fn a_foreign_spf_with_another_value_is_a_conflict_and_is_not_written() {
	let needed = [txt(ZONE, "v=spf1 mx -all")];
	let theirs = txt(ZONE, "v=spf1 include:_spf.example.net -all");
	let plan = plan(&needed, std::slice::from_ref(&theirs), &Ledger::new(ZONE));
	assert_eq!(action_for(&plan, &needed[0]), Action::Conflict);
	assert_eq!(plan.entries[0].current, vec![theirs.value]);
	assert_eq!(plan.writes(), 0);
}

/// The reason of a conflict carries a value read from the zone, and it
/// reaches the server log: a control character in it must not repaint the
/// terminal of the operator nor add a line to the log.
#[test]
fn the_reason_of_a_conflict_escapes_the_value_read_from_the_zone() {
	let needed = [txt(ZONE, "v=spf1 mx -all")];
	let theirs = txt(ZONE, "v=spf1 \u{1b}[31mred\u{1b}[0m -all\ninjected line");
	let plan = plan(&needed, std::slice::from_ref(&theirs), &Ledger::new(ZONE));
	assert_eq!(action_for(&plan, &needed[0]), Action::Conflict);
	let reason = &plan.entries[0].reason;
	assert!(
		!reason.contains('\n'),
		"a value from the zone cannot add a line to the log: {reason:?}"
	);
	assert!(
		!reason.contains('\u{1b}'),
		"a value from the zone cannot repaint the terminal: {reason:?}"
	);
	assert!(
		reason.contains("\\u{1b}"),
		"the escape is shown escaped: {reason:?}"
	);
	assert!(
		reason.contains("\\n"),
		"the newline is shown escaped: {reason:?}"
	);
}

#[test]
fn epistles_own_spf_with_another_value_is_updated() {
	let needed = [txt(ZONE, "v=spf1 mx -all")];
	let ours = txt(ZONE, "v=spf1 a mx -all");
	let plan = plan(
		&needed,
		std::slice::from_ref(&ours),
		&ledger_of(std::slice::from_ref(&ours)),
	);
	assert_eq!(action_for(&plan, &needed[0]), Action::Update);
}

#[test]
fn a_foreign_mx_set_without_the_needed_exchange_is_a_conflict() {
	// Every provider replaces the whole MX set on a write, so adding the
	// needed exchange would drop the operator's.
	let needed = [rec(ZONE, RecordKind::Mx, "10 mail.example.org")];
	let theirs = rec(ZONE, RecordKind::Mx, "10 mx.old.example.net");
	let plan = plan(&needed, &[theirs], &Ledger::new(ZONE));
	assert_eq!(action_for(&plan, &needed[0]), Action::Conflict);
}

#[test]
fn a_foreign_backup_exchange_next_to_the_needed_one_is_left_alone() {
	let needed = [rec(ZONE, RecordKind::Mx, "10 mail.example.org")];
	let backup = rec(ZONE, RecordKind::Mx, "20 backup.example.net");
	let plan = plan(&needed, &[needed[0].clone(), backup], &Ledger::new(ZONE));
	assert_eq!(action_for(&plan, &needed[0]), Action::Adopted);
	assert_eq!(plan.writes(), 0);
}

#[test]
fn two_spf_records_are_a_conflict_even_when_one_is_the_needed_one() {
	let needed = [txt(ZONE, "v=spf1 mx -all")];
	let existing = [needed[0].clone(), txt(ZONE, "v=spf1 -all")];
	let plan = plan(&needed, &existing, &ledger_of(&needed));
	assert_eq!(action_for(&plan, &needed[0]), Action::Conflict);
}

#[test]
fn a_needed_cname_at_a_name_with_an_address_is_a_conflict() {
	let needed = [rec(
		"autoconfig.example.org",
		RecordKind::Cname,
		"mail.example.org",
	)];
	let web = rec("autoconfig.example.org", RecordKind::A, "192.0.2.80");
	let plan = plan(&needed, &[web], &Ledger::new(ZONE));
	assert_eq!(action_for(&plan, &needed[0]), Action::Conflict);
}

#[test]
fn a_needed_record_at_a_name_that_is_a_cname_is_a_conflict() {
	let needed = [txt("_dmarc.example.org", "v=DMARC1; p=reject")];
	let outsourced = rec(
		"_dmarc.example.org",
		RecordKind::Cname,
		"example.org.dmarc.example.net",
	);
	let plan = plan(&needed, &[outsourced], &Ledger::new(ZONE));
	assert_eq!(action_for(&plan, &needed[0]), Action::Conflict);
}

#[test]
fn a_name_below_a_delegation_is_skipped() {
	let needed = [txt("sub.example.org", "v=spf1 mx -all")];
	let existing = [
		rec(ZONE, RecordKind::Ns, "ns1.example.net"),
		rec("sub.example.org", RecordKind::Ns, "ns1.example.com"),
	];
	let plan = plan(&needed, &existing, &Ledger::new(ZONE));
	assert_eq!(action_for(&plan, &needed[0]), Action::Skipped);
	assert!(plan.entries[0].reason.contains("delegated"));
}

#[test]
fn the_tlsa_value_the_certificate_refresh_published_counts_as_epistles_own() {
	let needed = [rec(
		"_25._tcp.mail.example.org",
		RecordKind::Tlsa,
		"3 0 1 bbbb",
	)];
	let refreshed = rec("_25._tcp.mail.example.org", RecordKind::Tlsa, "3 0 1 aaaa");
	let input = |also: &[DnsRecord]| {
		plan_zone(&ZoneInput {
			zone: ZONE,
			needed: &needed,
			existing: std::slice::from_ref(&refreshed),
			ledger: &Ledger::new(ZONE),
			also_ours: also,
			lockdown: &[],
			retire_within: None,
			incomplete: None,
			skip: &SkipSet::default(),
			flattens_apex_cname: false,
		})
	};
	assert_eq!(
		action_for(&input(std::slice::from_ref(&refreshed)), &needed[0]),
		Action::Update
	);
	assert_eq!(action_for(&input(&[]), &needed[0]), Action::Conflict);
}

#[test]
fn two_values_in_one_whole_set_are_left_to_the_operator_when_one_is_missing() {
	let needed = [
		rec(
			"_imaps._tcp.example.org",
			RecordKind::Srv,
			"0 1 993 mail.example.org.",
		),
		rec(
			"_imaps._tcp.example.org",
			RecordKind::Srv,
			"0 1 994 mail.example.org.",
		),
	];
	let plan = plan(&needed, &needed[..1], &ledger_of(&needed[..1]));
	assert!(plan.entries.iter().all(|e| e.action == Action::Conflict));
	assert_eq!(plan.writes(), 0);
}

#[test]
fn a_name_that_is_not_valid_is_skipped() {
	let needed = [txt("bad name.example.org", "v=spf1 -all")];
	let plan = plan(&needed, &[], &Ledger::new(ZONE));
	assert_eq!(action_for(&plan, &needed[0]), Action::Skipped);
}

#[test]
fn a_record_that_differs_only_in_ttl_or_description_is_not_rewritten() {
	let needed = [txt(ZONE, "v=spf1 mx -all")];
	let mut listed = needed[0].clone();
	listed.ttl = 300;
	listed.value = "\"v=spf1 mx -all\"".into();
	let plan = plan(&needed, &[listed], &ledger_of(&needed));
	assert_eq!(action_for(&plan, &needed[0]), Action::Present);
}
