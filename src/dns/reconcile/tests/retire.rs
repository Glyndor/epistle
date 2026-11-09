//! Records the configuration no longer needs: only epistle's own leave.

use super::run::{harness, publish, read};
use super::support::*;
use super::*;
use crate::dns::lockdown::tests::support::Zone;
use crate::dns::skip::SkipSet;

fn pop3() -> DnsRecord {
	rec(
		"_pop3s._tcp.example.org",
		RecordKind::Srv,
		"0 1 995 mail.example.org.",
	)
}

#[test]
fn epistles_own_record_the_configuration_no_longer_needs_is_removed() {
	// POP3 was turned off: its locator is no longer needed.
	let plan = plan(&[], &[pop3()], &ledger_of(&[pop3()]));
	assert_eq!(action_for(&plan, &pop3()), Action::Remove);
}

#[test]
fn a_record_epistle_did_not_publish_is_never_retired() {
	let plan = plan(&[], &[pop3()], &Ledger::new(ZONE));
	assert!(
		plan.entries.is_empty(),
		"a foreign record is not epistle's to retire: {:#?}",
		plan.entries
	);
}

#[test]
fn a_ledger_record_that_left_the_zone_is_forgotten() {
	let plan = plan(&[], &[], &ledger_of(&[pop3()]));
	assert_eq!(action_for(&plan, &pop3()), Action::Gone);
	assert!(plan.changes());
	assert_eq!(plan.writes(), 0);
}

#[test]
fn a_ledger_record_whose_value_changed_by_hand_is_forgotten_not_removed() {
	let edited = rec(
		"_pop3s._tcp.example.org",
		RecordKind::Srv,
		"0 1 1995 mail.example.org.",
	);
	let plan = plan(&[], &[edited], &ledger_of(&[pop3()]));
	assert_eq!(action_for(&plan, &pop3()), Action::Gone);
	assert_eq!(plan.writes(), 0);
}

#[test]
fn a_record_sharing_its_set_with_a_foreign_one_is_not_removed() {
	let theirs = rec(
		"_pop3s._tcp.example.org",
		RecordKind::Srv,
		"0 1 995 pop.example.net.",
	);
	let plan = plan(&[], &[pop3(), theirs], &ledger_of(&[pop3()]));
	assert_eq!(action_for(&plan, &pop3()), Action::Conflict);
	assert_eq!(plan.writes(), 0);
}

#[test]
fn a_dkim_key_is_left_to_the_rotation() {
	let key = txt("old._domainkey.example.org", "v=DKIM1; k=ed25519; p=AAAA");
	let plan = plan(
		&[],
		std::slice::from_ref(&key),
		&ledger_of(std::slice::from_ref(&key)),
	);
	assert_eq!(action_for(&plan, &key), Action::Skipped);
}

#[test]
fn a_dkim_key_under_a_selector_with_dots_is_left_to_the_rotation() {
	// No `v=DKIM1` tag (it is optional, RFC 6376 section 3.6.1), so only
	// the `_domainkey` label marks the record as a key.
	let key = txt("a.b._domainkey.example.org", "k=ed25519; p=AAAA");
	let plan = plan(
		&[],
		std::slice::from_ref(&key),
		&ledger_of(std::slice::from_ref(&key)),
	);
	assert_eq!(action_for(&plan, &key), Action::Skipped);
}

#[test]
fn a_dkim_key_at_an_unexpected_name_is_left_to_the_rotation() {
	let key = txt("keys.example.org", "v=DKIM1; k=rsa; p=AAAA");
	let plan = plan(
		&[],
		std::slice::from_ref(&key),
		&ledger_of(std::slice::from_ref(&key)),
	);
	assert_eq!(action_for(&plan, &key), Action::Skipped);
}

#[test]
fn an_incomplete_set_retires_nothing() {
	// A key or certificate that could not be read leaves records out of the
	// needed set; that is not the configuration dropping them.
	let gone = txt("old.example.org", "v=spf1 mx -all");
	let ledger = ledger_of(&[pop3(), gone.clone()]);
	let existing = [pop3()];
	let plan = plan_zone(&ZoneInput {
		zone: ZONE,
		needed: &[],
		existing: &existing,
		ledger: &ledger,
		also_ours: &[],
		lockdown: &[],
		retire_within: None,
		incomplete: Some("cannot read certificate"),
		skip: &SkipSet::default(),
	});
	assert_eq!(action_for(&plan, &pop3()), Action::Skipped);
	assert!(plan.entries.iter().any(|e| e.reason.contains("incomplete")));
	assert_eq!(action_for(&plan, &gone), Action::Gone);
	assert_eq!(plan.writes(), 0);
}

#[test]
fn a_name_delegated_since_it_was_published_is_left_alone() {
	let ours = txt("sub.example.org", "v=spf1 mx -all");
	let existing = [
		ours.clone(),
		rec("sub.example.org", RecordKind::Ns, "ns1.example.com"),
	];
	let plan = plan(&[], &existing, &ledger_of(std::slice::from_ref(&ours)));
	assert_eq!(action_for(&plan, &ours), Action::Skipped);
}

#[test]
fn retiring_is_limited_to_the_domain_the_run_was_asked_for() {
	let other = txt("other.example.org", "v=spf1 mx -all");
	let ledger = ledger_of(&[pop3(), other.clone()]);
	let existing = [pop3(), other.clone()];
	let plan = plan_zone(&ZoneInput {
		zone: ZONE,
		needed: &[],
		existing: &existing,
		ledger: &ledger,
		also_ours: &[],
		lockdown: &[],
		retire_within: Some("other.example.org"),
		incomplete: None,
		skip: &SkipSet::default(),
	});
	assert_eq!(action_for(&plan, &other), Action::Remove);
	assert!(
		!plan
			.entries
			.iter()
			.any(|e| crate::dns::rrset::same_record(&e.record, &pop3())),
		"a name outside the domain asked for is not planned"
	);
}

#[test]
fn a_ledger_record_whose_slot_is_still_needed_is_handled_as_an_update() {
	let old = rec(ZONE, RecordKind::Mx, "10 oldmail.example.org");
	let needed = [rec(ZONE, RecordKind::Mx, "10 mail.example.org")];
	let plan = plan(
		&needed,
		std::slice::from_ref(&old),
		&ledger_of(std::slice::from_ref(&old)),
	);
	assert_eq!(action_for(&plan, &needed[0]), Action::Update);
	assert_eq!(
		plan.entries.len(),
		1,
		"the old value is replaced, not also removed"
	);
}

/// A record another account writes between the listing and the removal is
/// still there when the removal is done: the publisher takes the record
/// epistle published and nothing else.
#[test]
fn a_record_another_account_wrote_in_the_meantime_is_not_removed_with_our_own() {
	let h = harness();
	let spf = txt("example.org", "v=spf1 mx -all");
	let theirs = txt("example.org", "v=spf1 include:_spf.example.net -all");
	let zone = Racing {
		zone: Zone::default(),
		foreign: theirs.clone(),
	};
	let _ = publish(&h, &zone, read(&h, &zone, std::slice::from_ref(&spf)));
	// The configuration no longer needs the record: the run retires it.
	let report = publish(&h, &zone, read(&h, &zone, &[]));
	assert!(report.failure.is_none(), "{:?}", report.failure);
	let now = zone.zone.snapshot();
	assert!(
		!holds(&now, &spf),
		"the record epistle published goes: {:#?}",
		now
	);
	assert!(
		holds(&now, &theirs),
		"a record another account wrote must survive: {:#?}",
		now
	);
}

#[test]
fn a_ledger_record_of_a_skipped_group_is_removed_and_the_reason_names_the_group() {
	let existing = [pop3()];
	let ledger = ledger_of(&[pop3()]);
	let skip = SkipSet::new([crate::dns::skip::SkipGroup::ClientLocators]);
	let plan = plan_zone(&ZoneInput {
		zone: ZONE,
		needed: &[],
		existing: &existing,
		ledger: &ledger,
		also_ours: &[],
		lockdown: &[],
		retire_within: None,
		incomplete: None,
		skip: &skip,
	});
	assert_eq!(action_for(&plan, &pop3()), Action::Remove);
	assert!(
		plan.entries
			.iter()
			.any(|e| e.reason.contains("skips the client-locators group")),
		"{:#?}",
		plan.entries
	);
}

#[test]
fn a_skipped_group_record_epistle_never_published_is_left_alone() {
	let existing = [pop3()];
	let skip = SkipSet::new([crate::dns::skip::SkipGroup::ClientLocators]);
	let plan = plan_zone(&ZoneInput {
		zone: ZONE,
		needed: &[],
		existing: &existing,
		ledger: &Ledger::new(ZONE),
		also_ours: &[],
		lockdown: &[],
		retire_within: None,
		incomplete: None,
		skip: &skip,
	});
	assert!(plan.entries.is_empty(), "{:#?}", plan.entries);
}
