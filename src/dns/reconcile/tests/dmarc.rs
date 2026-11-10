//! A DMARC record in place is never replaced by a weaker one.

use super::support::*;
use super::*;
use crate::dns::skip::SkipSet;

const NAME: &str = "_dmarc.example.org";

fn needed() -> DnsRecord {
	txt(
		NAME,
		"v=DMARC1; p=quarantine; rua=mailto:postmaster@example.org; adkim=s; aspf=s",
	)
}

#[test]
fn a_stricter_policy_in_place_is_kept_whoever_wrote_it() {
	let stricter = txt(
		NAME,
		"v=DMARC1; p=reject; sp=reject; np=reject; rua=mailto:postmaster@example.org; adkim=s; aspf=s",
	);
	for ledger in [
		Ledger::new(ZONE),
		ledger_of(std::slice::from_ref(&stricter)),
	] {
		let plan = plan(&[needed()], std::slice::from_ref(&stricter), &ledger);
		assert_eq!(action_for(&plan, &needed()), Action::Kept);
		assert_eq!(plan.writes(), 0);
	}
}

#[test]
fn a_weaker_policy_somebody_else_wrote_is_a_conflict() {
	// Strict alignment, so the policy is the one weaker tag.
	let weaker = txt(
		NAME,
		"v=DMARC1; p=none; rua=mailto:dmarc@example.net; adkim=s; aspf=s",
	);
	let plan = plan(&[needed()], &[weaker], &Ledger::new(ZONE));
	assert_eq!(action_for(&plan, &needed()), Action::Conflict);
	assert!(plan.entries[0].reason.contains("p=none"));
}

#[test]
fn a_weaker_policy_epistle_wrote_is_updated() {
	let weaker = txt(
		NAME,
		"v=DMARC1; p=none; rua=mailto:postmaster@example.org; adkim=s; aspf=s",
	);
	let plan = plan(
		&[needed()],
		std::slice::from_ref(&weaker),
		&ledger_of(std::slice::from_ref(&weaker)),
	);
	assert_eq!(action_for(&plan, &needed()), Action::Update);
}

#[test]
fn relaxed_alignment_is_weaker_than_strict() {
	let relaxed = txt(
		NAME,
		"v=DMARC1; p=reject; rua=mailto:postmaster@example.org; adkim=r; aspf=s",
	);
	let plan = plan(&[needed()], &[relaxed], &Ledger::new(ZONE));
	assert_eq!(action_for(&plan, &needed()), Action::Conflict);
	assert!(plan.entries[0].reason.contains("adkim"));
}

#[test]
fn a_subdomain_policy_weaker_than_the_needed_one_is_weaker() {
	let loose_sp = txt(NAME, "v=DMARC1; p=reject; sp=none; adkim=s; aspf=s");
	let plan = plan(&[needed()], &[loose_sp], &Ledger::new(ZONE));
	assert_eq!(action_for(&plan, &needed()), Action::Conflict);
	assert!(plan.entries[0].reason.contains("sp=none"));
}

#[test]
fn a_dmarc_record_that_cannot_be_read_is_a_conflict() {
	let broken = txt(NAME, "v=DMARC1; reject");
	let plan = plan(&[needed()], &[broken], &Ledger::new(ZONE));
	assert_eq!(action_for(&plan, &needed()), Action::Conflict);
	assert!(plan.entries[0].reason.contains("cannot be read"));
}

#[test]
fn a_policy_dns_lockdown_is_ramping_is_left_to_it() {
	// The lockdown starts a zone without DMARC at p=none and moves it one
	// step per run; publishing the default over it would skip the operator's
	// observation step.
	let ramping = txt(NAME, "v=DMARC1; p=none; sp=none; np=reject");
	let input = |lockdown: &[DnsRecord]| {
		plan_zone(&ZoneInput {
			zone: ZONE,
			needed: &[needed()],
			existing: std::slice::from_ref(&ramping),
			ledger: &Ledger::new(ZONE),
			also_ours: &[],
			lockdown,
			retire_within: None,
			incomplete: None,
			skip: &SkipSet::default(),
			flattens_apex_cname: false,
		})
	};
	assert_eq!(
		action_for(&input(std::slice::from_ref(&ramping)), &needed()),
		Action::Kept
	);
	assert_eq!(action_for(&input(&[]), &needed()), Action::Conflict);
}

#[test]
fn a_broken_record_is_never_rewritten_even_by_its_author() {
	let broken = txt(NAME, "v=DMARC1; reject");
	let plan = plan(
		&[needed()],
		std::slice::from_ref(&broken),
		&ledger_of(std::slice::from_ref(&broken)),
	);
	assert_eq!(action_for(&plan, &needed()), Action::Conflict);
}
