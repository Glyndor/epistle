//! A CNAME at the apex of a zone whose provider flattens it.

use super::support::*;
use super::*;
use crate::dns::skip::SkipSet;

const TUNNEL: &str = "abc.cfargotunnel.com";

fn plan_with(needed: &[DnsRecord], existing: &[DnsRecord], zone: &str, flat: bool) -> ZonePlan {
	let ledger = Ledger::new(zone);
	plan_zone(&ZoneInput {
		zone,
		needed,
		existing,
		ledger: &ledger,
		also_ours: &[],
		lockdown: &[],
		retire_within: None,
		incomplete: None,
		skip: &SkipSet::default(),
		flattens_apex_cname: flat,
	})
}

fn needed_set(name: &str) -> Vec<DnsRecord> {
	vec![
		rec(name, RecordKind::Mx, "10 mail.example.org"),
		txt(name, "v=spf1 mx -all"),
		rec(name, RecordKind::Caa, "0 issue \"letsencrypt.org\""),
	]
}

#[test]
fn flattening_provider_plans_the_apex_records_next_to_the_cname() {
	let needed = needed_set("example.org");
	let cname = rec("example.org", RecordKind::Cname, TUNNEL);
	let plan = plan_with(&needed, std::slice::from_ref(&cname), ZONE, true);
	for record in &needed {
		assert_eq!(action_for(&plan, record), Action::Create, "{record:?}");
	}
	let reason = &plan.entries[0].reason;
	assert!(reason.contains("flattened"), "{reason}");
	assert!(
		plan.entries
			.iter()
			.all(|e| e.record.kind != RecordKind::Cname),
		"the CNAME is never planned: {plan:#?}"
	);
}

#[test]
fn provider_that_does_not_flatten_keeps_the_conflict() {
	let needed = needed_set("example.org");
	let cname = rec("example.org", RecordKind::Cname, TUNNEL);
	let plan = plan_with(&needed, &[cname], ZONE, false);
	for record in &needed {
		assert_eq!(action_for(&plan, record), Action::Conflict, "{record:?}");
	}
}

#[test]
fn a_cname_below_the_apex_still_blocks_even_with_flattening() {
	let needed = needed_set("mail.example.org");
	let cname = rec("mail.example.org", RecordKind::Cname, TUNNEL);
	let plan = plan_with(&needed, &[cname], ZONE, true);
	for record in &needed {
		assert_eq!(action_for(&plan, record), Action::Conflict, "{record:?}");
	}
}
