//! Switching a domain to `send-only` retires what the publisher wrote for
//! the groups the role leaves out, through the ledger, and nothing else.

use super::support::*;
use super::*;
use crate::config::Config;
use crate::dns::skip::SkipSet;

fn needed(extra: &str) -> Vec<DnsRecord> {
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n{extra}"
	))
	.expect("config");
	crate::dns::desired::from_config(&config)
		.expect("set")
		.records
		.into_iter()
		.map(|r| r.record)
		.collect()
}

fn mta_sts() -> DnsRecord {
	txt("_mta-sts.example.org", "v=STSv1; id=1")
}

fn locator() -> DnsRecord {
	rec(
		"_imaps._tcp.example.org",
		RecordKind::Srv,
		"0 1 993 mail.example.org.",
	)
}

fn by_hand() -> DnsRecord {
	rec(
		"_imap._tcp.example.org",
		RecordKind::Srv,
		"0 1 143 imap.example.net.",
	)
}

fn plan_for(needed: &[DnsRecord], existing: &[DnsRecord], ledger: &Ledger) -> ZonePlan {
	plan_zone(&ZoneInput {
		zone: ZONE,
		needed,
		existing,
		ledger,
		also_ours: &[],
		lockdown: &[],
		retire_within: None,
		incomplete: None,
		skip: &SkipSet::default(),
		flattens_apex_cname: false,
	})
}

#[test]
fn the_records_a_send_only_role_leaves_out_are_retired_through_the_ledger() {
	let send_only = needed("send_only_domains = ['example.org']\n[[listeners]]\nkind = 'imaps'\n");
	let existing = [mta_sts(), locator()];
	let plan = plan_for(&send_only, &existing, &ledger_of(&existing));
	assert_eq!(action_for(&plan, &mta_sts()), Action::Remove);
	assert_eq!(action_for(&plan, &locator()), Action::Remove);
}

#[test]
fn a_full_domain_keeps_them() {
	let full = needed("[[listeners]]\nkind = 'imaps'\n");
	let existing = [mta_sts(), locator()];
	let plan = plan_for(&full, &existing, &ledger_of(&existing));
	assert!(
		!plan.entries.iter().any(|e| e.action == Action::Remove),
		"{:#?}",
		plan.entries
	);
}

#[test]
fn a_record_of_an_omitted_group_that_epistle_did_not_write_is_left_alone() {
	let send_only = needed("send_only_domains = ['example.org']\n[[listeners]]\nkind = 'imaps'\n");
	// The locator is epistle's; the other SRV was put there by the operator.
	let existing = [locator(), by_hand()];
	let plan = plan_for(&send_only, &existing, &ledger_of(&[locator()]));
	assert_eq!(action_for(&plan, &locator()), Action::Remove);
	assert!(
		!plan
			.entries
			.iter()
			.any(|e| crate::dns::rrset::same_record(&e.record, &by_hand())),
		"a foreign record is not epistle's to retire: {:#?}",
		plan.entries
	);
}
