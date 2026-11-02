//! Records and plans for the reconcile tests.

use super::*;

pub(crate) const ZONE: &str = "example.org";

pub(crate) fn rec(name: &str, kind: RecordKind, value: &str) -> DnsRecord {
	DnsRecord::new(name, kind, value, 3600)
}

pub(crate) fn txt(name: &str, value: &str) -> DnsRecord {
	rec(name, RecordKind::Txt, value)
}

/// A ledger that holds `records`.
pub(crate) fn ledger_of(records: &[DnsRecord]) -> Ledger {
	let mut ledger = Ledger::new(ZONE);
	for record in records {
		ledger.remember(record, None, 1);
	}
	ledger
}

/// Plan `needed` against `existing` with `ledger`, retiring anywhere.
pub(crate) fn plan(needed: &[DnsRecord], existing: &[DnsRecord], ledger: &Ledger) -> ZonePlan {
	plan_zone(&ZoneInput {
		zone: ZONE,
		needed,
		existing,
		ledger,
		also_ours: &[],
		lockdown: &[],
		retire_within: None,
		incomplete: None,
	})
}

/// The action of the entry for `record` (same name, type and value).
pub(crate) fn action_for(plan: &ZonePlan, record: &DnsRecord) -> Action {
	let found: Vec<&Entry> = plan
		.entries
		.iter()
		.filter(|e| crate::dns::rrset::same_record(&e.record, record))
		.collect();
	assert_eq!(
		found.len(),
		1,
		"expected one entry for {} {} {}, plan: {:#?}",
		record.name,
		record.kind.as_str(),
		record.value,
		plan.entries
	);
	found[0].action
}

/// The SPF, MX and DMARC a domain needs.
pub(crate) fn basics() -> Vec<DnsRecord> {
	vec![
		txt(ZONE, "v=spf1 mx -all"),
		rec(ZONE, RecordKind::Mx, "10 mail.example.org"),
		txt(
			"_dmarc.example.org",
			"v=DMARC1; p=quarantine; rua=mailto:postmaster@example.org; adkim=s; aspf=s",
		),
	]
}
