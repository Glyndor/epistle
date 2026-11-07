//! Records and plans for the reconcile tests.

use super::*;
use crate::dns::lockdown::tests::support::Zone;
use crate::dns::provider::DnsProvider;
use crate::dns::rrset::same_record;

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

/// Whether the zone holds `record`.
pub(crate) fn holds(zone: &[DnsRecord], record: &DnsRecord) -> bool {
	zone.iter().any(|r| same_record(r, record))
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

/// A zone that lets another account write into it between the listing and
/// the removal: the foreign record goes in just before the delete is
/// answered.
///
/// The ordinary delete follows the write rule of the provider contract and
/// takes the whole set of the kind (a TXT of the same purpose goes with it);
/// the exact delete takes the record with the value and nothing else.
pub(crate) struct Racing {
	/// The zone the records live in.
	pub(crate) zone: Zone,
	/// The record another account writes, at the moment of the removal.
	pub(crate) foreign: DnsRecord,
}

impl DnsProvider for Racing {
	fn upsert(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		self.zone.upsert(zone, record)
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		self.zone.delete(zone, record)
	}
	fn delete_exact(&self, _zone: &str, record: DnsRecord) -> crate::dns::provider::Op<'_> {
		let zone = &self.zone;
		let foreign = self.foreign.clone();
		Box::pin(async move {
			// Another account writes into the same slot, right now.
			zone.records.lock().unwrap().push(foreign);
			// The exact removal takes the record with this value alone.
			zone.records
				.lock()
				.unwrap()
				.retain(|r| !same_record(r, &record));
			Ok(())
		})
	}
	fn list(&self, zone: &str) -> crate::dns::provider::ListOp<'_> {
		self.zone.list(zone)
	}
}
