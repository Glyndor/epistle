//! Shared pieces for the lockdown tests: record builders, the default
//! served names, and a provider that keeps a zone in memory and honours
//! the upsert/delete contract of [`crate::dns::provider`].

use std::sync::Mutex;

use super::*;
use crate::dns::provider::{DnsProvider, ProviderError, same_txt_purpose};

type Op<'a> = std::pin::Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> =
	std::pin::Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

pub(crate) fn rec(name: &str, kind: RecordKind, value: &str) -> DnsRecord {
	DnsRecord::new(name, kind, value, TTL)
}

pub(crate) fn a(name: &str) -> DnsRecord {
	rec(name, RecordKind::A, "192.0.2.10")
}

pub(crate) fn txt(name: &str, value: &str) -> DnsRecord {
	rec(name, RecordKind::Txt, value)
}

pub(crate) fn mx(name: &str, value: &str) -> DnsRecord {
	rec(name, RecordKind::Mx, value)
}

/// `example.org` hosted on `mail.example.org`.
pub(crate) fn served(existing: &[DnsRecord]) -> ServedNames {
	ServedNames::new(&["example.org".to_string()], "mail.example.org", existing)
}

/// The plan for `example.org` against `existing`.
pub(crate) fn plan_with(
	existing: &[DnsRecord],
	journal: Option<&Journal>,
	dmarc: &DmarcInputs,
) -> Plan {
	let served = served(existing);
	build_plan(&PlanInput {
		domain: "example.org",
		served: &served,
		existing,
		journal,
		dmarc,
		zone_listed: true,
	})
}

pub(crate) fn plan(existing: &[DnsRecord]) -> Plan {
	plan_with(existing, None, &DmarcInputs::default())
}

/// The records the plan writes at `name`, as `KIND value`.
pub(crate) fn writes_at(plan: &Plan, name: &str) -> Vec<String> {
	plan.entries
		.iter()
		.filter(|e| e.record.name == name)
		.map(|e| format!("{} {}", e.record.kind.as_str(), e.record.value))
		.collect()
}

/// The reason the plan gives for leaving `name` alone.
pub(crate) fn skip_reason(plan: &Plan, name: &str) -> Option<String> {
	plan.skipped
		.iter()
		.find(|s| s.name == name)
		.map(|s| s.reason.clone())
}

/// A zone in memory. `fail_on` makes the n-th write (upsert or delete,
/// counted from 1) fail without changing anything.
#[derive(Default)]
pub(crate) struct Zone {
	pub(crate) records: Mutex<Vec<DnsRecord>>,
	pub(crate) writes: Mutex<u32>,
	pub(crate) fail_on: Option<u32>,
}

impl Zone {
	pub(crate) fn with(records: Vec<DnsRecord>) -> Self {
		Zone {
			records: Mutex::new(records),
			..Zone::default()
		}
	}

	pub(crate) fn snapshot(&self) -> Vec<DnsRecord> {
		self.records.lock().unwrap().clone()
	}

	fn count_write(&self) -> Result<(), ProviderError> {
		let mut writes = self.writes.lock().unwrap();
		*writes += 1;
		if Some(*writes) == self.fail_on {
			return Err(ProviderError::Remote("rate limited".into()));
		}
		Ok(())
	}
}

/// The contract: TXT matches by purpose, every other kind by name and kind.
fn same_place(a: &DnsRecord, b: &DnsRecord) -> bool {
	a.name == b.name
		&& a.kind == b.kind
		&& (a.kind != RecordKind::Txt || same_txt_purpose(&a.value, &b.value))
}

impl DnsProvider for Zone {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		let outcome = self.count_write().map(|()| {
			let mut records = self.records.lock().unwrap();
			records.retain(|r| !same_place(r, &record));
			records.push(record);
		});
		Box::pin(async move { outcome })
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		let outcome = self.count_write().map(|()| {
			self.records
				.lock()
				.unwrap()
				.retain(|r| !same_place(r, &record));
		});
		Box::pin(async move { outcome })
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		let records = self.snapshot();
		Box::pin(async move { Ok(records) })
	}
}
