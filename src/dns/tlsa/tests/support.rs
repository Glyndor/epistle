//! A provider that holds one zone in memory, and certificates to publish.

use std::pin::Pin;
use std::sync::Mutex;

use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind};

pub(super) type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
pub(super) type ListOp<'a> =
	Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// The zone every test publishes in.
pub(super) const ZONE: &str = "example.org";

/// The mail host every test publishes for.
pub(super) const HOST: &str = "mail.example.org";

/// A provider that holds [`ZONE`] and its records. It can be told to refuse
/// writes.
pub(super) struct Zone {
	pub(super) records: Mutex<Vec<DnsRecord>>,
	pub(super) upserts: Mutex<Vec<DnsRecord>>,
	pub(super) failing: Mutex<Option<ProviderError>>,
}

impl Zone {
	pub(super) fn empty() -> Self {
		Zone::holding(Vec::new())
	}

	pub(super) fn holding(records: Vec<DnsRecord>) -> Self {
		Zone {
			records: Mutex::new(records),
			upserts: Mutex::new(Vec::new()),
			failing: Mutex::new(None),
		}
	}

	pub(super) fn fail_with(&self, error: Option<ProviderError>) {
		*self.failing.lock().expect("failing") = error;
	}

	pub(super) fn writes(&self) -> usize {
		self.upserts.lock().expect("upserts").len()
	}

	pub(super) fn values(&self) -> Vec<String> {
		self.records
			.lock()
			.expect("records")
			.iter()
			.filter(|record| record.kind == RecordKind::Tlsa)
			.map(|record| record.value.clone())
			.collect()
	}
}

impl DnsProvider for Zone {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		if let Some(error) = self.failing.lock().expect("failing").clone() {
			return Box::pin(async move { Err(error) });
		}
		self.upserts.lock().expect("upserts").push(record.clone());
		let mut records = self.records.lock().expect("records");
		records.retain(|held| !(held.name == record.name && held.kind == record.kind));
		records.push(record);
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, _zone: &str, _record: DnsRecord) -> Op<'_> {
		Box::pin(async { Ok(()) })
	}

	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone = zone.to_string();
		let records = self.records.lock().expect("records").clone();
		Box::pin(async move {
			if zone == ZONE {
				Ok(records)
			} else {
				Err(ProviderError::ZoneNotFound(zone))
			}
		})
	}
}

/// A certificate for the mail host: its PEM and its TLSA association.
pub(super) fn certificate() -> (String, String) {
	let certified =
		rcgen::generate_simple_self_signed(vec![HOST.to_string()]).expect("certificate");
	let pem = certified.cert.pem();
	let value = crate::dns::records::tlsa_full_cert(&pem).expect("association");
	(pem, value)
}
