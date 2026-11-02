//! The ledger of the records epistle published in one zone.
//!
//! Own versus foreign is decided here and nowhere else. The description a
//! provider stores next to a record and the tags some providers offer are
//! labels: only a few providers have them, none lets epistle choose a record
//! id, and an operator can copy them by hand. A record is epistle's when the
//! ledger holds it with this name, type and value, so a record somebody else
//! wrote is never replaced or removed, whatever its label says.

use serde::{Deserialize, Serialize};

use super::slot::same_slot;
use crate::dns::provider::DnsRecord;
use crate::dns::rrset::same_record;

/// The ledger of one zone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
	/// The zone the ledger is for.
	pub zone: String,
	/// The records epistle published there, oldest first.
	pub entries: Vec<LedgerEntry>,
}

/// One record epistle published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
	/// The record as it was written.
	pub record: DnsRecord,
	/// The provider's own id for the record, when its answer carried one.
	/// Opaque: kept and shown, never parsed.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub identity: Option<String>,
	/// The epistle release that wrote it.
	pub release: String,
	/// When it was written, in seconds since the epoch.
	pub at: u64,
}

impl Ledger {
	/// An empty ledger for `zone`.
	pub fn new(zone: impl Into<String>) -> Self {
		Ledger {
			zone: zone.into(),
			entries: Vec::new(),
		}
	}

	/// The records the ledger holds.
	pub fn records(&self) -> Vec<DnsRecord> {
		self.entries.iter().map(|e| e.record.clone()).collect()
	}

	/// Whether the ledger holds `record`: same name, type and value.
	pub fn owns(&self, record: &DnsRecord) -> bool {
		self.entries.iter().any(|e| same_record(&e.record, record))
	}

	/// Note that `record` was written at `at`. It takes the place of the
	/// entry in the same slot, the value it replaced.
	pub fn remember(&mut self, record: &DnsRecord, identity: Option<String>, at: u64) {
		self.entries.retain(|e| !same_slot(&e.record, record));
		self.entries.push(LedgerEntry {
			record: record.clone(),
			identity,
			release: env!("CARGO_PKG_VERSION").to_string(),
			at,
		});
	}

	/// Forget `record`: it was removed from the zone, or is no longer there.
	pub fn forget(&mut self, record: &DnsRecord) {
		self.entries.retain(|e| !same_record(&e.record, record));
	}
}
