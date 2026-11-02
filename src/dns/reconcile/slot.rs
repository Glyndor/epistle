//! Where a record sits under the provider contract, and who wrote it.
//!
//! The upsert and delete contract of [`crate::dns::provider`] decides what a
//! write replaces: a TXT replaces the TXT of the same purpose (version tag)
//! at its name, or the identical value when it has no tag, and every other
//! type replaces the whole set at its name and type. A slot is that unit,
//! so a write planned for a slot is known to touch nothing outside it.

use crate::dns::names::canonical_name;
use crate::dns::provider::{DnsRecord, RecordKind, txt_purpose};
use crate::dns::rrset::same_record;

/// Whether `a` and `b` sit in the same slot: the same name and type and,
/// for a TXT, the same purpose, or the same logical value when neither has
/// a purpose.
pub(super) fn same_slot(a: &DnsRecord, b: &DnsRecord) -> bool {
	a.kind == b.kind
		&& canonical_name(&a.name) == canonical_name(&b.name)
		&& (a.kind != RecordKind::Txt
			|| match (txt_purpose(&a.value), txt_purpose(&b.value)) {
				(Some(x), Some(y)) => x == y,
				(None, None) => crate::dns::txt::same_txt_value(&a.value, &b.value),
				_ => false,
			})
}

/// The records of `existing` in the slot of `record`.
pub(super) fn slot_of<'a>(record: &DnsRecord, existing: &'a [DnsRecord]) -> Vec<&'a DnsRecord> {
	existing.iter().filter(|r| same_slot(r, record)).collect()
}

/// Whether a write to the slot of `record` replaces the whole set at the
/// name and type: every type but a TXT.
pub(super) fn whole_set(record: &DnsRecord) -> bool {
	record.kind != RecordKind::Txt
}

/// The records epistle wrote: the ones the ledger holds and the ones another
/// part of epistle published and keeps a record of (the TLSA values of the
/// certificate refresh).
pub(super) struct Owners<'a> {
	pub(super) ledger: &'a [DnsRecord],
	pub(super) also: &'a [DnsRecord],
}

impl Owners<'_> {
	/// Whether epistle wrote `record`, with this value.
	pub(super) fn owns(&self, record: &DnsRecord) -> bool {
		self.ledger
			.iter()
			.chain(self.also.iter())
			.any(|ours| same_record(ours, record))
	}
}

/// Whether `record` is a DKIM key: a name with a `_domainkey` label at any
/// position (a selector may itself contain dots), or a TXT whose value is
/// tagged `v=DKIM1` whatever its name. The DKIM rotation publishes and
/// retires those, so the publisher never retires one.
pub(super) fn is_dkim(record: &DnsRecord) -> bool {
	canonical_name(&record.name)
		.split('.')
		.any(|label| label == "_domainkey")
		|| (record.kind == RecordKind::Txt && txt_purpose(&record.value) == Some("v=DKIM1"))
}

/// The text a plan shows for the values of `records`.
pub(super) fn values(records: &[&DnsRecord]) -> Vec<String> {
	records.iter().map(|r| r.value.clone()).collect()
}
