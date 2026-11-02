//! The DigitalOcean upsert and delete.

use super::*;

impl DigitaloceanProvider {
	pub(super) async fn upsert_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let rel = self.relative_name(&record.name);
		let existing = self.find_records(zone, kind, &rel).await?;
		let body = Self::record_body(kind, &rel, &record)?;
		// The TXT matching rule from `src/dns/provider/mod.rs` is the
		// contract: an upsert replaces the TXT with the same
		// purpose (version tag) at that name and leaves every
		// other TXT at the name alone. Two records of the same
		// purpose are a configuration mistake (SPF returns
		// permerror, DMARC is ignored): the upsert collapses them
		// by updating the first match and deleting every other.
		// Non-TXT kinds take the whole (type, name) set, so
		// duplicates do not arise.
		if record.kind == RecordKind::Txt {
			let mut matching = existing
				.into_iter()
				.filter(|r| same_txt_purpose(&r.data, &record.value));
			match matching.next() {
				Some(primary) => {
					let primary_id = primary.id;
					self.update(zone, primary_id, body).await?;
					for dup in matching {
						self.delete_record(zone, dup.id).await?;
					}
					Ok(())
				}
				None => {
					self.create(zone, body).await?;
					Ok(())
				}
			}
		} else {
			let mut found = existing.into_iter();
			match found.next() {
				Some(prev) => {
					self.update(zone, prev.id, body).await?;
					for stale in found {
						self.delete_record(zone, stale.id).await?;
					}
					Ok(())
				}
				None => {
					self.create(zone, body).await?;
					Ok(())
				}
			}
		}
	}

	pub(super) async fn delete_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let rel = self.relative_name(&record.name);
		let existing = self.find_records(zone, kind, &rel).await?;
		// The TXT matching rule from `src/dns/provider/mod.rs` is the
		// contract: a value-bearing delete drops only the record
		// whose data matches the value (a sibling ACME challenge at
		// the same owner survives), an empty-value delete drops
		// every record at the owner (the DKIM rotator's retire
		// path). Other record kinds fall through to the
		// first-by-(type, name) selection, which is the existing
		// whole-set semantics.
		if record.kind == RecordKind::Txt && record.value.is_empty() {
			for prev in existing {
				self.delete_record(zone, prev.id).await?;
			}
			return Ok(());
		}
		match existing.into_iter().find(|r| {
			r.kind == kind
				&& r.name == rel
				&& (record.kind != RecordKind::Txt || same_txt_value(&r.data, &record.value))
		}) {
			Some(prev) => self.delete_record(zone, prev.id).await,
			None => Ok(()), // already absent: idempotent.
		}
	}
}
