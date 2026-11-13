//! The guarded write of a DNSimple zone: the set at the name and type is read
//! again right before the write, and records are updated and deleted by their
//! id (see [`crate::dns::providers::guarded`]).

use super::*;
use crate::dns::providers::guarded::{ById, Fresh, at_name};
use crate::dns::publish::provider::{Guard, ObservedRecord, Snapshot};

/// A DNSimple record id, as the text the guarded contract carries.
fn parse_id(id: &str) -> Result<u64, ProviderError> {
	id.parse()
		.map_err(|_| ProviderError::Remote("DNSimple gave a record id that is not a number".into()))
}

impl DnsimpleProvider {
	/// The zone as DNSimple lists it, each record with its id.
	pub(super) async fn snapshot_inner(&self, zone: &str) -> Result<Snapshot, ProviderError> {
		let records = self.list_page(zone).await?;
		if records.len() > LIST_MAX_RECORDS {
			return Err(listing_too_long(zone));
		}
		Ok(Snapshot {
			zone: zone.to_string(),
			records: records
				.iter()
				.filter_map(|r| {
					Some(ObservedRecord {
						record: read::record_of(self.secret.zone(), r)?,
						identity: Some(r.id.to_string()),
					})
				})
				.collect(),
			revision: None,
			guard: Guard::Checked,
		})
	}
}

impl ById for DnsimpleProvider {
	type Body = String;

	fn authorizes(&self, name: &str) -> bool {
		self.secret.authorizes(name)
	}

	async fn read_set(&self, zone: &str, change: &Change) -> Result<Vec<Fresh>, ProviderError> {
		Self::api_kind(&change.kind)?;
		let records = self.list_page(zone).await?;
		Ok(at_name(
			change,
			records.iter().filter_map(|r| {
				Some(Fresh {
					id: r.id.to_string(),
					record: read::record_of(self.secret.zone(), r)?,
				})
			}),
		))
	}

	fn body(&self, record: &DnsRecord) -> Result<String, ProviderError> {
		let kind = Self::api_kind(&record.kind)?;
		self.record_body(kind, &self.relative_name(&record.name), record)
	}

	async fn update(&self, zone: &str, id: &str, body: &String) -> Result<(), ProviderError> {
		self.write_body(zone, Some(parse_id(id)?), body.clone())
			.await
	}

	async fn create(&self, zone: &str, body: &String) -> Result<(), ProviderError> {
		self.write_body(zone, None, body.clone()).await
	}

	async fn delete(&self, zone: &str, id: &str) -> Result<(), ProviderError> {
		self.delete_by_id(self.records_url(zone, Some(parse_id(id)?))?)
			.await
	}
}
