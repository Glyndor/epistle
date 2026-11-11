//! The guarded write of a DigitalOcean zone: the set at the name and type is
//! read again right before the write, and records are updated and deleted by
//! their id (see [`crate::dns::providers::guarded`]).

use super::*;
use crate::dns::providers::guarded::{ById, Fresh, at_name};
use crate::dns::publish::provider::{Guard, ObservedRecord, Snapshot};

/// A DigitalOcean record id, as the text the guarded contract carries.
fn parse_id(id: &str) -> Result<u64, ProviderError> {
	id.parse().map_err(|_| {
		ProviderError::Remote("DigitalOcean gave a record id that is not a number".into())
	})
}

impl DigitaloceanProvider {
	/// The zone as DigitalOcean lists it, each record with its id.
	pub(super) async fn snapshot_inner(&self, zone: &str) -> Result<Snapshot, ProviderError> {
		let listed = self.list_all(zone).await?;
		Ok(Snapshot {
			zone: zone.to_string(),
			records: listed
				.iter()
				.filter_map(|r| {
					Some(ObservedRecord {
						record: record_of(zone, r)?,
						identity: Some(r.id.to_string()),
					})
				})
				.collect(),
			revision: None,
			guard: Guard::Checked,
		})
	}
}

impl ById for DigitaloceanProvider {
	type Body = String;

	fn authorizes(&self, name: &str) -> bool {
		self.secret.authorizes(name)
	}

	async fn read_set(&self, zone: &str, change: &Change) -> Result<Vec<Fresh>, ProviderError> {
		let kind = Self::api_kind(&change.kind)?;
		let rel = self.relative_name(&change.name);
		let listed = self.find_records(zone, kind, &rel).await?;
		Ok(at_name(
			change,
			listed.iter().filter_map(|r| {
				Some(Fresh {
					id: r.id.to_string(),
					record: record_of(zone, r)?,
				})
			}),
		))
	}

	fn body(&self, record: &DnsRecord) -> Result<String, ProviderError> {
		let kind = Self::api_kind(&record.kind)?;
		Self::record_body(kind, &self.relative_name(&record.name), record)
	}

	async fn update(&self, zone: &str, id: &str, body: &String) -> Result<(), ProviderError> {
		DigitaloceanProvider::update(self, zone, parse_id(id)?, body.clone()).await
	}

	async fn create(&self, zone: &str, body: &String) -> Result<(), ProviderError> {
		DigitaloceanProvider::create(self, zone, body.clone())
			.await
			.map(drop)
	}

	async fn delete(&self, zone: &str, id: &str) -> Result<(), ProviderError> {
		self.delete_record(zone, parse_id(id)?).await
	}
}
