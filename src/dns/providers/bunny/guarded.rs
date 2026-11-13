//! The guarded write of a Bunny zone: the set at the name and type is read
//! again right before the write, and records are updated and deleted by their
//! id (see [`crate::dns::providers::guarded`]).

use super::*;
use crate::dns::providers::guarded::{ById, Fresh, at_name};
use crate::dns::publish::provider::{Guard, ObservedRecord, Snapshot};

/// A Bunny record id, as the text the guarded contract carries.
fn parse_id(id: &str) -> Result<i64, ProviderError> {
	id.parse()
		.map_err(|_| ProviderError::Remote("Bunny gave a record id that is not a number".into()))
}

impl BunnyProvider {
	/// The zone as Bunny lists it, each record with its id.
	pub(super) async fn snapshot_inner(&self, zone: &str) -> Result<Snapshot, ProviderError> {
		let zone_id = self.zone_id().await?;
		let detail = self.zone_detail(zone_id).await?;
		Ok(Snapshot {
			zone: zone.to_string(),
			records: detail
				.records
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

impl ById for BunnyProvider {
	type Body = String;

	fn authorizes(&self, name: &str) -> bool {
		self.secret.authorizes(name)
	}

	async fn read_set(&self, _zone: &str, change: &Change) -> Result<Vec<Fresh>, ProviderError> {
		Self::api_type(&change.kind)?;
		let zone_id = self.zone_id().await?;
		let detail = self.zone_detail(zone_id).await?;
		Ok(at_name(
			change,
			detail.records.iter().filter_map(|r| {
				Some(Fresh {
					id: r.id.to_string(),
					record: read::record_of(self.secret.zone(), r)?,
				})
			}),
		))
	}

	fn body(&self, record: &DnsRecord) -> Result<String, ProviderError> {
		self.record_body(record, Self::api_type(&record.kind)?)
	}

	async fn update(&self, _zone: &str, id: &str, body: &String) -> Result<(), ProviderError> {
		let url = self.record_url(self.zone_id().await?, Some(parse_id(id)?))?;
		check(
			self.send_write(reqwest::Method::POST, url, body.clone())
				.await?,
		)
	}

	async fn create(&self, _zone: &str, body: &String) -> Result<(), ProviderError> {
		let url = self.record_url(self.zone_id().await?, None)?;
		check(
			self.send_write(reqwest::Method::PUT, url, body.clone())
				.await?,
		)
	}

	async fn delete(&self, _zone: &str, id: &str) -> Result<(), ProviderError> {
		self.delete_by_id(self.zone_id().await?, parse_id(id)?)
			.await
	}
}
