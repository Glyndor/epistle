//! The guarded write of a Porkbun zone: the set at the name and type is read
//! again right before the write, and records are edited and deleted by their
//! id (see [`crate::dns::providers::guarded`]).

use super::*;
use crate::dns::providers::guarded::{ById, Fresh, at_name};
use crate::dns::publish::provider::{Guard, ObservedRecord, Snapshot};

impl PorkbunProvider {
	/// The zone as Porkbun lists it, each record with its id.
	pub(super) async fn snapshot_inner(&self, zone: &str) -> Result<Snapshot, ProviderError> {
		Ok(Snapshot {
			zone: zone.to_string(),
			records: self
				.retrieve()
				.await?
				.iter()
				.filter_map(|r| {
					Some(ObservedRecord {
						record: record_of(r)?,
						identity: Some(r.id.clone()),
					})
				})
				.collect(),
			revision: None,
			guard: Guard::Checked,
		})
	}
}

impl ById for PorkbunProvider {
	type Body = serde_json::Value;

	fn authorizes(&self, name: &str) -> bool {
		self.secret.authorizes(name)
	}

	async fn read_set(&self, _zone: &str, change: &Change) -> Result<Vec<Fresh>, ProviderError> {
		Self::api_kind(&change.kind)?;
		Ok(at_name(
			change,
			self.retrieve().await?.iter().filter_map(|r| {
				Some(Fresh {
					id: r.id.clone(),
					record: record_of(r)?,
				})
			}),
		))
	}

	fn body(&self, record: &DnsRecord) -> Result<serde_json::Value, ProviderError> {
		self.record_fields(record, Self::api_kind(&record.kind)?)
	}

	async fn update(
		&self,
		_zone: &str,
		id: &str,
		body: &serde_json::Value,
	) -> Result<(), ProviderError> {
		let segments = ["dns", "edit", self.secret.zone(), id];
		self.call(&segments, body.clone()).await.map(drop)
	}

	async fn create(&self, _zone: &str, body: &serde_json::Value) -> Result<(), ProviderError> {
		let segments = ["dns", "create", self.secret.zone()];
		self.call(&segments, body.clone()).await.map(drop)
	}

	async fn delete(&self, _zone: &str, id: &str) -> Result<(), ProviderError> {
		self.delete_id(id).await
	}
}
