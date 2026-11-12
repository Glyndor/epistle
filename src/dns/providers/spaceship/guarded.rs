//! The guarded write of a Spaceship zone.
//!
//! Spaceship has no record ids, no revision and no condition on a write. What
//! it has is a removal that names the record by its type, name and value, so
//! the guard is the one a provider with ids gets (see
//! [`crate::dns::providers::guarded`]): the set at the name and type is read
//! again right before the write and must still be the one the plan was made
//! against, and the write only ever names records the plan listed. The
//! "id" of a record is the exact removal request that matches it, so a
//! record another account added is never named, and so never removed, and a
//! record that is replaced is added first and removed after.
//!
//! The check and the write are two requests, so a record another account
//! changes in between is not detected. A save is sent without `force`, so a
//! conflict Spaceship finds (a CNAME next to another record, say) refuses
//! the write instead of being resolved by dropping a record.

use super::*;
use crate::dns::providers::guarded::{ById, Fresh, at_name};
use crate::dns::publish::provider::{Guard, ObservedRecord, Snapshot};

/// The removal request that matches `item` and nothing else, as the text the
/// guarded contract carries for an id. A TXT is removed by its value as
/// Spaceship lists it, not as epistle reads it.
fn removal_of(item: &serde_json::Value, record: &DnsRecord) -> Option<String> {
	let kind = SpaceshipProvider::api_kind(&record.kind).ok()?;
	let name = item.get("name").and_then(|v| v.as_str())?;
	let mut exact = record.clone();
	if record.kind == RecordKind::Txt {
		exact.value = SpaceshipProvider::extract_value(item)?;
	}
	exact::delete_item(&exact, kind, name)
		.ok()
		.map(|item| item.to_string())
}

impl SpaceshipProvider {
	/// Every record of the zone, with the removal that matches it as its id.
	async fn identified(&self) -> Result<Vec<Fresh>, ProviderError> {
		let zone = self.zone.trim_end_matches('.').to_string();
		Ok(self
			.list_all()
			.await?
			.iter()
			.filter_map(|item| {
				let record = read::record_of(&zone, item)?;
				let id = removal_of(item, &record).unwrap_or_default();
				Some(Fresh { id, record })
			})
			.collect())
	}

	/// The zone as Spaceship lists it. A record of a type epistle cannot
	/// write has no removal request and no identity.
	pub(super) async fn snapshot_inner(&self, zone: &str) -> Result<Snapshot, ProviderError> {
		let records = self.identified().await?;
		if records.len() > LIST_MAX_RECORDS {
			return Err(listing_too_long(zone));
		}
		Ok(Snapshot {
			zone: zone.to_string(),
			records: records
				.into_iter()
				.map(|fresh| ObservedRecord {
					record: fresh.record,
					identity: (!fresh.id.is_empty()).then_some(fresh.id),
				})
				.collect(),
			revision: None,
			guard: Guard::Checked,
		})
	}

	/// Send the removal request `id` stands for.
	async fn remove_id(&self, id: &str) -> Result<(), ProviderError> {
		let item = serde_json::from_str(id)
			.map_err(|_| ProviderError::Remote("a record id that is not a removal".into()))?;
		self.remove_exact_item(item).await
	}
}

impl ById for SpaceshipProvider {
	type Body = serde_json::Value;

	fn authorizes(&self, name: &str) -> bool {
		self.authorize(&DnsRecord::new(name, RecordKind::A, "", 0))
			.is_ok()
	}

	async fn read_set(&self, _zone: &str, change: &Change) -> Result<Vec<Fresh>, ProviderError> {
		Self::api_kind(&change.kind)?;
		Ok(at_name(change, self.identified().await?))
	}

	fn body(&self, record: &DnsRecord) -> Result<serde_json::Value, ProviderError> {
		let kind = Self::api_kind(&record.kind)?;
		Self::item_of(kind, &self.relative_name(&record.name), record)
	}

	/// Spaceship has no update in place: the new record is added, then the
	/// old one is removed by its exact value.
	async fn update(
		&self,
		_zone: &str,
		id: &str,
		body: &serde_json::Value,
	) -> Result<(), ProviderError> {
		self.put_item(body.clone(), false).await?;
		self.remove_id(id).await
	}

	async fn create(&self, _zone: &str, body: &serde_json::Value) -> Result<(), ProviderError> {
		self.put_item(body.clone(), false).await
	}

	async fn delete(&self, _zone: &str, id: &str) -> Result<(), ProviderError> {
		self.remove_id(id).await
	}
}
