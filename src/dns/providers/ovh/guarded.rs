//! The guarded write of an OVH zone: the set at the name and type is read
//! again right before the write, and records are updated and deleted by their
//! id (see [`crate::dns::providers::guarded`]). The zone is refreshed once
//! after the writes, as OVH only publishes it on request.

use super::*;
use crate::dns::providers::guarded::{ById, Fresh, at_name};
use crate::dns::publish::provider::{Guard, ObservedRecord, Snapshot};

/// An OVH record id, as the text the guarded contract carries.
fn parse_id(id: &str) -> Result<u64, ProviderError> {
	id.parse()
		.map_err(|_| ProviderError::Remote("OVH gave a record id that is not a number".into()))
}

impl OvhProvider {
	/// The zone as OVH lists it, each record with its id.
	pub(super) async fn snapshot_inner(&self, zone: &str) -> Result<Snapshot, ProviderError> {
		let ids: Vec<u64> = self
			.send_json(reqwest::Method::GET, &self.zone_url(zone, &["record"])?, "")
			.await?;
		// One request per id follows, so the cap is checked before any.
		if ids.len() > LIST_MAX_RECORDS {
			return Err(listing_too_long(zone));
		}
		let mut records = Vec::with_capacity(ids.len());
		for id in ids {
			// A record the list names and the detail denies is a listing that
			// does not add up, not a shorter zone.
			let Some(rec) = self.get_record(zone, id).await? else {
				return Err(inconsistent_pages(zone));
			};
			records.push(ObservedRecord {
				record: record_from_ovh(&rec, zone),
				identity: Some(id.to_string()),
			});
		}
		Ok(Snapshot {
			zone: zone.to_string(),
			records,
			revision: None,
			guard: Guard::Checked,
		})
	}

	/// The request body of `record` in `zone`.
	fn record_body(zone: &str, record: &DnsRecord) -> Result<String, ProviderError> {
		let kind = Self::api_kind(&record.kind)?;
		let sub = Self::sub_domain(zone, &record.name);
		let target = if record.kind == RecordKind::Txt {
			txt_encode(&record.value, TXT_FORM)
		} else {
			record.value.clone()
		};
		Ok(serde_json::json!({
			"fieldType": kind,
			"subDomain": sub,
			"target": target,
			"ttl": record.ttl,
		})
		.to_string())
	}
}

impl ById for OvhProvider {
	type Body = DnsRecord;

	fn authorizes(&self, name: &str) -> bool {
		self.consumer_secret.authorizes(name)
	}

	async fn read_set(&self, zone: &str, change: &Change) -> Result<Vec<Fresh>, ProviderError> {
		let kind = Self::api_kind(&change.kind)?;
		let sub = Self::sub_domain(zone, &change.name);
		let ids: Vec<u64> = self
			.send_json(reqwest::Method::GET, &self.find_url(zone, kind, &sub)?, "")
			.await?;
		if ids.len() > LIST_MAX_RECORDS {
			return Err(listing_too_long(zone));
		}
		let mut fresh = Vec::with_capacity(ids.len());
		for id in ids {
			// A record deleted since the list is not there any more, and the
			// set that is left is not the one the plan saw.
			if let Some(rec) = self.get_record(zone, id).await? {
				fresh.push(Fresh {
					id: id.to_string(),
					record: record_from_ovh(&rec, zone),
				});
			}
		}
		Ok(at_name(change, fresh))
	}

	fn body(&self, record: &DnsRecord) -> Result<DnsRecord, ProviderError> {
		Self::api_kind(&record.kind)?;
		Ok(record.clone())
	}

	async fn update(&self, zone: &str, id: &str, body: &DnsRecord) -> Result<(), ProviderError> {
		let url = self.zone_url(zone, &["record", &parse_id(id)?.to_string()])?;
		self.send_unit(reqwest::Method::PUT, &url, &Self::record_body(zone, body)?)
			.await
	}

	async fn create(&self, zone: &str, body: &DnsRecord) -> Result<(), ProviderError> {
		let url = self.zone_url(zone, &["record"])?;
		self.send_unit(reqwest::Method::POST, &url, &Self::record_body(zone, body)?)
			.await
	}

	async fn delete(&self, zone: &str, id: &str) -> Result<(), ProviderError> {
		let url = self.zone_url(zone, &["record", &parse_id(id)?.to_string()])?;
		self.send_unit(reqwest::Method::DELETE, &url, "").await
	}

	async fn finish(&self, zone: &str) -> Result<(), ProviderError> {
		self.refresh_zone(zone).await
	}
}
