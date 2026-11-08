//! Select complete values before issuing record-ID deletes and refreshing.

use super::*;
use crate::dns::rrset::canonical_value;

pub(super) fn matches(stored: &OvhRecord, record: &DnsRecord, relative: &str) -> bool {
	!record.value.is_empty()
		&& stored.field_type.eq_ignore_ascii_case(record.kind.as_str())
		&& stored.sub_domain.eq_ignore_ascii_case(relative)
		&& canonical_value(&record.kind, &stored.target)
			== canonical_value(&record.kind, &record.value)
}

impl OvhProvider {
	pub(super) async fn delete_exact_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		if record.value.is_empty() {
			return Err(ProviderError::Unsupported);
		}
		let relative = Self::sub_domain(zone, &record.name);
		let ids: Vec<u64> = self
			.send_json(
				reqwest::Method::GET,
				&self.find_url(zone, kind, &relative)?,
				"",
			)
			.await?;
		if ids.len() > LIST_MAX_RECORDS {
			return Err(listing_too_long(zone));
		}
		let mut targets = Vec::new();
		for id in ids {
			if let Some(stored) = self.get_record(zone, id).await?
				&& matches(&stored, &record, &relative)
			{
				targets.push(id);
			}
		}
		if targets.is_empty() {
			return Ok(());
		}
		for id in targets {
			self.send_unit(
				reqwest::Method::DELETE,
				&self.zone_url(zone, &["record", &id.to_string()])?,
				"",
			)
			.await?;
		}
		self.refresh_zone(zone).await
	}
}
