//! Select complete values before issuing record-ID deletes.

use super::*;
use crate::dns::rrset::canonical_value;

pub(super) fn matches(stored: &DnsRecordRef, record: &DnsRecord, relative: &str) -> bool {
	if record.value.is_empty()
		|| parse_kind(stored.rtype) != record.kind
		|| !stored
			.name
			.as_deref()
			.is_some_and(|n| n.eq_ignore_ascii_case(relative))
	{
		return false;
	}
	let Some(raw) = stored.value.as_deref() else {
		return false;
	};
	let value = match record.kind {
		RecordKind::Srv => format!("0 {raw}"),
		RecordKind::Mx if !starts_with_preference(raw) => {
			let Some(priority) = stored.priority else {
				return false;
			};
			format!("{priority} {raw}")
		}
		_ => raw.to_string(),
	};
	canonical_value(&record.kind, &value) == canonical_value(&record.kind, &record.value)
}

impl BunnyProvider {
	pub(super) async fn delete_exact_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record.name)?;
		Self::api_type(&record.kind)?;
		if record.value.is_empty() {
			return Err(ProviderError::Unsupported);
		}
		let zone_id = self.zone_id().await?;
		let relative = self.subname(&record.name);
		for stored in self
			.zone_detail(zone_id)
			.await?
			.records
			.into_iter()
			.filter(|r| matches(r, &record, &relative))
		{
			self.delete_by_id(zone_id, stored.id).await?;
		}
		Ok(())
	}
}
