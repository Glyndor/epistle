//! Select complete values before issuing record-ID deletes.

use super::*;
use crate::dns::names::canonical_name;
use crate::dns::rrset::canonical_value;

pub(super) fn matches(stored: &Record, record: &DnsRecord) -> bool {
	if record.value.is_empty()
		|| !stored.kind.eq_ignore_ascii_case(record.kind.as_str())
		|| canonical_name(&stored.name) != canonical_name(&record.name)
	{
		return false;
	}
	let value = if record.kind == RecordKind::Mx {
		let Ok(priority) = stored.prio.parse::<u16>() else {
			return false;
		};
		format!("{priority} {}", stored.content)
	} else {
		stored.content.clone()
	};
	canonical_value(&record.kind, &value) == canonical_value(&record.kind, &record.value)
}

impl PorkbunProvider {
	pub(super) async fn delete_exact_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		Self::api_kind(&record.kind)?;
		if record.value.is_empty() {
			return Err(ProviderError::Unsupported);
		}
		for stored in self
			.retrieve()
			.await?
			.into_iter()
			.filter(|r| matches(r, &record))
		{
			self.delete_id(&stored.id).await?;
		}
		Ok(())
	}
}
