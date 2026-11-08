//! Select complete values before issuing record-ID deletes.

use super::*;
use crate::dns::rrset::canonical_value;

pub(super) fn matches(stored: &Record, record: &DnsRecord, relative: &str) -> bool {
	if record.value.is_empty()
		|| !stored.kind.eq_ignore_ascii_case(record.kind.as_str())
		|| !stored.name.eq_ignore_ascii_case(relative)
	{
		return false;
	}
	let Some(value) = value(stored, &record.kind) else {
		return false;
	};
	canonical_value(&record.kind, &value) == canonical_value(&record.kind, &record.value)
}

fn value(stored: &Record, kind: &RecordKind) -> Option<String> {
	Some(match kind {
		RecordKind::Mx => format!("{} {}", stored.priority?, stored.content),
		RecordKind::Srv => format!(
			"{} {} {} {}",
			stored.priority?, stored.weight?, stored.port?, stored.content
		),
		RecordKind::Caa => format!(
			"{} {} \"{}\"",
			stored.flags?,
			stored.caa_tag.as_deref()?,
			stored.content
		),
		_ => stored.content.clone(),
	})
}

impl DnsimpleProvider {
	pub(super) async fn delete_exact_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		Self::api_kind(&record.kind)?;
		if record.value.is_empty() {
			return Err(ProviderError::Unsupported);
		}
		let relative = self.relative_name(&record.name);
		for stored in self
			.list_page(zone)
			.await?
			.into_iter()
			.filter(|r| matches(r, &record, &relative))
		{
			self.delete_by_id(self.records_url(zone, Some(stored.id))?)
				.await?;
		}
		Ok(())
	}
}
