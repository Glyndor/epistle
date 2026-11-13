//! Select complete values before issuing record-ID deletes.

use super::*;
use crate::dns::names::canonical_name;
use crate::dns::rrset::canonical_value;

/// The `priority weight port target` of a stored SRV record, whichever of the
/// two shapes Porkbun holds it in: the whole value in `content`, as this
/// provider writes it, or the plain priority in `prio` with
/// `weight port target` in `content`, as the panel writes it. A record that
/// is neither is not one this provider can read.
pub(super) fn stored_srv(content: &str, prio: &str) -> Option<String> {
	let (priority, weight, port, target) = parse_srv(content).or_else(|| {
		let priority: u16 = prio.trim().parse().ok()?;
		parse_srv(&format!("{priority} {content}"))
	})?;
	Some(format!("{priority} {weight} {port} {target}"))
}

pub(super) fn matches(stored: &Record, record: &DnsRecord) -> bool {
	if record.value.is_empty()
		|| !stored.kind.eq_ignore_ascii_case(record.kind.as_str())
		|| canonical_name(&stored.name) != canonical_name(&record.name)
	{
		return false;
	}
	let value = if record.kind == RecordKind::Srv {
		let Some(value) = stored_srv(&stored.content, &stored.prio) else {
			return false;
		};
		value
	} else if record.kind == RecordKind::Mx {
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
