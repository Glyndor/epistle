//! A Spaceship record read back into the shape the rest of epistle uses.

use super::*;

/// `item` as a [`DnsRecord`] of the zone `zone` (without a trailing dot), or
/// `None` when it lacks a field its type needs.
pub(super) fn record_of(zone: &str, item: &serde_json::Value) -> Option<DnsRecord> {
	let kind = item.get("type").and_then(|v| v.as_str())?;
	let name = item.get("name").and_then(|v| v.as_str())?;
	let ttl = item.get("ttl").and_then(|v| v.as_u64()).unwrap_or(3600) as u32;
	let fqdn = if name == "@" {
		zone.to_string()
	} else {
		format!("{name}.{zone}")
	};
	let kind = RecordKind::from_token(kind);
	let value = match &kind {
		RecordKind::Srv => {
			let priority = item.get("priority").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
			let weight = item.get("weight").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
			let port = item.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
			let target = item.get("target").and_then(|v| v.as_str())?;
			format!(
				"{priority} {weight} {port} {}",
				target.trim_end_matches('.')
			)
		}
		RecordKind::Mx => {
			let priority = item
				.get("preference")
				.or_else(|| item.get("priority"))
				.and_then(|v| v.as_u64())
				.unwrap_or(0) as u16;
			let target = item
				.get("exchange")
				.and_then(|v| v.as_str())
				.or_else(|| item.get("value").and_then(|v| v.as_str()))?;
			format!("{priority} {}", target.trim_end_matches('.'))
		}
		RecordKind::Txt => txt_decode(&SpaceshipProvider::extract_value(item)?, TXT_FORM),
		// A CAA is three fields (`flag`, `tag`, `value`): the
		// presentation form is `0 issue "ca.example"`.
		RecordKind::Caa if item.get("tag").is_some() => {
			let flag = item.get("flag").and_then(|v| v.as_u64()).unwrap_or(0);
			let tag = item.get("tag").and_then(|v| v.as_str()).unwrap_or("");
			let value = item.get("value").and_then(|v| v.as_str()).unwrap_or("");
			format!("{flag} {tag} \"{value}\"")
		}
		// A kind epistle does not publish is listed even when its
		// value cannot be read: a delegation's NS that vanished
		// from the listing would let the lockdown write under it.
		RecordKind::Ns | RecordKind::Https | RecordKind::Svcb | RecordKind::Other(_) => {
			SpaceshipProvider::foreign_value(&kind, item)
		}
		_ => SpaceshipProvider::extract_value(item)?,
	};
	Some(DnsRecord {
		name: fqdn,
		kind,
		value,
		ttl,
		proxied: None,
	})
}
