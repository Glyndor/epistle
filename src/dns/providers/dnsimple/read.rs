//! A DNSimple record read back into the shape the rest of epistle uses.

use super::*;

/// `r` as a [`DnsRecord`] of the zone `zone`, or `None` when it lacks a
/// field its type needs (an SRV without priority, weight and port).
pub(super) fn record_of(zone: &str, r: &Record) -> Option<DnsRecord> {
	let name = if r.name.is_empty() {
		zone.to_string()
	} else {
		format!("{}.{}", r.name, zone)
	};
	let kind = RecordKind::from_token(&r.kind);
	let value = if kind == RecordKind::Srv {
		match (r.priority, r.weight, r.port) {
			(Some(p), Some(w), Some(port)) => {
				format!("{p} {w} {port} {}", r.content.trim_end_matches('.'))
			}
			_ => return None,
		}
	} else if kind == RecordKind::Txt {
		txt_decode(&r.content, TXT_FORM)
	} else if kind == RecordKind::Mx && r.priority.is_some() {
		format!("{} {}", r.priority.unwrap_or(0), r.content)
	} else {
		r.content.clone()
	};
	Some(DnsRecord {
		name,
		kind,
		value,
		ttl: r.ttl,
		proxied: None,
	})
}
