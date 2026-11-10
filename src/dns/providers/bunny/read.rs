//! Reading a Bunny record back into the shape the rest of epistle uses.

use super::*;

/// The record a listed entry stands for; `None` for an SRV without the
/// `weight port target` it carries in `Value`.
pub(super) fn record_of(zone: &str, r: &DnsRecordRef) -> Option<DnsRecord> {
	let name_rel = r.name.as_deref().unwrap_or_default();
	let name = if name_rel.is_empty() {
		zone.to_string()
	} else {
		format!("{name_rel}.{zone}")
	};
	let kind = parse_kind(r.rtype);
	let value_raw = r.value.clone().unwrap_or_default();
	let value = if kind == RecordKind::Srv {
		// Bunny returns SRV values as `weight port target`; lift
		// them into the canonical `priority weight port target.`
		// form (Bunny's API pins priority to 0, so the wire value
		// is exactly the one we will need to upsert later).
		let mut parts = value_raw.split_whitespace();
		let weight = parts.next()?;
		let port = parts.next()?;
		let target = parts.collect::<Vec<_>>().join(" ");
		format!("0 {weight} {port} {target}")
	} else if kind == RecordKind::Txt {
		txt_decode(&value_raw, TXT_FORM)
	} else if kind == RecordKind::Mx && r.priority.is_some() && !starts_with_preference(&value_raw)
	{
		// `Priority` and `Value` are separate fields; a record written
		// as `<preference> <exchange>` in `Value` already has it.
		format!("{} {value_raw}", r.priority.unwrap_or(0))
	} else if kind == RecordKind::Caa && r.tag.is_some() {
		format!(
			"{} {} \"{value_raw}\"",
			r.flags.unwrap_or(0),
			r.tag.as_deref().unwrap_or_default()
		)
	} else {
		value_raw
	};
	Some(DnsRecord {
		name,
		kind,
		value,
		ttl: r.ttl.max(0) as u32,
		proxied: None,
	})
}

/// Whether an MX `Value` already begins with its preference: a number and
/// something after it (`10 mail.example.org`, `0 .`).
pub(super) fn starts_with_preference(value: &str) -> bool {
	let mut parts = value.split_whitespace();
	parts
		.next()
		.is_some_and(|first| first.parse::<u16>().is_ok())
		&& parts.next().is_some()
}

/// Map Bunny's numeric record type back to a [`RecordKind`]. The numbers
/// are Bunny's `DnsRecordTypes` enum (<https://bunny.net/docs/reference/dnszonepublic_add>,
/// read 2026-10-16). The ones epistle does not publish keep their own kind
/// (NS at 12 is a delegation), and a number the enum does not list is
/// `TYPE<n>`, never a TXT.
pub(super) fn parse_kind(rtype: i64) -> RecordKind {
	let token = match rtype {
		0 => "A",
		1 => "AAAA",
		2 => "CNAME",
		3 => "TXT",
		4 => "MX",
		5 => "REDIRECT",
		6 => "FLATTEN",
		7 => "PULLZONE",
		8 => "SRV",
		9 => "CAA",
		10 => "PTR",
		11 => "SCRIPT",
		12 => "NS",
		13 => "SVCB",
		14 => "HTTPS",
		15 => "TLSA",
		other => return RecordKind::from_token(&format!("TYPE{other}")),
	};
	RecordKind::from_token(token)
}
