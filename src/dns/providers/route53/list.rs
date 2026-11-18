//! Reading the record sets of the hosted zone.
//!
//! `ListResourceRecordSets` answers XML, a page of record sets at a time, and
//! says the list goes on with `IsTruncated` true plus `NextRecordName`,
//! `NextRecordType` and, for a record set with a routing policy,
//! `NextRecordIdentifier`, which the next request passes as `name`, `type`
//! and `identifier`
//! (<https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListResourceRecordSets.html>,
//! read 2026-11-13). The XML is read with a small hand-rolled reader; the
//! response is well-formed by API contract.
//!
//! A provider is configured with one hosted zone and no zone name, so the
//! name of the zone is learned from the zone itself: its apex is the one
//! name that holds the SOA record set. Asking for it needs only the listing
//! permission the provider needs anyway.

use super::*;
use crate::dns::names::canonical_name;

/// A record set as the API returns it. `name` is the FQDN with the trailing
/// dot AWS always uses; `values` is each rdata as Route 53 returns it, XML
/// entities resolved but still quoted and escaped the way a change writes it
/// back.
#[derive(Debug, Clone)]
pub(super) struct Rrset {
	pub(super) name: String,
	pub(super) kind: String,
	pub(super) ttl: u32,
	pub(super) values: Vec<String>,
	/// The set is an alias or has a routing policy (`AliasTarget` or
	/// `SetIdentifier`): a change that names it without those fields would
	/// not match it, and epistle does not write it.
	pub(super) routed: bool,
}

/// Where a page of the listing starts: `(name, type, identifier)`.
pub(super) type Start = (String, String, Option<String>);

/// Every `<ResourceRecordSet>` of one page, in the order listed. The reader
/// uses a lowercased view to find tag boundaries (the wire form is
/// case-insensitive) and slices the original `xml` to keep the byte case of
/// the values.
pub(super) fn parse_rrsets(xml: &str) -> Vec<Rrset> {
	let lower = xml.to_ascii_lowercase();
	let mut rrsets = Vec::new();
	let mut cursor = 0;
	while let Some(rel_start) = lower[cursor..].find("<resourcerecordset>") {
		let abs = cursor + rel_start;
		let Some(rel_end) = lower[abs..].find("</resourcerecordset>") else {
			break;
		};
		let end = abs + rel_end;
		if let Some(rrset) = parse_block(xml, &lower, abs, end) {
			rrsets.push(rrset);
		}
		cursor = end + "</resourcerecordset>".len();
	}
	rrsets
}

/// The record set between `abs` and `end`.
fn parse_block(xml: &str, lower: &str, abs: usize, end: usize) -> Option<Rrset> {
	let block_lower = &lower[abs..end];
	let original = |tag: &str| {
		let open = format!("<{tag}>");
		let start = block_lower.find(&open)? + open.len();
		let stop = block_lower[start..].find(&format!("</{tag}>"))? + start;
		Some(xml_unescape(&xml[abs + start..abs + stop]))
	};
	let name = original("name")?;
	let kind = original("type")?.trim().to_string();
	let mut values: Vec<String> = Vec::new();
	let mut value_cursor = 0;
	while let Some(rel_value) = block_lower[value_cursor..].find("<value>") {
		let vstart = value_cursor + rel_value + "<value>".len();
		let vend = vstart + block_lower[vstart..].find("</value>")?;
		values.push(xml_unescape(&xml[abs + vstart..abs + vend]));
		value_cursor = vend;
	}
	let ttl: u32 = extract_tag_lower(block_lower, "ttl")
		.and_then(|s| s.trim().parse().ok())
		.unwrap_or(300);
	let routed = block_lower.contains("<aliastarget>") || block_lower.contains("<setidentifier>");
	Some(Rrset {
		name,
		kind,
		ttl,
		values,
		routed,
	})
}

/// The first record set of `xml` whose `<Name>` is `target` and whose
/// `<Type>` is `wanted`.
pub(super) fn parse_rrset(xml: &str, target: &str, wanted: &str) -> Option<Rrset> {
	parse_rrsets(xml).into_iter().find(|rrset| {
		rrset.kind.eq_ignore_ascii_case(wanted)
			&& rrset
				.name
				.trim_end_matches('.')
				.eq_ignore_ascii_case(target.trim_end_matches('.'))
	})
}

/// The text content of the first `<tag>...</tag>` in `block_lower`,
/// with both halves already lowercased. The caller picks the original
/// bytes from `xml` if it needs case preserved.
pub(super) fn extract_tag_lower(block_lower: &str, tag: &str) -> Option<String> {
	let open = format!("<{tag}>");
	let close = format!("</{tag}>");
	let start = block_lower.find(&open)? + open.len();
	let end = block_lower[start..].find(&close)? + start;
	Some(block_lower[start..end].to_string())
}

/// Where the next page of a truncated ListResourceRecordSets answer
/// starts, or `None` when the list is complete.
pub(super) fn next_page(xml: &str) -> Option<Start> {
	let lower = xml.to_ascii_lowercase();
	if extract_tag_lower(&lower, "istruncated")?.trim() != "true" {
		return None;
	}
	let tag = |name: &str| {
		let open = format!("<{}>", name.to_ascii_lowercase());
		let start = lower.find(&open)? + open.len();
		let end = lower[start..].find(&format!("</{}>", name.to_ascii_lowercase()))? + start;
		Some(xml_unescape(&xml[start..end]))
	};
	Some((
		tag("NextRecordName")?,
		tag("NextRecordType")?,
		tag("NextRecordIdentifier"),
	))
}

/// A name as Route 53 returns it, in the form the rest of epistle uses: the
/// trailing dot dropped and a character Route 53 escapes as a backslash and
/// three octal digits (`\052` for `*`) given back.
pub(super) fn read_name(name: &str) -> String {
	let bytes = name.trim_end_matches('.').as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		let octal = bytes
			.get(i + 1..i + 4)
			.filter(|digits| bytes[i] == b'\\' && digits.iter().all(|d| (b'0'..=b'7').contains(d)));
		match octal.and_then(|d| u8::from_str_radix(std::str::from_utf8(d).ok()?, 8).ok()) {
			Some(byte) => {
				out.push(byte);
				i += 4;
			}
			None => {
				out.push(bytes[i]);
				i += 1;
			}
		}
	}
	String::from_utf8_lossy(&out).into_owned()
}

/// The records of one record set, in the shape the rest of epistle uses. A
/// TXT value is read back to its logical text; an alias has no value and
/// gives no record.
pub(super) fn records_of(rrset: &Rrset) -> Vec<DnsRecord> {
	let kind = RecordKind::from_token(&rrset.kind);
	let name = read_name(&rrset.name);
	rrset
		.values
		.iter()
		.map(|value| DnsRecord {
			name: name.clone(),
			kind: kind.clone(),
			value: if kind == RecordKind::Txt {
				txt_read(value)
			} else {
				value.clone()
			},
			ttl: rrset.ttl,
			proxied: None,
		})
		.collect()
}

impl Route53Provider {
	/// Every record set of the hosted zone, every page of it. A listing that
	/// does not end within [`crate::dns::providers::LIST_MAX_PAGES`], or
	/// whose next page starts where the last one did, is an error and not a
	/// shorter zone.
	pub(super) async fn all_rrsets(&self, zone: &str) -> Result<Vec<Rrset>, ProviderError> {
		let mut rrsets = Vec::new();
		let mut start: Option<Start> = None;
		for _ in 0..crate::dns::providers::LIST_MAX_PAGES {
			let text = self.list_page(start.as_ref()).await?;
			rrsets.extend(parse_rrsets(&text));
			if rrsets.len() > crate::dns::providers::LIST_MAX_RECORDS {
				return Err(crate::dns::providers::listing_too_long(zone));
			}
			match next_page(&text) {
				None => return Ok(rrsets),
				Some(next) if start.as_ref() == Some(&next) => {
					return Err(crate::dns::providers::inconsistent_pages(zone));
				}
				Some(next) => start = Some(next),
			}
		}
		Err(crate::dns::providers::listing_too_long(zone))
	}

	/// Whether `zone` is the apex of the hosted zone: the name that holds
	/// its SOA record set. One page of one record set, starting at the SOA
	/// of that name, answers it.
	pub(super) async fn is_apex(&self, zone: &str) -> Result<bool, ProviderError> {
		let wanted = canonical_name(zone);
		if let Some(apex) = self.apex.lock().ok().and_then(|apex| apex.clone()) {
			return Ok(apex == wanted);
		}
		let start = (format!("{wanted}."), "SOA".to_string(), None);
		let text = self.list_page_sized(Some(&start), Some(1)).await?;
		let found = parse_rrsets(&text).into_iter().any(|rrset| {
			!rrset.routed
				&& rrset.kind.eq_ignore_ascii_case("SOA")
				&& canonical_name(&read_name(&rrset.name)) == wanted
		});
		if found && let Ok(mut apex) = self.apex.lock() {
			*apex = Some(wanted);
		}
		Ok(found)
	}

	/// The records of the hosted zone, when `zone` is its apex.
	pub(super) async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		if !self.is_apex(zone).await? {
			return Err(ProviderError::ZoneNotFound(zone.to_string()));
		}
		Ok(self
			.all_rrsets(zone)
			.await?
			.iter()
			.flat_map(records_of)
			.collect())
	}
}
