//! XML <-> record helpers: parsing the zone into [`Host`], building a
//! [`Host`] from a [`DnsRecord`], the SLD/TLD split, and the host label.
//!
//! [`Host`]: super::xml::Host

use super::xml::Host;
use crate::dns::provider::{DnsRecord, ProviderError, RecordKind};
use crate::dns::txt::{TxtForm, txt_encode};

/// Split a registered domain into (sld, tld) via the Public Suffix List.
/// Falls back to a two-label split when the PSL has no entry (covers plain
/// TLDs in tests with non-public TLDs).
pub(crate) fn split_sld_tld(zone: &str) -> (String, String) {
	use psl::Psl;
	let registrable = psl::List
		.domain(zone.as_bytes())
		.and_then(|d| std::str::from_utf8(d.as_bytes()).ok())
		.unwrap_or(zone);
	match registrable.split_once('.') {
		Some((sld, tld)) => (sld.to_string(), tld.to_string()),
		None => (registrable.to_string(), String::new()),
	}
}

/// The Namecheap host label for a record: `@` for the apex, the prefix
/// otherwise (`_dmarc` for `_dmarc.example.org`, leaving the zone to be added
/// back through `SLD`/`TLD`).
pub(crate) fn host_label(record_name: &str, zone: &str) -> String {
	let record_name = record_name.trim_end_matches('.');
	let zone = zone.trim_end_matches('.');
	if record_name.eq_ignore_ascii_case(zone) {
		return "@".to_string();
	}
	record_name
		.strip_suffix(&format!(".{zone}"))
		.unwrap_or(record_name)
		.to_string()
}

/// Build a [`Host`] from a [`DnsRecord`], validating the value format for
/// kinds that carry structured data (MX priority, SRV priority/weight/port).
pub(crate) fn host_from_record(record: &DnsRecord, zone: &str) -> Result<Host, ProviderError> {
	let kind_str = api_kind(record.kind)?;
	let mut host = Host {
		name: host_label(&record.name, zone),
		kind: kind_str.to_string(),
		address: match record.kind {
			// The setHosts reference describes `Address` only as "URL or
			// IP address ... based on RecordType", with no word on TXT
			// quoting, length or escaping
			// (<https://www.namecheap.com/support/api/methods/domains-dns/set-hosts/>,
			// read 2026-10-12). The logical value is the form that is the
			// same bytes every time it is sent and the one other clients
			// send (lego); a quoted value risks being published with the
			// quotes as part of the text.
			RecordKind::Txt => txt_encode(&record.value, TxtForm::Logical),
			_ => record.value.trim_end_matches('.').to_string(),
		},
		ttl: record.ttl.max(60),
		mx_pref: None,
		priority: None,
		weight: None,
		port: None,
	};
	match record.kind {
		RecordKind::Mx => {
			let (pref, target) = record
				.value
				.split_once(char::is_whitespace)
				.ok_or(ProviderError::Unsupported)?;
			host.mx_pref = Some(pref.parse().map_err(|_| ProviderError::Unsupported)?);
			host.address = target.trim().trim_end_matches('.').to_string();
		}
		RecordKind::Srv => {
			let parts: Vec<&str> = record.value.split_whitespace().collect();
			if parts.len() != 4 {
				return Err(ProviderError::Unsupported);
			}
			host.priority = Some(parts[0].parse().map_err(|_| ProviderError::Unsupported)?);
			host.weight = Some(parts[1].parse().map_err(|_| ProviderError::Unsupported)?);
			host.port = Some(parts[2].parse().map_err(|_| ProviderError::Unsupported)?);
			host.address = parts[3].trim_end_matches('.').to_string();
		}
		_ => {}
	}
	Ok(host)
}

/// Whether `kind` can be published through Namecheap. TLSA is not — the API
/// has no field for the usage/selector/matching/cert tuple.
fn api_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
	match kind {
		RecordKind::A
		| RecordKind::Aaaa
		| RecordKind::Txt
		| RecordKind::Cname
		| RecordKind::Mx
		| RecordKind::Srv
		| RecordKind::Caa => Ok(kind.as_str()),
		RecordKind::Tlsa => Err(ProviderError::Unsupported),
	}
}
