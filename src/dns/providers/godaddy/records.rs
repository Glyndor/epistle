//! Wire record encoding and value matching.

use crate::dns::provider::{DnsRecord, ProviderError, RecordKind, parse_srv, same_txt_purpose};
use crate::dns::txt::{TxtForm, txt_encode};

use super::GodaddyProvider;

/// How GoDaddy takes a TXT `data` and lists it back; see `record_element`.
pub(super) const TXT_FORM: TxtForm = TxtForm::Logical;

/// GoDaddy's floor for a record TTL, in seconds. Shorter values are rejected
/// by the API; the provider raises the configured TTL to the floor at write
/// time so a low-TTL DKIM/SPF never hits the wire.
const MIN_TTL: u32 = 600;

/// Translate an FQDN into the relative name GoDaddy's API expects: the
/// label minus the zone suffix, or `@` for the apex. The strip is
/// case-insensitive on the suffix so `_dmarc.EXAMPLE.ORG` is mapped
/// to `_dmarc` for a `example.org` zone; a trailing dot is stripped
/// first so `example.org.` also maps to `@` and the
/// authorisation check in [`Self::secret_zone_authorizes`] agrees
/// on the apex. The returned label keeps the input's case for the
/// part that is not the zone suffix; an apex absolute name (zone,
/// zone with a trailing dot, or any case variant) maps to the
/// literal `@`.
pub(super) fn fqdn_to_relative(name: &str, zone: &str) -> String {
	let name = name.trim_end_matches('.');
	let zone = zone.trim_end_matches('.');
	if name.is_empty() {
		return "@".to_string();
	}
	let name_lower = name.to_ascii_lowercase();
	let zone_lower = zone.to_ascii_lowercase();
	if name_lower == zone_lower {
		return "@".to_string();
	}
	let suffix = format!(".{zone_lower}");
	match name_lower.strip_suffix(&suffix) {
		Some(prefix) if !prefix.is_empty() => {
			// Reconstruct the original case for the prefix portion.
			// `name` is at least as long as `name_lower` (ASCII), so
			// the byte slice is safe.
			name[..prefix.len()].to_string()
		}
		_ => name.to_string(),
	}
}

/// Split an SRV owner name into `(service, protocol)`. The owner
/// always starts with `_service._proto` for a non-apex SRV; the
/// `_service._proto.` prefix is stripped, the rest is treated as
/// the host part of the record. An owner that does not follow the
/// shape (a single label, or a label that is not a service name)
/// returns empty strings; the API rejects the empty wire shape, so
/// the upstream caller will see the failure through the standard
/// error path.
fn service_protocol_from_owner(rel: &str) -> (String, String) {
	let labels: Vec<&str> = rel.split('.').collect();
	if labels.len() < 2 || !labels[0].starts_with('_') || !labels[1].starts_with('_') {
		return (String::new(), String::new());
	}
	(labels[0].to_string(), labels[1].to_string())
}

impl GodaddyProvider {
	/// The GoDaddy record type for a kind we can publish. A/AAAA/TXT/CNAME
	/// go through the plain `data` field; MX and SRV add the kind's extra
	/// fields to the array element. TLSA is rejected with `Unsupported`:
	/// the v1 endpoints' allowed-type set excludes it
	/// (https://developer.godaddy.com/en/docs/references/rest/domains/v1/record-replace-type-name),
	/// so a TLSA publish would round-trip a 4xx instead of a clean
	/// "this provider does not support TLSA" verdict.
	pub(super) fn api_kind(kind: &RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A => Ok("A"),
			RecordKind::Aaaa => Ok("AAAA"),
			RecordKind::Txt => Ok("TXT"),
			RecordKind::Cname => Ok("CNAME"),
			RecordKind::Mx => Ok("MX"),
			RecordKind::Srv => Ok("SRV"),
			RecordKind::Caa => Ok("CAA"),
			// TLSA has no structured field on GoDaddy.
			RecordKind::Tlsa => Err(ProviderError::Unsupported),
			RecordKind::Ns | RecordKind::Https | RecordKind::Svcb | RecordKind::Other(_) => {
				Err(ProviderError::Unsupported)
			}
		}
	}

	/// The JSON array element for one record. MX adds `priority`; SRV adds
	/// `priority`/`weight`/`port`/`service`/`protocol`; every other kind
	/// carries just `data` and `ttl`. The TTL is raised to the API floor
	/// so a low-TTL DKIM/SPF never hits the wire.
	pub(super) fn record_element(
		&self,
		record: &DnsRecord,
	) -> Result<serde_json::Value, ProviderError> {
		let ttl = record.ttl.max(MIN_TTL);
		if record.kind == RecordKind::Mx {
			let mut parts = record.value.split_whitespace();
			let priority: u16 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = crate::dns::provider::mx_target_for_api(target).to_string();
			return Ok(serde_json::json!({
				"data": target,
				"ttl": ttl,
				"priority": priority,
			}));
		}
		if record.kind == RecordKind::Srv {
			let (priority, weight, port, target) = parse_srv(&record.value)
				.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {}", record.value)))?;
			// GoDaddy's SRV record splits the owner into `service` and
			// `protocol` and uses a string `data` for the target host.
			// epistle stores the value in the standard SRV presentation
			// form (`prio weight port target.`) and encodes the owner
			// name as `_service._proto.zone`; the labels before the
			// zone are the service and protocol. A blank `data` and
			// empty `service` / `protocol` are rejected by the API.
			let owner_rel = fqdn_to_relative(&record.name, &self.zone);
			let (service, protocol) = service_protocol_from_owner(&owner_rel);
			return Ok(serde_json::json!({
				"data": target.trim_end_matches('.'),
				"ttl": ttl,
				"priority": priority,
				"weight": weight,
				"port": port,
				"service": service,
				"protocol": protocol,
				"host": target.trim_end_matches('.'),
			}));
		}
		// The v1 OpenAPI gives `data` as a bare string with nothing on
		// TXT quoting, length or escaping
		// (<https://developer.godaddy.com/openapi/domains-v1.json>,
		// DNSRecord, read 2026-10-12). The logical value is the form that
		// is the same bytes every time it is sent and the one other
		// clients send (lego), and `elements_match_kind` compares logical
		// values so a set GoDaddy hands back quoted still matches.
		let data = if record.kind == RecordKind::Txt {
			txt_encode(&record.value, TXT_FORM)
		} else {
			record.value.clone()
		};
		Ok(serde_json::json!({
			"data": data,
			"ttl": ttl,
		}))
	}
}

/// Compare two wire elements by their value-identifying fields for
/// `kind`, per the upsert/delete contract in
/// [`crate::dns::provider::DnsProvider`]. The matching rule differs by
/// kind:
///
/// - TXT: `data` is compared through [`same_txt_purpose`], so two
///   values with the same version tag match (an SPF change replaces
///   the SPF rather than appending a second one) and an untagged
///   value matches only an identical value (an ACME DNS-01 cleanup
///   does not wipe a sibling challenge at the same owner). Untagged
///   values compare as logical values (quoting and string splits do not
///   count); dots are never trimmed.
/// - MX / SRV / CNAME: `data` is the FQDN target. GoDaddy stores the
///   target with a trailing dot, epistle publishes without one; the
///   compare is case-insensitive and ignores one trailing dot so a
///   `MAIL.Example.Org.` round-trip matches `mail.example.org`.
/// - A / AAAA / TLSA / CAA: the `data` is the address or hash bytes;
///   it is compared verbatim, no case folding or dot stripping.
///
/// The TTL is intentionally not part of the match: a re-upsert with
/// a different TTL is an update of the same value, not a second
/// record. The structured fields (MX `priority`, SRV `priority`/
/// `weight`/`port`/`service`/`protocol`) still have to match
/// alongside the data so a priority change lands as a replacement
/// rather than a duplicate.
pub(super) fn elements_match_kind(
	kind: &str,
	existing: &serde_json::Value,
	new: &serde_json::Value,
) -> bool {
	let data_eq = match (existing.get("data"), new.get("data")) {
		(Some(serde_json::Value::String(a)), Some(serde_json::Value::String(b))) => match kind {
			"TXT" => same_txt_purpose(a, b),
			"MX" | "SRV" | "CNAME" => {
				let a = a.trim_end_matches('.').to_ascii_lowercase();
				let b = b.trim_end_matches('.').to_ascii_lowercase();
				a == b
			}
			_ => a == b,
		},
		(a, b) => a == b,
	};
	match kind {
		"MX" => data_eq && existing.get("priority") == new.get("priority"),
		"SRV" => {
			data_eq
				&& existing.get("priority") == new.get("priority")
				&& existing.get("weight") == new.get("weight")
				&& existing.get("port") == new.get("port")
				&& existing.get("service") == new.get("service")
				&& existing.get("protocol") == new.get("protocol")
		}
		_ => data_eq,
	}
}
