//! How a record is written for Cloudflare: the API kind and the request body.

use super::*;

impl CloudflareProvider {
	/// The Cloudflare record type for a kind we can publish. TXT/A/AAAA/CNAME
	/// go through a plain `content` field; TLSA, SRV, MX, and CAA use a
	/// structured `data` object — each carries its kind-specific shape
	/// (`usage selector matching cert` / `priority weight port target` /
	/// `priority host` / `flags tag value`).
	pub(super) fn api_kind(kind: &RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A => Ok("A"),
			RecordKind::Aaaa => Ok("AAAA"),
			RecordKind::Txt => Ok("TXT"),
			RecordKind::Cname => Ok("CNAME"),
			RecordKind::Tlsa => Ok("TLSA"),
			RecordKind::Srv => Ok("SRV"),
			RecordKind::Mx => Ok("MX"),
			RecordKind::Caa => Ok("CAA"),
			// Cloudflare accepts HTTPS and SVCB; publishing NS, HTTPS
			// or SVCB is the operator's call, not epistle's. Any
			// other (custom) type is also out of scope.
			RecordKind::Ns | RecordKind::Https | RecordKind::Svcb | RecordKind::Other(_) => {
				Err(ProviderError::Unsupported)
			}
		}
	}

	/// The Cloudflare record body for a record: TLSA and SRV carry a
	/// structured `data` object (`usage selector matching_type certificate` /
	/// `priority weight port target`), everything else a plain `content`
	/// string. SRV splits the presentation form on whitespace.
	#[cfg(test)]
	pub(super) fn record_body(kind: &str, record: &DnsRecord) -> Result<String, ProviderError> {
		Ok(Self::record_value(kind, record)?.to_string())
	}

	/// The record body as JSON, before tags are added.
	pub(super) fn record_value(
		kind: &str,
		record: &DnsRecord,
	) -> Result<serde_json::Value, ProviderError> {
		let mut value = if record.kind == RecordKind::Tlsa {
			let mut parts = record.value.split_whitespace();
			let usage: u8 =
				parts
					.next()
					.and_then(|p| p.parse().ok())
					.ok_or(ProviderError::Remote(
						"TLSA needs usage selector matching cert".into(),
					))?;
			let selector: u8 =
				parts
					.next()
					.and_then(|p| p.parse().ok())
					.ok_or(ProviderError::Remote(
						"TLSA needs usage selector matching cert".into(),
					))?;
			let matching: u8 =
				parts
					.next()
					.and_then(|p| p.parse().ok())
					.ok_or(ProviderError::Remote(
						"TLSA needs usage selector matching cert".into(),
					))?;
			let cert = parts.next().ok_or(ProviderError::Remote(
				"TLSA needs usage selector matching cert".into(),
			))?;
			serde_json::json!({
				"type": kind,
				"name": record.name,
				"ttl": record.ttl,
				"data": {
					"usage": usage,
					"selector": selector,
					"matching_type": matching,
					"certificate": cert,
				},
			})
		} else if record.kind == RecordKind::Srv {
			let (priority, weight, port, target) = parse_srv(&record.value)
				.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {}", record.value)))?;
			serde_json::json!({
				"type": kind,
				"name": record.name,
				"ttl": record.ttl,
				"data": {
					"priority": priority,
					"weight": weight,
					"port": port,
					"target": target,
				},
			})
		} else if record.kind == RecordKind::Caa {
			serde_json::json!({
				"type": kind,
				"name": record.name,
				"ttl": record.ttl,
				"data": Self::caa_data(&record.value)?,
			})
		} else if record.kind == RecordKind::Mx {
			// MX value: `<priority> <target>` — split into `priority` and
			// `host` fields per Cloudflare's MX data shape.
			let mut parts = record.value.split_whitespace();
			let priority: u8 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = crate::dns::provider::mx_target_for_api(target).to_string();
			serde_json::json!({
				"type": kind,
				"name": record.name,
				"ttl": record.ttl,
				"data": {
					"priority": priority,
					"host": target,
				},
			})
		} else {
			// A TXT `content` "must consist of quoted "character
			// strings" (RFC 1035), each with a length of up to 255
			// bytes. Strings exceeding this allowed maximum length are
			// automatically split."
			// (<https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/>,
			// TXTRecord.content, read 2026-10-12). Only the dashboard
			// adds missing quotes (DNS changelog, 2024-10-15); a value
			// sent through the API unquoted is stored as given, so it
			// goes quoted and already split, escaped the RFC 1035 way.
			let content = if record.kind == RecordKind::Txt {
				txt_encode(&record.value, TXT_FORM)
			} else {
				record.value.clone()
			};
			let mut body = serde_json::json!({
				"type": kind,
				"name": record.name,
				"content": content,
				"ttl": record.ttl,
			});
			// Cloudflare only accepts `proxied` on the kinds it can
			// actually proxy (A, AAAA, CNAME). Pin those to DNS-only:
			// the proxy only speaks HTTP(S), so a mail hostname, an
			// `autoconfig`, an `autodiscover`, or an `mta-sts` A/AAAA/CNAME
			// the proxy took over would never deliver mail. Other kinds
			// do not take the field.
			if matches!(
				record.kind,
				RecordKind::A | RecordKind::Aaaa | RecordKind::Cname
			) {
				body["proxied"] = serde_json::Value::from(false);
			}
			body
		};
		value["comment"] = serde_json::Value::from(record_description());
		Ok(value)
	}

	/// The Cloudflare wire shape for a CAA record body: per
	/// <https://developers.cloudflare.com/api/operations/dns-records-create-dns-record>
	/// CAA uses a `data` object with `flags`, `tag` and `value`. We parse the
	/// presentation form `"<flags> <tag> <value>"` we emit.
	pub(super) fn caa_data(value: &str) -> Result<serde_json::Value, ProviderError> {
		let mut parts = value.splitn(3, ' ');
		let flags: u8 = parts
			.next()
			.and_then(|p| p.parse().ok())
			.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?;
		let tag = parts
			.next()
			.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?
			.to_string();
		let v = parts
			.next()
			.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?
			.trim_matches('"')
			.to_string();
		Ok(serde_json::json!({
			"flags": flags,
			"tag": tag,
			"value": v,
		}))
	}
}
