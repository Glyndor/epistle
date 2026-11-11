//! The request body of a Porkbun record.

use super::*;

impl PorkbunProvider {
	/// The fields `create` and `edit` take for `record`, of Porkbun type
	/// `kind`; refused here, before any write, when the value is malformed.
	pub(super) fn record_fields(
		&self,
		record: &DnsRecord,
		kind: &str,
	) -> Result<serde_json::Value, ProviderError> {
		// The API documents `content` only as "The record value", with
		// no word on quoting, length or escaping for TXT
		// (<https://porkbun.com/api/json/v3/spec>, read 2026-10-12). The
		// logical value is the form that is the same bytes every time it
		// is sent, and it is the one other clients of this API send
		// (dnscontrol, lego, libdns).
		let content = if record.kind == RecordKind::Txt {
			txt_encode(&record.value, TXT_FORM)
		} else {
			record.value.clone()
		};
		let mut fields = serde_json::json!({
			"name": self.label(&record.name),
			"type": kind,
			"content": content,
			"ttl": record.ttl.max(MIN_TTL),
			// Free-text note shown in the Porkbun panel; edit replaces it.
			"notes": record_description(),
		});
		if record.kind == RecordKind::Srv {
			// Porkbun's SRV payload: the value carries the full presentation
			// form (`prio weight port target`) verbatim in `content`, and the
			// `prio` field is the plain preference (here, the priority, since
			// weight and port are part of the value already). We still validate
			// the value with parse_srv so a malformed SRV never reaches the API.
			let _ = Self::sr_prio(record)?;
			if let Some(map) = fields.as_object_mut() {
				map.insert(
					"prio".to_string(),
					parse_srv(&record.value)
						.map(|(p, _w, _port, _target)| p)
						.unwrap_or(0)
						.into(),
				);
			}
		}
		if record.kind == RecordKind::Caa {
			// Porkbun's CAA payload: `content` carries the CA value verbatim,
			// and the `caa_tag` field holds the tag ("issue", "issuewild",
			// "iodef"). We split the presentation form to surface malformed
			// input as a `Remote` error rather than letting Porkbun reject it.
			let mut parts = record.value.splitn(3, ' ');
			let _flags = parts.next();
			let tag = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?
				.to_string();
			let value = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?
				.trim_matches('"')
				.to_string();
			if let Some(map) = fields.as_object_mut() {
				map.insert("caa_tag".to_string(), tag.into());
				map.insert("content".to_string(), value.into());
			}
		}
		if record.kind == RecordKind::Mx {
			// Porkbun's MX payload: `content` carries the target, `prio`
			// carries the preference as an integer.
			let mut parts = record.value.split_whitespace();
			let priority: u16 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = crate::dns::provider::mx_target_for_api(target).to_string();
			if let Some(map) = fields.as_object_mut() {
				map.insert("prio".to_string(), priority.into());
				map.insert("content".to_string(), target.into());
			}
		}
		Ok(fields)
	}
}
