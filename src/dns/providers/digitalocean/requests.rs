//! The DigitalOcean create, update and delete requests and the record body.

use super::*;

impl DigitaloceanProvider {
	/// `POST /v2/domains/{zone}/records` — create a record; returns the
	/// server-assigned id.
	pub(super) async fn create(&self, zone: &str, body: String) -> Result<u64, ProviderError> {
		let url = self.records_url(zone, None)?;
		let response = self
			.client
			.post(url.into_url())
			.bearer_auth(self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(ProviderError::Auth);
		}
		if !status.is_success() {
			return Err(ProviderError::Remote(format!("HTTP {status}")));
		}
		let envelope: Envelope = decode(response).await?;
		Ok(envelope.domain_record.id)
	}

	/// `PUT /v2/domains/{zone}/records/{id}` — replace a record's data/ttl.
	pub(super) async fn update(
		&self,
		zone: &str,
		id: u64,
		body: String,
	) -> Result<(), ProviderError> {
		let url = self.records_url(zone, Some(id))?;
		let response = self
			.client
			.put(url.into_url())
			.bearer_auth(self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(ProviderError::Auth);
		}
		if status.is_success() {
			Ok(())
		} else {
			Err(ProviderError::Remote(format!("HTTP {status}")))
		}
	}

	/// `DELETE /v2/domains/{zone}/records/{id}` — DigitalOcean replies 204.
	pub(super) async fn delete_record(&self, zone: &str, id: u64) -> Result<(), ProviderError> {
		let url = self.records_url(zone, Some(id))?;
		let response = self
			.client
			.delete(url.into_url())
			.bearer_auth(self.secret.token())
			.send()
			.await
			.map_err(transport)?;
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(ProviderError::Auth);
		}
		if status.is_success() {
			Ok(())
		} else {
			Err(ProviderError::Remote(format!("HTTP {status}")))
		}
	}

	/// Build the create/update JSON body. The API reference describes
	/// `data` only as "Variable data depending on record type" and the
	/// product guide shows a TXT value unquoted
	/// (<https://docs.digitalocean.com/reference/api/reference/domain-records/>
	/// and <https://docs.digitalocean.com/products/networking/dns/how-to/manage-records/>,
	/// read 2026-10-12); quoting, splitting past 255 octets and escaping are
	/// not documented. A TXT goes as its logical value, which other clients
	/// send too (lego, dnscontrol) and which DigitalOcean lists back as
	/// written. SRV splits the presentation form into the dedicated fields.
	pub(super) fn record_body(
		kind: &str,
		rel: &str,
		record: &DnsRecord,
	) -> Result<String, ProviderError> {
		if record.kind == RecordKind::Srv {
			let (priority, weight, port, target) = parse_srv(&record.value)
				.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {}", record.value)))?;
			return Ok(serde_json::json!({
				"type": kind,
				"name": rel,
				"data": target,
				"priority": priority,
				"weight": weight,
				"port": port,
				"ttl": record.ttl,
			})
			.to_string());
		}
		if record.kind == RecordKind::Caa {
			let mut parts = record.value.splitn(3, ' ');
			let flags: u8 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?;
			let tag = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?
				.to_string();
			let value = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?
				.trim_matches('"')
				.to_string();
			return Ok(serde_json::json!({
				"type": kind,
				"name": rel,
				"data": value,
				"priority": flags,
				"tag": tag,
				"ttl": record.ttl,
			})
			.to_string());
		}
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
				"type": kind,
				"name": rel,
				"data": target,
				"priority": priority,
				"ttl": record.ttl,
			})
			.to_string());
		}
		let data = if record.kind == RecordKind::Txt {
			txt_encode(&record.value, TXT_FORM)
		} else {
			record.value.clone()
		};
		Ok(serde_json::json!({
			"type": kind,
			"name": rel,
			"data": data,
			"ttl": record.ttl,
		})
		.to_string())
	}
}
