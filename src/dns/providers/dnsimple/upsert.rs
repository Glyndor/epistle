//! The DNSimple upsert and the request bodies it writes.

use super::*;

impl DnsimpleProvider {
	pub(super) async fn upsert_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let relative = self.relative_name(&record.name);
		// The TXT matching rule from `src/dns/provider/mod.rs` is the
		// contract: an upsert replaces the TXT with the same
		// purpose (version tag) at that name and leaves every
		// other TXT at the name alone. Two records of the same
		// purpose are a configuration mistake (SPF returns
		// permerror, DMARC is ignored): the upsert collapses them
		// by PATCHing the first match and DELETEing every other.
		// `same_txt_purpose` carries the contract; for non-TXT
		// kinds the matching is just (name, kind) and the first
		// match is fine.
		if record.kind == RecordKind::Txt {
			let lookup = record.value.clone();
			let mut ids = self.find_ids(zone, &relative, kind, Some(&lookup)).await?;
			match ids.next() {
				Some(primary) => {
					self.write_record(zone, primary, record).await?;
					for dup in ids {
						self.delete_by_id(self.records_url(zone, Some(dup))?)
							.await?;
					}
					Ok(())
				}
				None => self.create_record(zone, record).await,
			}
		} else {
			match self.find_id(zone, &relative, kind, None).await? {
				Some(id) => self.write_record(zone, id, record).await,
				None => self.create_record(zone, record).await,
			}
		}
	}

	pub(super) async fn create_record(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		let kind = Self::api_kind(&record.kind)?;
		let relative = self.relative_name(&record.name);
		let body = self.record_body(kind, &relative, &record)?;
		self.write_body(zone, None, body).await
	}

	pub(super) async fn write_record(
		&self,
		zone: &str,
		id: u64,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		let kind = Self::api_kind(&record.kind)?;
		let relative = self.relative_name(&record.name);
		let body = self.record_body(kind, &relative, &record)?;
		self.write_body(zone, Some(id), body).await
	}

	pub(super) async fn write_body(
		&self,
		zone: &str,
		id: Option<u64>,
		body: String,
	) -> Result<(), ProviderError> {
		let url = match id {
			Some(id) => self.records_url(zone, Some(id))?,
			None => self.records_url(zone, None)?,
		};
		let request = if id.is_some() {
			self.client.patch(url.into_url())
		} else {
			self.client.post(url.into_url())
		};
		let response = request
			.bearer_auth(self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		check(response)
	}

	pub(super) fn record_body(
		&self,
		kind: &str,
		relative: &str,
		record: &DnsRecord,
	) -> Result<String, ProviderError> {
		let body = if record.kind == RecordKind::Srv {
			let (priority, weight, port, target) = parse_srv(&record.value)
				.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {}", record.value)))?;
			serde_json::json!({
				"name": relative,
				"type": kind,
				"content": target,
				"ttl": record.ttl,
				"priority": priority,
				"weight": weight,
				"port": port,
			})
			.to_string()
		} else if record.kind == RecordKind::Caa {
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
			serde_json::json!({
				"name": relative,
				"type": kind,
				"content": value,
				"ttl": record.ttl,
				"flags": flags,
				"caa_tag": tag,
			})
			.to_string()
		} else if record.kind == RecordKind::Mx {
			let mut parts = record.value.split_whitespace();
			let priority: u16 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = crate::dns::provider::mx_target_for_api(target).to_string();
			serde_json::json!({
				"name": relative,
				"type": kind,
				"content": target,
				"ttl": record.ttl,
				"priority": priority,
			})
			.to_string()
		} else {
			// DNSimple serializes an unquoted TXT itself, but content
			// already in double quotes "will store and publish this
			// content verbatim", splitting past 255 is automatic, and
			// pre-split "chunk1" "chunk2" is stored as is
			// (<https://support.dnsimple.com/articles/txt-record-format/>,
			// read 2026-10-12). Sending the presentation form makes the
			// stored content exactly what was sent, the same bytes every
			// time, with the escaping under our control.
			let content = if record.kind == RecordKind::Txt {
				txt_encode(&record.value, TXT_FORM)
			} else {
				record.value.clone()
			};
			serde_json::json!({
				"name": relative,
				"type": kind,
				"content": content,
				"ttl": record.ttl,
			})
			.to_string()
		};
		Ok(body)
	}
}
