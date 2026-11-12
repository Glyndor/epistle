//! The Spaceship requests that add and remove a record.

use super::*;

impl SpaceshipProvider {
	/// `PUT /dns/records/{zone}` — append items with `force: true`. Spaceship
	/// documents the body as `{ force: true, items: [ ... ] }` and replies 204
	/// on success. SRV uses dedicated `priority`/`weight`/`port`/`target`
	/// fields; everything else uses the kind-specific value field.
	pub(super) async fn add(
		&self,
		kind: &str,
		rel: &str,
		record: &DnsRecord,
	) -> Result<(), ProviderError> {
		let item = Self::item_of(kind, rel, record)?;
		self.put_item(item, true).await
	}

	/// The item of a save request for `record`.
	pub(super) fn item_of(
		kind: &str,
		rel: &str,
		record: &DnsRecord,
	) -> Result<serde_json::Value, ProviderError> {
		let mut item = serde_json::json!({
			"type": kind,
			"name": rel,
			"ttl": record.ttl,
		});
		if record.kind == RecordKind::Srv {
			let (priority, weight, port, target) = parse_srv(&record.value)
				.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {}", record.value)))?;
			let map = item.as_object_mut().expect("object");
			map.insert("priority".to_string(), priority.into());
			map.insert("weight".to_string(), weight.into());
			map.insert("port".to_string(), port.into());
			map.insert("target".to_string(), target.into());
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
			let map = item.as_object_mut().expect("object");
			map.insert("flag".to_string(), flags.into());
			map.insert("tag".to_string(), tag.into());
			map.insert("value".to_string(), value.into());
		} else if record.kind == RecordKind::Mx {
			// Spaceship stores MX as `preference` (number) + `exchange`
			// (target) fields.
			let mut parts = record.value.split_whitespace();
			let priority: u16 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = crate::dns::provider::mx_target_for_api(target).to_string();
			let map = item.as_object_mut().expect("object");
			map.insert("preference".to_string(), priority.into());
			map.insert("exchange".to_string(), target.into());
		} else {
			let map = item.as_object_mut().expect("object");
			map.insert(
				Self::value_field(&record.kind).to_string(),
				Self::wire_value(record).into(),
			);
		}
		Ok(item)
	}

	/// Save `item`. `force` turns off Spaceship's conflict resolution, which
	/// the ordinary upsert wants and the guarded write does not: a conflict
	/// is refused there, not resolved by dropping somebody's record.
	pub(super) async fn put_item(
		&self,
		item: serde_json::Value,
		force: bool,
	) -> Result<(), ProviderError> {
		let url = self.records_url()?;
		let body = serde_json::json!({
			"force": force,
			"items": [item],
		})
		.to_string();
		let response = self
			.request(reqwest::Method::PUT, url)
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		check(response)
	}

	/// `DELETE /dns/records/{zone}`, remove the matching item(s). The body
	/// is an array of `{type, name, [value]}` records. The contract from
	/// `src/dns/provider/mod.rs` says a TXT delete with a value drops only
	/// the record whose value matches, and an empty-value delete drops
	/// every record at the owner (the DKIM rotator's retire path).
	/// Spaceship's API matches by `value` when the field is present,
	/// so the empty-value case omits the field to mean "wholesale";
	/// the value-bearing case includes it. Replies 204 whether or not
	/// anything matched (idempotent by definition).
	pub(super) async fn remove(
		&self,
		kind: &str,
		rel: &str,
		record: &DnsRecord,
	) -> Result<(), ProviderError> {
		// TXT value-bearing deletes need the value to disambiguate
		// same-name records; the wholesale empty-value case leaves
		// the field off.
		let value = (record.kind == RecordKind::Txt && !record.value.is_empty())
			.then(|| Self::wire_value(record));
		self.remove_value(kind, rel, value).await
	}

	/// Send one DELETE for `(kind, rel)`, naming `value` exactly as given
	/// when there is one.
	pub(super) async fn remove_value(
		&self,
		kind: &str,
		rel: &str,
		value: Option<String>,
	) -> Result<(), ProviderError> {
		let url = self.records_url()?;
		let mut item = serde_json::json!({"type": kind, "name": rel});
		if let Some(value) = value {
			item["value"] = serde_json::Value::String(value);
		}
		let response = self
			.request(reqwest::Method::DELETE, url)
			.body(serde_json::json!([item]).to_string())
			.send()
			.await
			.map_err(transport)?;
		check(response)
	}
}
