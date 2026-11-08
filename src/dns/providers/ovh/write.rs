//! The OVH upsert and delete.

use super::*;

impl OvhProvider {
	pub(super) async fn upsert_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let sub = Self::sub_domain(zone, &record.name);
		// The API schema gives `target` only as "Target of the record"
		// (<https://eu.api.ovh.com/v1/domain.json>, read 2026-10-12), and
		// the DNS zone guide shows TXT and DKIM targets unquoted
		// (<https://github.com/ovh/docs/blob/develop/pages/web_cloud/domains/dns_zone_records/guide.en-gb.md>,
		// read 2026-10-12). Nothing documents quoting, splitting or
		// escaping for the API. Other clients send the logical value
		// unsplit because OVH refuses pre-split strings (dnscontrol's
		// ovh provider), and OVH lists a plain TXT back quoted and split
		// (<https://github.com/ovh/terraform-provider-ovh/issues/1225>
		// shows a DKIM key coming back as two quoted strings). Logical
		// out, `txt_decode` in.
		let target = if record.kind == RecordKind::Txt {
			txt_encode(&record.value, TXT_FORM)
		} else {
			record.value.clone()
		};
		let body = serde_json::json!({
			"fieldType": kind,
			"subDomain": sub,
			"target": target,
			"ttl": record.ttl,
		})
		.to_string();
		// The TXT matching rule from `src/dns/provider/mod.rs` is the
		// contract: an upsert replaces the TXT with the same
		// purpose (version tag) at that name and leaves every
		// other TXT at the name alone. Two records of the same
		// purpose are a configuration mistake (SPF returns
		// permerror, DMARC is ignored): the upsert collapses them
		// by PUTing the first match with the new value and
		// DELETEing every other. `same_txt_purpose` carries the
		// contract; for non-TXT kinds the matching is just
		// (kind, sub) and the first match is fine.
		if record.kind == RecordKind::Txt {
			let mut ids = self
				.find_record_ids(zone, &sub, kind, Some(&record.value))
				.await?;
			match ids.next() {
				Some(primary) => {
					let url = self.zone_url(zone, &["record", &primary.to_string()])?;
					self.send_unit(reqwest::Method::PUT, &url, &body).await?;
					for dup in ids {
						let dup_url = self.zone_url(zone, &["record", &dup.to_string()])?;
						self.send_unit(reqwest::Method::DELETE, &dup_url, "")
							.await?;
					}
				}
				None => {
					let url = self.zone_url(zone, &["record"])?;
					self.send_unit(reqwest::Method::POST, &url, &body).await?;
				}
			}
		} else if let Some(id) = self.find_record_id(zone, &sub, kind, None).await? {
			let url = self.zone_url(zone, &["record", &id.to_string()])?;
			self.send_unit(reqwest::Method::PUT, &url, &body).await?;
		} else {
			let url = self.zone_url(zone, &["record"])?;
			self.send_unit(reqwest::Method::POST, &url, &body).await?;
		}
		self.refresh_zone(zone).await
	}

	/// `delete` is idempotent: an absent record returns Ok without a refresh
	/// (no zone mutation happened).
	pub(super) async fn delete_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let sub = Self::sub_domain(zone, &record.name);
		// The TXT matching rule from `src/dns/provider/mod.rs` is the
		// contract: a value-bearing delete drops only the record
		// whose target matches the value (a sibling ACME challenge
		// at the same owner survives), an empty-value delete drops
		// every record at the owner (the DKIM rotator's retire
		// path). Other record kinds fall through to the
		// first-by-(kind, sub) selection, which is the existing
		// whole-set semantics.
		if record.kind == RecordKind::Txt && record.value.is_empty() {
			let ids: Vec<u64> = self
				.send_json(reqwest::Method::GET, &self.find_url(zone, kind, &sub)?, "")
				.await?;
			let deleted_any = !ids.is_empty();
			for id in &ids {
				let url = self.zone_url(zone, &["record", &id.to_string()])?;
				self.send_unit(reqwest::Method::DELETE, &url, "").await?;
			}
			if deleted_any {
				self.refresh_zone(zone).await?;
			}
			return Ok(());
		}
		let lookup_value = match record.kind {
			RecordKind::Txt => Some(record.value.as_str()),
			_ => None,
		};
		let Some(id) = self.find_record_id(zone, &sub, kind, lookup_value).await? else {
			return Ok(());
		};
		let url = self.zone_url(zone, &["record", &id.to_string()])?;
		self.send_unit(reqwest::Method::DELETE, &url, "").await?;
		self.refresh_zone(zone).await
	}
}
