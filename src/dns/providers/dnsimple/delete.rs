//! The DNSimple delete.

use super::*;

impl DnsimpleProvider {
	pub(super) async fn delete_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let relative = self.relative_name(&record.name);
		// The TXT matching rule from `src/dns/provider/mod.rs` is the
		// contract: a value-bearing delete drops only the record
		// whose content matches the value (a sibling ACME challenge
		// at the same owner survives), an empty-value delete drops
		// every record at the owner (the DKIM rotator's retire
		// path). Other record kinds fall through to the
		// first-by-(name, kind) selection, which is the existing
		// whole-set semantics.
		if record.kind == RecordKind::Txt && record.value.is_empty() {
			let pages = self.list_page(zone).await?;
			let to_delete: Vec<u64> = pages
				.into_iter()
				.filter(|r| r.name == relative && r.kind.eq_ignore_ascii_case(kind))
				.map(|r| r.id)
				.collect();
			for id in to_delete {
				let url = self.records_url(zone, Some(id))?;
				self.delete_by_id(url).await?;
			}
			return Ok(());
		}
		let lookup_value = match record.kind {
			RecordKind::Txt => Some(record.value.as_str()),
			_ => None,
		};
		let Some(id) = self.find_id(zone, &relative, kind, lookup_value).await? else {
			return Ok(()); // already absent: idempotent.
		};
		let url = self.records_url(zone, Some(id))?;
		self.delete_by_id(url).await
	}

	pub(super) async fn delete_by_id(&self, url: HttpsUrl) -> Result<(), ProviderError> {
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
		// DNSimple returns 204 on a real delete; we accept any 2xx so a future
		// 200-with-body shape still parses as success.
		if status.is_success() {
			Ok(())
		} else {
			Err(ProviderError::Remote(format!("HTTP {status}")))
		}
	}
}
