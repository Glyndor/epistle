//! The Cloudflare upsert and delete, which find the record first and then write.

use super::*;

impl CloudflareProvider {
	pub(super) async fn upsert_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let zone_id = self.zone_id(zone).await?;
		let body = Self::record_value(kind, &record)?;
		// The upsert contract in `src/dns/provider/mod.rs`: a TXT replaces
		// the record of the same purpose and leaves every other TXT
		// at the name alone (an ACME challenge, a verification
		// token). Two records of the same purpose at the same name
		// are a configuration mistake (SPF returns permerror, DMARC
		// is ignored): the upsert collapses them by editing the
		// first match and deleting every other. Every other kind
		// owns its name, so the write replaces the whole set: the
		// first record is updated in place and any others at the
		// name are removed.
		let found = self.find_records(&zone_id, &record.name, kind).await?;
		let (existing, extra) = if record.kind == RecordKind::Txt {
			// Filter to records of the same purpose only: an
			// untagged TXT at the same owner (an ACME challenge,
			// a site-verification token) is not a duplicate of
			// epistle's record and the upsert must leave it alone.
			let mut found = found
				.into_iter()
				.filter(|r| same_txt_purpose(&r.content, &record.value));
			let primary = found.next();
			let rest: Vec<RecordRef> = found.collect();
			(primary, rest)
		} else {
			let mut found = found.into_iter();
			(found.next(), found.collect::<Vec<_>>())
		};
		self.write_record(&zone_id, existing.as_ref(), &body)
			.await?;
		for stale in extra {
			self.delete_id(&zone_id, &stale.id).await?;
		}
		Ok(())
	}

	/// Create the record `body` describes, or update `existing` in place
	/// by its id. The tags of the record are kept but for epistle's own,
	/// and a refusal over tags is retried once without them.
	pub(super) async fn write_record(
		&self,
		zone_id: &str,
		existing: Option<&RecordRef>,
		body: &serde_json::Value,
	) -> Result<(), ProviderError> {
		let operator_tags: Vec<String> = existing.map(|r| r.tags.clone()).unwrap_or_default();
		let url = self.records_url(zone_id, existing.map(|r| r.id.as_str()))?;
		let own = self
			.host_tag
			.as_deref()
			.filter(|_| self.tags_allowed.load(Ordering::Relaxed));
		let response = self
			.write(
				&url,
				existing.is_some(),
				body,
				&cloudflare_tags::merge(&operator_tags, own),
			)
			.await?;
		if own.is_some() && retry_without_tags(response.status()) {
			let retry = self
				.write(
					&url,
					existing.is_some(),
					body,
					&cloudflare_tags::merge(&operator_tags, None),
				)
				.await?;
			if retry.status().is_success() {
				self.tags_allowed.store(false, Ordering::Relaxed);
				tracing::warn!(
					"Cloudflare refused DNS record tags (they need a paid plan); records are written without them from now on"
				);
			}
			decode_ok(retry).await
		} else {
			decode_ok(response).await
		}
	}

	/// Delete the record with `id`.
	pub(super) async fn delete_id(&self, zone_id: &str, id: &str) -> Result<(), ProviderError> {
		let response = self
			.client
			.delete(self.records_url(zone_id, Some(id))?.into_url())
			.bearer_auth(self.secret.token())
			.send()
			.await
			.map_err(transport)?;
		decode_ok(response).await
	}

	/// Send one create (POST) or update (PUT) with `tags`; the body is
	/// `body` plus a `tags` array when there are any.
	pub(super) async fn write(
		&self,
		url: &HttpsUrl,
		update: bool,
		body: &serde_json::Value,
		tags: &[String],
	) -> Result<reqwest::Response, ProviderError> {
		let mut body = body.clone();
		if !tags.is_empty() {
			body["tags"] = serde_json::Value::from(tags.to_vec());
		}
		let method = if update {
			reqwest::Method::PUT
		} else {
			reqwest::Method::POST
		};
		self.client
			.request(method, url.clone().into_url())
			.bearer_auth(self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body.to_string())
			.send()
			.await
			.map_err(transport)
	}

	pub(super) async fn delete_inner(
		&self,
		zone: &str,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let zone_id = self.zone_id(zone).await?;
		// The TXT matching rule from `src/dns/provider/mod.rs` is the
		// contract: a value-bearing delete drops only the record
		// whose content matches the value (a sibling ACME challenge
		// at the same owner survives), an empty-value delete drops
		// every record at the owner (the DKIM rotator's retire
		// path). Other record kinds fall through to the
		// first-by-(type, name) selection, which is the existing
		// whole-set semantics.
		let needle = if record.kind == RecordKind::Txt {
			if record.value.is_empty() {
				None
			} else {
				Some(record.value.as_str())
			}
		} else {
			None
		};
		let Some(found) = self
			.find_record(&zone_id, &record.name, kind, needle)
			.await?
		else {
			return Ok(()); // already absent: idempotent.
		};
		self.delete_id(&zone_id, &found.id).await
	}
}
