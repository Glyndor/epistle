//! The TXT record set reads and writes of the Route 53 provider.

use super::*;

impl Route53Provider {
	/// Find the TXT rrset at `name`. ListResourceRecordSets returns at
	/// most a page of record sets per call and says the list goes on
	/// with `IsTruncated` true plus `NextRecordName` and `NextRecordType`,
	/// which the next request passes as `name` and `type`
	/// (<https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListResourceRecordSets.html>,
	/// read 2026-10-12). The pages are followed until the rrset turns up
	/// or the list ends, so a zone bigger than one page does not hide it.
	/// The XML is read with a small hand-rolled reader; the response is
	/// well-formed by API contract.
	pub(super) async fn fetch_txt_rrset(&self, name: &str) -> Result<Option<Rrset>, ProviderError> {
		self.fetch_rrset(name, "TXT").await
	}

	/// [`Self::fetch_txt_rrset`] for the record set of `kind` at `name`.
	pub(super) async fn fetch_rrset(
		&self,
		name: &str,
		kind: &str,
	) -> Result<Option<Rrset>, ProviderError> {
		let mut start: Option<list::Start> = None;
		loop {
			let text = self.list_page(start.as_ref()).await?;
			if let Some(rrset) = parse_rrset(&text, name, kind) {
				return Ok(Some(rrset));
			}
			match next_page(&text) {
				Some(next) if start.as_ref() != Some(&next) => start = Some(next),
				_ => return Ok(None),
			}
		}
	}

	/// One signed `GET .../rrset` page, starting at `(name, type,
	/// identifier)` when given.
	pub(super) async fn list_page(
		&self,
		start: Option<&list::Start>,
	) -> Result<String, ProviderError> {
		self.list_page_sized(start, None).await
	}

	/// [`Self::list_page`] with at most `max` record sets in the answer.
	pub(super) async fn list_page_sized(
		&self,
		start: Option<&list::Start>,
		max: Option<u32>,
	) -> Result<String, ProviderError> {
		let mut url = self.rrset_url()?;
		if let Some((name, kind, identifier)) = start {
			url = url.with_query("name", name).with_query("type", kind);
			if let Some(identifier) = identifier {
				url = url.with_query("identifier", identifier);
			}
		}
		if let Some(max) = max {
			url = url.with_query("maxitems", &max.to_string());
		}
		let path = url.as_url().path().to_string();
		let query = canonical_query(url.as_url());
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default();
		let (amz_date, date) = timestamps(now.as_secs());
		let auth = self.authorization_get(&path, &query, &amz_date, &date);
		let response = self
			.client
			.get(url.into_url())
			.header("x-amz-date", &amz_date)
			.header(reqwest::header::HOST, HOST)
			.header(reqwest::header::AUTHORIZATION, auth)
			.send()
			.await
			.map_err(transport)?;
		let status = response.status();
		if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
			return Err(ProviderError::Auth);
		}
		if !status.is_success() {
			return Err(ProviderError::Remote(format!("HTTP {status}")));
		}
		crate::dns::providers::read_body(response).await
	}

	/// UPSERT one rrset carrying the given values verbatim. Used by
	/// the value-bearing TXT delete to drop a single rdata and keep
	/// the siblings.
	pub(super) async fn upsert_rrset(
		&self,
		name: &str,
		kind: &str,
		ttl: u32,
		values: &[String],
	) -> Result<(), ProviderError> {
		let url = self.rrset_url()?;
		let path = url.as_url().path().to_string();
		let value_xml: String = values
			.iter()
			.map(|v| {
				format!(
					"<ResourceRecord><Value>{}</Value></ResourceRecord>",
					xml_escape(v)
				)
			})
			.collect();
		let body = format!(
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/{API_VERSION}/\">\
<ChangeBatch><Changes><Change>\
<Action>UPSERT</Action>\
<ResourceRecordSet>\
<Name>{}</Name><Type>{kind}</Type><TTL>{ttl}</TTL>\
<ResourceRecords>{value_xml}</ResourceRecords>\
</ResourceRecordSet></Change></Changes></ChangeBatch>\
</ChangeResourceRecordSetsRequest>",
			xml_escape(name),
		);
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default();
		let (amz_date, date) = timestamps(now.as_secs());
		let auth = self.authorization(&path, &body, &amz_date, &date);
		let response = self
			.client
			.post(url.into_url())
			.header("x-amz-date", &amz_date)
			.header(reqwest::header::HOST, HOST)
			.header(reqwest::header::AUTHORIZATION, auth)
			.header(reqwest::header::CONTENT_TYPE, "application/xml")
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		let status = response.status();
		if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
			return Err(ProviderError::Auth);
		}
		if status.is_success() {
			Ok(())
		} else {
			Err(ProviderError::Remote(format!("HTTP {status}")))
		}
	}
}
