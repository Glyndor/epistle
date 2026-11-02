//! The paged reads of the DigitalOcean provider.

use super::*;

impl DigitaloceanProvider {
	/// `GET /v2/domains/{zone}/records?per_page=200&name=&type=` — returns the
	/// matching records, following the pagination links.
	pub(super) async fn find_records(
		&self,
		zone: &str,
		kind: &str,
		name: &str,
	) -> Result<Vec<DomainRecord>, ProviderError> {
		let url = self
			.records_url(zone, None)?
			.with_query("per_page", "200")
			.with_query("type", kind)
			.with_query("name", name);
		self.fetch_pages(url, zone).await
	}

	/// `GET /v2/domains/{zone}/records?per_page=200` — every record (for
	/// [`DnsProvider::list`]).
	pub(super) async fn list_all(&self, zone: &str) -> Result<Vec<DomainRecord>, ProviderError> {
		let url = self.records_url(zone, None)?.with_query("per_page", "200");
		self.fetch_pages(url, zone).await
	}

	/// GET `first` and every page DigitalOcean links to through
	/// `links.pages.next` until exhausted, so a zone with hundreds of records
	/// is not silently truncated. The link comes from the response body, so it
	/// is resolved against the configured base and refused when it points at a
	/// different origin: the bearer token must not follow it anywhere else.
	pub(super) async fn fetch_pages(
		&self,
		first: HttpsUrl,
		zone: &str,
	) -> Result<Vec<DomainRecord>, ProviderError> {
		let mut url = first;
		let mut out = Vec::new();
		let mut pages = 0;
		loop {
			let response = self
				.client
				.get(url.clone().into_url())
				.bearer_auth(self.secret.token())
				.send()
				.await
				.map_err(transport)?;
			let status = response.status();
			if status == reqwest::StatusCode::UNAUTHORIZED
				|| status == reqwest::StatusCode::FORBIDDEN
			{
				return Err(ProviderError::Auth);
			}
			if status == reqwest::StatusCode::NOT_FOUND {
				if pages == 0 {
					// The records of a domain DigitalOcean does not
					// hold: the domain is not there, which is not a
					// failure of the provider, and the search goes on
					// to the parent.
					return Err(ProviderError::ZoneNotFound(zone.to_string()));
				}
				// A page after a valid one: the first page proved the
				// domain is there, so this is a failure of the
				// provider and not an absent domain.
				return Err(ProviderError::Remote(format!("HTTP {status}")));
			}
			let page: ListResponse = decode(response).await?;
			out.extend(page.domain_records);
			pages += 1;
			if out.len() > LIST_MAX_RECORDS {
				return Err(listing_too_long(self.secret.zone()));
			}
			// What the listing says about itself must add up, page by page.
			let total = page.meta.total;
			if total.is_some_and(|total| out.len() > total) {
				return Err(inconsistent_pages(self.secret.zone()));
			}
			match page.links.pages.next {
				Some(next) if !next.is_empty() => {
					if pages >= LIST_MAX_PAGES {
						return Err(listing_too_long(self.secret.zone()));
					}
					url = self.base.follow(&next)?;
				}
				_ => {
					if total.is_some_and(|total| out.len() != total) {
						return Err(inconsistent_pages(self.secret.zone()));
					}
					break;
				}
			}
		}
		Ok(out)
	}
}
