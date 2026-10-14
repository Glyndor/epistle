//! Listing the rrsets of a Cloud DNS managed zone, every page of it.
//! Cloud DNS decides how many rrsets one answer holds and hands out a
//! `nextPageToken` for the rest; a zone read from its first page alone
//! looks like a zone without the rest of its records, and an upsert that
//! looks for the existing rrset there misses it.

use super::{GcloudProvider, ListRrsetsResp, Rrset};
use crate::dns::provider::ProviderError;

/// The most pages one listing reads, so a server that keeps handing out
/// page tokens cannot keep the listing going for ever.
const LIST_MAX_PAGES: usize = 1000;

impl GcloudProvider {
	pub(super) async fn list_rrsets(
		&self,
		managed_zone: &str,
	) -> Result<Vec<Rrset>, ProviderError> {
		let token = self.ensure_token().await?;
		let mut rrsets = Vec::new();
		let mut page_token: Option<String> = None;
		for _ in 0..LIST_MAX_PAGES {
			let mut url = self.managed_zones_url(&[managed_zone, "rrsets"])?;
			if let Some(page) = &page_token {
				url = url.with_query("pageToken", page);
			}
			let response = self
				.client
				.get(url.into_url())
				.bearer_auth(&token)
				.send()
				.await
				.map_err(|e| ProviderError::Remote(e.to_string()))?;
			Self::classify(&response, false)?;
			let text = self.read_body(response).await?;
			let parsed: ListRrsetsResp =
				serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))?;
			rrsets.extend(parsed.rrsets);
			match parsed.next_page_token {
				Some(next) if !next.is_empty() => page_token = Some(next),
				_ => return Ok(rrsets),
			}
		}
		Err(ProviderError::Remote(format!(
			"the {managed_zone} zone has more than {LIST_MAX_PAGES} pages of rrsets"
		)))
	}
}
