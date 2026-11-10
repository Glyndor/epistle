//! Listing a Cloudflare zone: every page of `GET
//! /zones/{id}/dns_records`, each record read back into the shape the rest
//! of epistle uses (TXT as its logical value, MX as `priority target`, SRV
//! as `priority weight port target`, the orange-cloud `proxied` flag on the
//! kinds Cloudflare can proxy).

use super::{CloudflareProvider, ListRecords, RecordRef, TXT_FORM};
use crate::dns::provider::{DnsRecord, ProviderError, RecordKind};
use crate::dns::providers::{inconsistent_pages, missing_page_count};
use crate::dns::txt::txt_decode;
use std::time::Duration;

/// Records asked for per page of a zone listing: Cloudflare's default,
/// stated so the paging below does not depend on it. A zone read from its
/// first page alone looks like a zone without the rest of its records.
const LIST_PAGE_SIZE: u32 = 100;

/// The most pages one listing reads, so a server that keeps answering
/// with more pages cannot keep the listing going for ever.
const LIST_MAX_PAGES: u32 = 1000;

/// How many times one listing is read before an inconsistent answer is
/// given up on. Right after a write Cloudflare can answer a paged read
/// with totals that move; a few seconds later the same read is stable.
const LIST_ATTEMPTS: u32 = 5;

/// The pause before the first re-read; each later one doubles it, so the
/// five attempts wait 1, 2, 4 and 8 seconds, well inside the operation
/// deadline. Tests do not wait.
#[cfg(not(test))]
const LIST_RETRY_PAUSE: Duration = Duration::from_secs(1);
#[cfg(test)]
const LIST_RETRY_PAUSE: Duration = Duration::ZERO;

/// The pause after the `attempt`-th failed read (counted from 1).
fn retry_pause(base: Duration, attempt: u32) -> Duration {
	base * 2u32.saturating_pow(attempt - 1)
}

/// Why one read of the pages failed: the totals did not add up (worth
/// reading again) or anything else (reported as it is).
enum ReadError {
	Inconsistent(ProviderError),
	Other(ProviderError),
}

impl From<ProviderError> for ReadError {
	fn from(error: ProviderError) -> Self {
		Self::Other(error)
	}
}

impl CloudflareProvider {
	pub(super) async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		let zone_id = self.zone_id(zone).await?;
		Ok(self
			.list_refs(&zone_id, zone)
			.await?
			.into_iter()
			.map(|r| {
				let kind = RecordKind::from_token(&r.kind);
				// The read form is not documented. A record written by
				// the API comes back quoted (possibly re-split), one an
				// older release wrote unquoted comes back as it was;
				// `txt_decode` reads both as the logical value.
				let value = match (&kind, r.priority) {
					(RecordKind::Txt, _) => txt_decode(&r.content, TXT_FORM),
					// `priority target`, the shape every MX value has.
					(RecordKind::Mx, Some(priority)) => format!("{priority} {}", r.content),
					// Cloudflare keeps the SRV priority apart from the
					// rest too: the `content` holds `weight port
					// target`, so the priority goes in front of it.
					(RecordKind::Srv, Some(priority)) => format!("{priority} {}", r.content),
					_ => r.content,
				};
				// Cloudflare only returns `proxied` for the kinds it can
				// proxy (A, AAAA, CNAME). Other kinds leave it `None`,
				// which the rest of epistle treats as "not applicable".
				let proxied = match &kind {
					RecordKind::A | RecordKind::Aaaa | RecordKind::Cname => r.proxied,
					_ => None,
				};
				DnsRecord {
					name: r.name,
					kind,
					value,
					ttl: r.ttl,
					proxied,
				}
			})
			.collect())
	}
	/// All pages with record IDs retained for value-exact deletion. A
	/// listing whose pages do not add up is read again after a growing
	/// pause, up to [`LIST_ATTEMPTS`] reads; any other failure ends it at
	/// once, and an inconsistency that outlasts the attempts is the error.
	pub(super) async fn list_refs(
		&self,
		zone_id: &str,
		zone: &str,
	) -> Result<Vec<RecordRef>, ProviderError> {
		let mut attempt = 1;
		loop {
			match self.read_pages(zone_id, zone).await {
				Ok(listed) => return Ok(listed),
				Err(ReadError::Other(error)) => return Err(error),
				Err(ReadError::Inconsistent(error)) if attempt >= LIST_ATTEMPTS => {
					return Err(error);
				}
				Err(ReadError::Inconsistent(_)) => {
					tokio::time::sleep(retry_pause(LIST_RETRY_PAUSE, attempt)).await;
					attempt += 1;
				}
			}
		}
	}

	/// One read of every page.
	async fn read_pages(&self, zone_id: &str, zone: &str) -> Result<Vec<RecordRef>, ReadError> {
		let mut listed: Vec<RecordRef> = Vec::new();
		let mut page = 1;
		let mut expected: Option<u32> = None;
		loop {
			let url = self
				.records_url(zone_id, None)?
				.with_query("per_page", &LIST_PAGE_SIZE.to_string())
				.with_query("page", &page.to_string());
			let records: ListRecords = self.get_json(url).await?;
			let count = records.result.len();
			listed.extend(records.result);
			let (total_pages, total_count) = records
				.result_info
				.map_or((None, None), |info| (info.total_pages, info.total_count));
			// What the listing says about itself must add up, page by page.
			if total_count.is_some_and(|total| listed.len() > total)
				|| (total_pages.is_some() && expected.is_some() && expected != total_pages)
			{
				return Err(ReadError::Inconsistent(inconsistent_pages(zone)));
			}
			expected = total_pages.or(expected);
			match total_pages {
				Some(total) if page >= total => {
					if total_count.is_some_and(|count| listed.len() != count) {
						return Err(ReadError::Inconsistent(inconsistent_pages(zone)));
					}
					break;
				}
				Some(_) if count == 0 => {
					return Err(ReadError::Inconsistent(inconsistent_pages(zone)));
				}
				Some(_) => {}
				// No page count: a short page is the last one, a full page
				// may not be, and a zone is never read as finished on that
				// guess.
				None if count < LIST_PAGE_SIZE as usize => break,
				None => return Err(missing_page_count(zone).into()),
			}
			if page >= LIST_MAX_PAGES {
				return Err(ProviderError::Remote(format!(
					"the {zone} zone has more than {LIST_MAX_PAGES} pages of records"
				))
				.into());
			}
			page += 1;
		}
		Ok(listed)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_pause_doubles_after_each_failed_read() {
		let base = Duration::from_secs(1);
		let pauses: Vec<_> = (1..LIST_ATTEMPTS).map(|n| retry_pause(base, n)).collect();
		assert_eq!(pauses, [1, 2, 4, 8].map(Duration::from_secs));
	}
}
