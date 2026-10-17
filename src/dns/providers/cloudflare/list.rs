//! Listing a Cloudflare zone: every page of `GET
//! /zones/{id}/dns_records`, each record read back into the shape the rest
//! of epistle uses (TXT as its logical value, MX as `priority target`, the
//! orange-cloud `proxied` flag on the kinds Cloudflare can proxy).

use super::{CloudflareProvider, ListRecords, RecordRef, TXT_FORM};
use crate::dns::provider::{DnsRecord, ProviderError, RecordKind};
use crate::dns::txt::txt_decode;

/// Records asked for per page of a zone listing: Cloudflare's default,
/// stated so the paging below does not depend on it. A zone read from its
/// first page alone looks like a zone without the rest of its records.
const LIST_PAGE_SIZE: u32 = 100;

/// The most pages one listing reads, so a server that keeps answering
/// with more pages cannot keep the listing going for ever.
const LIST_MAX_PAGES: u32 = 1000;

impl CloudflareProvider {
	pub(super) async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		let zone_id = self.zone_id(zone).await?;
		let mut listed: Vec<RecordRef> = Vec::new();
		let mut page = 1;
		loop {
			let url = self
				.records_url(&zone_id, None)?
				.with_query("per_page", &LIST_PAGE_SIZE.to_string())
				.with_query("page", &page.to_string());
			let records: ListRecords = self.get_json(url).await?;
			listed.extend(records.result);
			let total = records
				.result_info
				.and_then(|info| info.total_pages)
				.unwrap_or(1);
			if page >= total {
				break;
			}
			if page >= LIST_MAX_PAGES {
				return Err(ProviderError::Remote(format!(
					"the {zone} zone has more than {LIST_MAX_PAGES} pages of records"
				)));
			}
			page += 1;
		}
		Ok(listed
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
}
