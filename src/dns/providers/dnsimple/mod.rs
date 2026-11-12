//! A DNSimple DNS provider implementing [`DnsProvider`]. Authenticates with a
//! user-token in `Authorization: Bearer …` and routes every request under
//! `/v2/{account_id}/zones/{zone}/records`. Records are individual objects with
//! numeric ids; `upsert` lists first (filtering by `name` and `type`), then
//! either `POST` a new record or `PATCH` the existing one. `list` walks the
//! paginated list endpoint and returns FQDNs.
//!
//! Endpoints used (from the DNSimple API v2 reference at
//! <https://developer.dnsimple.com/v2/zones/records/>):
//!
//! - `GET    /v2/{account_id}/zones/{zone}/records?per_page=100` (paginated; we
//!   follow `pagination.total_pages`).
//! - `POST   /v2/{account_id}/zones/{zone}/records` — `{ name, type, content, ttl }`.
//! - `PATCH  /v2/{account_id}/zones/{zone}/records/{record_id}` — same shape.
//! - `DELETE /v2/{account_id}/zones/{zone}/records/{record_id}` — 204 No Content.
//!
//! Responses are wrapped in `{ "data": ... }`; lists also carry a `pagination`
//! object. The `account_id` is configured alongside the token; it is not a
//! secret but is required to address the account.

use std::pin::Pin;

use serde::Deserialize;

use crate::dns::providers::{
	LIST_MAX_PAGES, LIST_MAX_RECORDS, inconsistent_pages, listing_too_long, missing_page_count,
};
use crate::net::HttpsUrl;

use crate::dns::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, parse_srv, same_txt_purpose,
};
use crate::dns::providers::transport;
use crate::dns::publish::provider::{Change, ReceiptOp, SnapshotOp};
use crate::dns::txt::{TxtForm, txt_decode, txt_encode};

/// How DNSimple takes a TXT `content` and lists it back; see `upsert_inner`.
const TXT_FORM: TxtForm = TxtForm::Presentation;

/// DNSimple's API root. The account id goes in the path (`/v2/{id}/...`), so
/// the base stops at `/v2` and we append `<account_id>` per request.
const DEFAULT_BASE: &str = "https://api.dnsimple.com/v2";

/// `per_page` ceiling — DNSimple accepts up to 100, the maximum, to minimise
/// pagination round trips on `list`.
const PER_PAGE: u32 = 100;

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A DNSimple-backed DNS provider for one account and zone.
pub struct DnsimpleProvider {
	client: reqwest::Client,
	secret: ScopedSecret,
	account_id: String,
	base: HttpsUrl,
}

#[derive(Deserialize)]
struct ListResponse {
	data: Vec<Record>,
	pagination: Pagination,
}

#[derive(Deserialize)]
struct Pagination {
	/// Absent when the answer does not say how many pages there are.
	#[serde(default)]
	total_pages: Option<u32>,
	/// How many records the whole listing holds.
	#[serde(default)]
	total_entries: Option<usize>,
}

#[derive(Deserialize)]
struct Record {
	id: u64,
	#[serde(default)]
	name: String,
	#[serde(rename = "type", default)]
	kind: String,
	#[serde(default)]
	content: String,
	#[serde(default)]
	ttl: u32,
	#[serde(default)]
	priority: Option<u16>,
	#[serde(default)]
	weight: Option<u16>,
	#[serde(default)]
	port: Option<u16>,
	#[serde(default)]
	flags: Option<u8>,
	#[serde(default)]
	caa_tag: Option<String>,
}

impl DnsimpleProvider {
	/// Build a provider for the token's zone in `account_id`. Without
	/// `account_id` there is no URL to call, so the caller is expected to gate
	/// that case at the config layer.
	pub fn new(secret: ScopedSecret, account_id: impl Into<String>) -> Self {
		DnsimpleProvider {
			client: crate::dns::providers::http_client(),
			secret,
			account_id: account_id.into(),
			base: HttpsUrl::from_static(DEFAULT_BASE),
		}
	}

	/// Point the provider at an alternate API root (tests). The account id is
	/// still appended per request.
	pub fn with_base(mut self, base: HttpsUrl) -> Self {
		self.base = base;
		self
	}

	/// `{base}/{account_id}/zones/{zone}/records[/{record_id}]`, with the
	/// account id and the zone each escaped as one path segment.
	fn records_url(&self, zone: &str, record_id: Option<u64>) -> Result<HttpsUrl, ProviderError> {
		let mut segments = vec![
			self.account_id.clone(),
			"zones".to_string(),
			zone.to_string(),
			"records".to_string(),
		];
		segments.extend(record_id.map(|id| id.to_string()));
		Ok(self.base.with_segments(segments)?)
	}

	/// The DNSimple record type token for a kind we can publish. TXT/A/AAAA/CNAME
	/// and SRV (after splitting priority/weight/port/target) go through `content`
	/// plus dedicated fields; TLSA has no structured field on DNSimple, and MX
	/// needs the priority split out, so both stay Unsupported.
	fn api_kind(kind: &RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A => Ok("A"),
			RecordKind::Aaaa => Ok("AAAA"),
			RecordKind::Txt => Ok("TXT"),
			RecordKind::Cname => Ok("CNAME"),
			RecordKind::Mx => Ok("MX"),
			RecordKind::Srv => Ok("SRV"),
			RecordKind::Caa => Ok("CAA"),
			// TLSA has no structured field on DNSimple.
			RecordKind::Tlsa => Err(ProviderError::Unsupported),
			RecordKind::Ns | RecordKind::Https | RecordKind::Svcb | RecordKind::Other(_) => {
				Err(ProviderError::Unsupported)
			}
		}
	}

	/// The relative name (label left of the zone); the apex is the empty
	/// string — DNSimple expects that, not `@` or the zone itself.
	fn relative_name(&self, name: &str) -> String {
		let name = name.trim_end_matches('.');
		let zone = self.secret.zone();
		if name.eq_ignore_ascii_case(zone) {
			return String::new();
		}
		name.strip_suffix(&format!(".{zone}"))
			.unwrap_or(name)
			.to_string()
	}

	/// Reject a record the token is not scoped for, before any network call.
	fn authorize(&self, record: &DnsRecord) -> Result<(), ProviderError> {
		if self.secret.authorizes(&record.name) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	/// Walk all pages of the list endpoint and concatenate the records.
	async fn list_page(&self, zone: &str) -> Result<Vec<Record>, ProviderError> {
		let mut all = Vec::new();
		let mut expected: Option<u32> = None;
		for page in 1.. {
			let url = self
				.records_url(zone, None)?
				.with_query("per_page", &PER_PAGE.to_string())
				.with_query("page", &page.to_string());
			let response = self
				.client
				.get(url.into_url())
				.bearer_auth(self.secret.token())
				.send()
				.await
				.map_err(transport)?;
			let status = response.status();
			if status == reqwest::StatusCode::NOT_FOUND {
				if page == 1 {
					// DNSimple answers 404 for a zone it does not hold:
					// the zone is not there, which is not a failure of
					// the provider, and the search goes on to the
					// parent.
					return Err(ProviderError::ZoneNotFound(zone.to_string()));
				}
				// A page after a valid one: the first page proved the
				// zone is there, so this is a failure of the provider
				// and not an absent zone.
				return Err(ProviderError::Remote(format!("HTTP {status}")));
			}
			let mut batch: ListResponse = decode(response).await?;
			let count = batch.data.len();
			all.append(&mut batch.data);
			if all.len() > LIST_MAX_RECORDS {
				return Err(listing_too_long(zone));
			}
			// What the listing says about itself must add up, page by page.
			let total_pages = batch.pagination.total_pages;
			let total_entries = batch.pagination.total_entries;
			if total_entries.is_some_and(|total| all.len() > total)
				|| (total_pages.is_some() && expected.is_some() && expected != total_pages)
			{
				return Err(inconsistent_pages(zone));
			}
			expected = total_pages.or(expected);
			match total_pages {
				Some(total) if page >= total => {
					if total_entries.is_some_and(|entries| all.len() != entries) {
						return Err(inconsistent_pages(zone));
					}
					break;
				}
				Some(_) if count == 0 => return Err(inconsistent_pages(zone)),
				Some(_) => {}
				// No page count: a short page is the last one, a full
				// page may not be, and a zone is never read as finished
				// on that guess.
				None if count < PER_PAGE as usize => break,
				None => return Err(missing_page_count(zone)),
			}
			if page as usize >= LIST_MAX_PAGES {
				return Err(listing_too_long(zone));
			}
		}
		Ok(all)
	}

	/// Find the id of an existing record with matching relative name and kind,
	/// if any. When `value` is `Some`, the match is by content too: a
	/// `same_txt_purpose` comparison for TXT (so the existing tagged
	/// record is updated in place) or exact-match for the first record
	/// otherwise. A `None` value keeps the first-by-(name, kind)
	/// selection.
	async fn find_id(
		&self,
		zone: &str,
		relative_name: &str,
		kind: &str,
		value: Option<&str>,
	) -> Result<Option<u64>, ProviderError> {
		let records = self.list_page(zone).await?;
		Ok(records
			.into_iter()
			.find(|r| {
				r.name == relative_name
					&& r.kind.eq_ignore_ascii_case(kind)
					&& match value {
						Some(v) => same_txt_purpose(&r.content, v),
						None => true,
					}
			})
			.map(|r| r.id))
	}

	/// Every record id that would match a single-record lookup
	/// (`find_id`); used by the TXT upsert path to collapse
	/// duplicates of the same purpose.
	async fn find_ids(
		&self,
		zone: &str,
		relative_name: &str,
		kind: &str,
		value: Option<&str>,
	) -> Result<impl Iterator<Item = u64>, ProviderError> {
		let records = self.list_page(zone).await?;
		Ok(records
			.into_iter()
			.filter(move |r| {
				r.name == relative_name
					&& r.kind.eq_ignore_ascii_case(kind)
					&& match value {
						Some(v) => same_txt_purpose(&r.content, v),
						None => true,
					}
			})
			.map(|r| r.id))
	}

	async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		let records = self.list_page(zone).await?;
		let zone_label = self.secret.zone();
		Ok(records
			.iter()
			.filter_map(|r| read::record_of(zone_label, r))
			.collect())
	}
}

impl DnsProvider for DnsimpleProvider {
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let zone = zone.to_string();
		Box::pin(crate::dns::providers::within(async move {
			self.upsert_inner(&zone, record).await
		}))
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let zone = zone.to_string();
		Box::pin(crate::dns::providers::within(async move {
			self.delete_inner(&zone, record).await
		}))
	}
	fn delete_exact(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let zone = zone.to_string();
		Box::pin(crate::dns::providers::within(async move {
			self.delete_exact_inner(&zone, record).await
		}))
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone = zone.to_string();
		let zone_name = zone.to_string();
		Box::pin(crate::dns::providers::listing(zone_name, async move {
			self.list_inner(&zone).await
		}))
	}
	fn publish_snapshot<'a>(&'a self, zone: &'a str) -> SnapshotOp<'a> {
		Box::pin(crate::dns::providers::within(self.snapshot_inner(zone)))
	}
	fn apply_guarded<'a>(&'a self, zone: &'a str, change: Change) -> ReceiptOp<'a> {
		Box::pin(crate::dns::providers::guarded::apply(self, zone, change))
	}
}

/// Decode a JSON body, mapping a 401/403 to an auth error.
async fn decode<T: serde::de::DeserializeOwned>(
	response: reqwest::Response,
) -> Result<T, ProviderError> {
	let status = response.status();
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return Err(ProviderError::Auth);
	}
	let text = crate::dns::providers::read_body(response).await?;
	serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))
}

/// Confirm a write succeeded (2xx), mapping auth failures distinctly.
fn check(response: reqwest::Response) -> Result<(), ProviderError> {
	let status = response.status();
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return Err(ProviderError::Auth);
	}
	if status.is_success() {
		Ok(())
	} else {
		Err(ProviderError::Remote(format!("HTTP {status}")))
	}
}

mod delete;
mod guarded;
mod read;
mod upsert;

mod exact;

#[cfg(test)]
mod tests;
