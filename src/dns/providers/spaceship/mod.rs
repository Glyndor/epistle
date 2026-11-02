//! A Spaceship (spaceship.dev) DNS provider implementing [`DnsProvider`].
//! Authentication is two header values — `X-API-Key` and `X-API-Secret` — set up
//! at <https://www.spaceship.com/application/api-manager/>. The API at
//! <https://spaceship.dev/api/v1> has no in-place update: `upsert` is
//! read-then-delete-then-add (delete the existing `(type, name)` tuple, then
//! `PUT` the new item). A/AAAA/TXT/CNAME/TLSA are supported; MX and SRV carry
//! priority/weight/port fields the rest of epistle does not emit yet.

use std::pin::Pin;

use serde::Deserialize;

use crate::dns::providers::{
	LIST_MAX_PAGES, LIST_MAX_RECORDS, inconsistent_pages, listing_too_long, missing_page_count,
};
use crate::net::HttpsUrl;

use crate::dns::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, parse_srv, same_txt_purpose,
};
use crate::dns::providers::transport;
use crate::dns::txt::{TxtForm, txt_decode, txt_encode};

/// How Spaceship takes a TXT `value` and lists it back; see `wire_value`.
const TXT_FORM: TxtForm = TxtForm::Logical;

/// Spaceship's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://spaceship.dev/api/v1";

/// Maximum records per page the API allows.
const PAGE_MAX: i64 = 500;

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A Spaceship-backed DNS provider for one zone.
pub struct SpaceshipProvider {
	client: reqwest::Client,
	api_key: String,
	api_secret: String,
	zone: String,
	base: HttpsUrl,
}

#[derive(Deserialize)]
struct ListResponse {
	items: Vec<serde_json::Value>,
	/// Absent when the answer does not say how many records there are.
	#[serde(default)]
	total: Option<i64>,
}

impl SpaceshipProvider {
	/// Build a provider for `zone` with the two credential halves.
	pub fn new(api_key: String, api_secret: String, zone: String) -> Self {
		SpaceshipProvider {
			client: crate::dns::providers::http_client(),
			api_key,
			api_secret,
			zone,
			base: HttpsUrl::from_static(DEFAULT_BASE),
		}
	}

	/// Point the provider at an alternate API base (tests).
	pub fn with_base(mut self, base: HttpsUrl) -> Self {
		self.base = base;
		self
	}

	/// The Spaceship type token for a kind we can publish; SRV splits the
	/// presentation form into `priority`/`weight`/`port`/`target` fields, MX
	/// needs the priority split out (epistle still packs it into the value).
	fn api_kind(kind: &RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A => Ok("A"),
			RecordKind::Aaaa => Ok("AAAA"),
			RecordKind::Txt => Ok("TXT"),
			RecordKind::Cname => Ok("CNAME"),
			RecordKind::Mx => Ok("MX"),
			RecordKind::Srv => Ok("SRV"),
			RecordKind::Tlsa => Ok("TLSA"),
			RecordKind::Caa => Ok("CAA"),
			RecordKind::Ns | RecordKind::Https | RecordKind::Svcb | RecordKind::Other(_) => {
				Err(ProviderError::Unsupported)
			}
		}
	}

	/// The Spaceship-relative name: `name` minus the zone suffix, or `@` for
	/// the apex (the literal Spaceship uses for the zone itself).
	fn relative_name(&self, name: &str) -> String {
		let name = name.trim_end_matches('.');
		let zone = self.zone.trim_end_matches('.');
		if name.eq_ignore_ascii_case(zone) {
			return "@".to_string();
		}
		name.strip_suffix(&format!(".{zone}"))
			.unwrap_or(name)
			.to_string()
	}

	/// Reject a record outside the configured zone before any network call.
	fn authorize(&self, record: &DnsRecord) -> Result<(), ProviderError> {
		let name = record.name.to_ascii_lowercase();
		let zone = self.zone.to_ascii_lowercase();
		if name == zone || name.ends_with(&format!(".{zone}")) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	/// The JSON key that holds the record's value for `kind`. Spaceship
	/// discriminates by `type` and uses a different value field per kind:
	/// `value` for TXT, `address` for A/AAAA, `cname` for CNAME,
	/// `associationData` for TLSA, `target` for SRV (priority/weight/port
	/// travel in their own dedicated fields).
	fn value_field(kind: &RecordKind) -> &'static str {
		match kind {
			RecordKind::Txt => "value",
			RecordKind::A | RecordKind::Aaaa => "address",
			RecordKind::Cname => "cname",
			RecordKind::Tlsa => "associationData",
			RecordKind::Srv => "target",
			RecordKind::Caa => "value",
			RecordKind::Mx => "exchange",
			// Spaceship's API does not model NS / HTTPS / SVCB; an
			// `Other` type is something we cannot translate to one
			// of Spaceship's value fields. The caller must never
			// reach this point: `api_kind` rejects the kinds.
			RecordKind::Ns | RecordKind::Https | RecordKind::Svcb | RecordKind::Other(_) => "",
		}
	}

	/// `{base}/dns/records/{zone}`, with the zone escaped as one path segment.
	fn records_url(&self) -> Result<HttpsUrl, ProviderError> {
		Ok(self
			.base
			.with_segments(["dns", "records", self.zone.as_str()])?)
	}

	/// Add a fresh request with the Spaceship auth headers attached.
	fn request(&self, method: reqwest::Method, url: HttpsUrl) -> reqwest::RequestBuilder {
		self.client
			.request(method, url.into_url())
			.header("X-API-Key", &self.api_key)
			.header("X-API-Secret", &self.api_secret)
			.header(reqwest::header::CONTENT_TYPE, "application/json")
	}

	/// `GET /dns/records/{zone}?take=500&skip=N` — list records. Spaceship
	/// caps `take` at 500; we page through `skip` until we have fetched
	/// `total` records so a large zone is not silently truncated.
	async fn list_all(&self) -> Result<Vec<serde_json::Value>, ProviderError> {
		let url = self.records_url()?;
		let mut out = Vec::new();
		let mut skip: i64 = 0;
		let mut pages = 0;
		let mut expected: Option<i64> = None;
		loop {
			let page_url = url
				.with_query("take", &PAGE_MAX.to_string())
				.with_query("skip", &skip.to_string());
			let response = self
				.request(reqwest::Method::GET, page_url)
				.send()
				.await
				.map_err(transport)?;
			let status = response.status();
			if status == reqwest::StatusCode::UNAUTHORIZED
				|| status == reqwest::StatusCode::FORBIDDEN
			{
				return Err(ProviderError::Auth);
			}
			let page: ListResponse =
				crate::dns::providers::read_body(response)
					.await
					.and_then(|text| {
						serde_json::from_str(&text)
							.map_err(|e| ProviderError::Remote(e.to_string()))
					})?;
			let count = page.items.len() as i64;
			out.extend(page.items);
			if out.len() > LIST_MAX_RECORDS {
				return Err(listing_too_long(&self.zone));
			}
			match page.total {
				Some(total) => {
					// The total is a promise: what was read must add up to
					// it, page by page, and it must not move.
					if total < 0
						|| expected.is_some_and(|seen| seen != total)
						|| out.len() as i64 > total
					{
						return Err(inconsistent_pages(&self.zone));
					}
					expected = Some(total);
					if out.len() as i64 == total {
						break;
					}
					if count == 0 {
						return Err(inconsistent_pages(&self.zone));
					}
				}
				// No total: a short page is the last one, a full page
				// may not be, and a zone is never read as finished on
				// that guess.
				None if count < PAGE_MAX => break,
				None => return Err(missing_page_count(&self.zone)),
			}
			pages += 1;
			if pages >= LIST_MAX_PAGES {
				return Err(listing_too_long(&self.zone));
			}
			skip += count;
		}
		Ok(out)
	}

	/// The value field for `record`. The API reference gives a TXT
	/// `value` as one string of up to 65535 characters, with an unquoted
	/// example and nothing on quoting or escaping, and matches a TXT on
	/// delete by its exact, case-sensitive value
	/// (<https://docs.spaceship.dev/>, TxtResourceRecord and
	/// DELETE /v1/dns/records/{domain}, read 2026-10-12). So a TXT goes as
	/// its logical value, the same bytes on the save and on every delete
	/// that has to find it again.
	fn wire_value(record: &DnsRecord) -> String {
		if record.kind == RecordKind::Txt {
			txt_encode(&record.value, TXT_FORM)
		} else {
			record.value.clone()
		}
	}

	/// Pick the `value`-shaped field out of a list item: Spaceship returns
	/// each record type with its own value key.
	fn extract_value(item: &serde_json::Value) -> Option<String> {
		for key in ["value", "address", "cname", "exchange", "associationData"] {
			if let Some(v) = item.get(key).and_then(|v| v.as_str()) {
				return Some(v.to_string());
			}
		}
		None
	}

	/// The value of a listed record of a kind epistle does not publish.
	/// Spaceship names the field after the type: `nameserver` for an NS,
	/// `svcPriority`, `targetName` and `svcParams` for an HTTPS or SVCB
	/// (<https://docs.spaceship.dev/>, the NS and HTTPS resource record
	/// schemas, read 2026-10-16), `aliasName` and `pointer` for the types
	/// that follow the same pattern. An item with none of them lists with an
	/// empty value.
	fn foreign_value(kind: &RecordKind, item: &serde_json::Value) -> String {
		let text = |key: &str| item.get(key).and_then(|v| v.as_str());
		if matches!(kind, RecordKind::Https | RecordKind::Svcb) {
			let priority = item
				.get("svcPriority")
				.and_then(|v| v.as_u64())
				.unwrap_or(0);
			return format!(
				"{priority} {} {}",
				text("targetName").unwrap_or("."),
				text("svcParams").unwrap_or("")
			)
			.trim_end()
			.to_string();
		}
		for key in ["nameserver", "aliasName", "pointer"] {
			if let Some(v) = text(key) {
				return v.to_string();
			}
		}
		Self::extract_value(item).unwrap_or_default()
	}

	async fn list_inner(&self) -> Result<Vec<DnsRecord>, ProviderError> {
		let items = self.list_all().await?;
		let zone = self.zone.trim_end_matches('.').to_string();
		Ok(items
			.into_iter()
			.filter_map(|item| {
				let kind = item.get("type").and_then(|v| v.as_str())?;
				let name = item.get("name").and_then(|v| v.as_str())?;
				let ttl = item.get("ttl").and_then(|v| v.as_u64()).unwrap_or(3600) as u32;
				let fqdn = if name == "@" {
					zone.clone()
				} else {
					format!("{name}.{zone}")
				};
				let kind = RecordKind::from_token(kind);
				let value = match &kind {
					RecordKind::Srv => {
						let priority =
							item.get("priority").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
						let weight =
							item.get("weight").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
						let port = item.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
						let target = item.get("target").and_then(|v| v.as_str())?;
						format!(
							"{priority} {weight} {port} {}",
							target.trim_end_matches('.')
						)
					}
					RecordKind::Mx => {
						let priority = item
							.get("preference")
							.or_else(|| item.get("priority"))
							.and_then(|v| v.as_u64())
							.unwrap_or(0) as u16;
						let target = item
							.get("exchange")
							.and_then(|v| v.as_str())
							.or_else(|| item.get("value").and_then(|v| v.as_str()))?;
						format!("{priority} {}", target.trim_end_matches('.'))
					}
					RecordKind::Txt => txt_decode(&Self::extract_value(&item)?, TXT_FORM),
					// A CAA is three fields (`flag`, `tag`, `value`): the
					// presentation form is `0 issue "ca.example"`.
					RecordKind::Caa if item.get("tag").is_some() => {
						let flag = item.get("flag").and_then(|v| v.as_u64()).unwrap_or(0);
						let tag = item.get("tag").and_then(|v| v.as_str()).unwrap_or("");
						let value = item.get("value").and_then(|v| v.as_str()).unwrap_or("");
						format!("{flag} {tag} \"{value}\"")
					}
					// A kind epistle does not publish is listed even when its
					// value cannot be read: a delegation's NS that vanished
					// from the listing would let the lockdown write under it.
					RecordKind::Ns
					| RecordKind::Https
					| RecordKind::Svcb
					| RecordKind::Other(_) => Self::foreign_value(&kind, &item),
					_ => Self::extract_value(&item)?,
				};
				Some(DnsRecord {
					name: fqdn,
					kind,
					value,
					ttl,
					proxied: None,
				})
			})
			.collect())
	}
}

impl DnsProvider for SpaceshipProvider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(crate::dns::providers::within(async move {
			self.upsert_inner(record).await
		}))
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(crate::dns::providers::within(async move {
			self.delete_inner(record).await
		}))
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone_name = zone.to_string();
		Box::pin(crate::dns::providers::listing(zone_name, async move {
			self.list_inner().await
		}))
	}
}

/// Map a write response to success or a typed error.
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

mod upsert;
mod write;

#[cfg(test)]
mod tests;
