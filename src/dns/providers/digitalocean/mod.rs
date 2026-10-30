//! A DigitalOcean DNS provider implementing [`DnsProvider`]. It authenticates
//! with a zone-scoped personal access token and uses the v2 REST API, where
//! each record carries a server-assigned integer `id`; upsert is read-then-
//! POST-or-PUT against `/v2/domains/{zone}/records/{id}`. MX/SRV need priority
//! fields the API exposes but the rest of epistle does not emit yet, so they
//! return [`ProviderError::Unsupported`].

use std::pin::Pin;

use serde::Deserialize;

use crate::dns::providers::{
	LIST_MAX_PAGES, LIST_MAX_RECORDS, inconsistent_pages, listing_too_long,
};
use crate::net::HttpsUrl;

use crate::dns::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, parse_srv, same_txt_purpose,
};
use crate::dns::providers::transport;
use crate::dns::txt::{TxtForm, same_txt_value, txt_decode, txt_encode};

/// How DigitalOcean takes a TXT `data` and lists it back; see `record_body`.
const TXT_FORM: TxtForm = TxtForm::Logical;

/// DigitalOcean's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://api.digitalocean.com";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A DigitalOcean-backed DNS provider.
pub struct DigitaloceanProvider {
	client: reqwest::Client,
	secret: ScopedSecret,
	base: HttpsUrl,
}

#[derive(Deserialize)]
struct ListResponse {
	domain_records: Vec<DomainRecord>,
	#[serde(default)]
	links: Links,
	#[serde(default)]
	meta: Meta,
}

#[derive(Deserialize, Default)]
struct Meta {
	/// How many records the whole listing holds.
	#[serde(default)]
	total: Option<usize>,
}

#[derive(Deserialize, Default)]
struct Links {
	#[serde(default)]
	pages: Pages,
}

#[derive(Deserialize, Default)]
struct Pages {
	#[serde(default)]
	next: Option<String>,
}

#[derive(Deserialize)]
struct DomainRecord {
	id: u64,
	#[serde(rename = "type")]
	kind: String,
	name: String,
	data: String,
	#[serde(default)]
	ttl: u32,
	#[serde(default)]
	priority: Option<u16>,
	#[serde(default)]
	weight: Option<u16>,
	#[serde(default)]
	port: Option<u16>,
	/// The flags and the tag of a CAA; its `data` is the issuer alone.
	#[serde(default)]
	flags: Option<u8>,
	#[serde(default)]
	tag: Option<String>,
}

#[derive(Deserialize)]
struct Envelope {
	domain_record: DomainRecord,
}

impl DigitaloceanProvider {
	/// Build a provider for the token's zone.
	pub fn new(secret: ScopedSecret) -> Self {
		DigitaloceanProvider {
			client: crate::dns::providers::http_client(),
			secret,
			base: HttpsUrl::from_static(DEFAULT_BASE),
		}
	}

	/// Point the provider at an alternate API base (tests).
	pub fn with_base(mut self, base: HttpsUrl) -> Self {
		self.base = base;
		self
	}

	/// The DigitalOcean type token for a kind we can publish; SRV uses
	/// dedicated `priority`/`weight`/`port`/`data` fields, MX needs the
	/// priority split out (epistle still packs it into the value).
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

	/// The relative name DigitalOcean's API wants: `name` minus the zone suffix,
	/// or `"@"` for the apex. DigitalOcean stores TXT and most record types with
	/// the host label relative to the zone; the apex is the literal `"@"`.
	fn relative_name(&self, name: &str) -> String {
		let name = name.trim_end_matches('.');
		let zone = self.secret.zone();
		if name.eq_ignore_ascii_case(zone) {
			return "@".to_string();
		}
		name.strip_suffix(&format!(".{zone}"))
			.unwrap_or(name)
			.to_string()
	}

	/// Reject a record outside the token's zone before any network call.
	fn authorize(&self, record: &DnsRecord) -> Result<(), ProviderError> {
		if self.secret.authorizes(&record.name) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	/// `{base}/v2/domains/{zone}/records[/{id}]`, with the zone escaped as one
	/// path segment.
	fn records_url(&self, zone: &str, id: Option<u64>) -> Result<HttpsUrl, ProviderError> {
		let mut segments = vec!["v2".to_string(), "domains".to_string(), zone.to_string()];
		segments.push("records".to_string());
		segments.extend(id.map(|id| id.to_string()));
		Ok(self.base.with_segments(segments)?)
	}

	/// `GET /v2/domains/{zone}/records?per_page=200&name=&type=` — returns the
	/// matching records, following the pagination links.
	async fn find_records(
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
	async fn list_all(&self, zone: &str) -> Result<Vec<DomainRecord>, ProviderError> {
		let url = self.records_url(zone, None)?.with_query("per_page", "200");
		self.fetch_pages(url, zone).await
	}

	/// GET `first` and every page DigitalOcean links to through
	/// `links.pages.next` until exhausted, so a zone with hundreds of records
	/// is not silently truncated. The link comes from the response body, so it
	/// is resolved against the configured base and refused when it points at a
	/// different origin: the bearer token must not follow it anywhere else.
	async fn fetch_pages(
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

	/// `POST /v2/domains/{zone}/records` — create a record; returns the
	/// server-assigned id.
	async fn create(&self, zone: &str, body: String) -> Result<u64, ProviderError> {
		let url = self.records_url(zone, None)?;
		let response = self
			.client
			.post(url.into_url())
			.bearer_auth(self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(ProviderError::Auth);
		}
		if !status.is_success() {
			return Err(ProviderError::Remote(format!("HTTP {status}")));
		}
		let envelope: Envelope = decode(response).await?;
		Ok(envelope.domain_record.id)
	}

	/// `PUT /v2/domains/{zone}/records/{id}` — replace a record's data/ttl.
	async fn update(&self, zone: &str, id: u64, body: String) -> Result<(), ProviderError> {
		let url = self.records_url(zone, Some(id))?;
		let response = self
			.client
			.put(url.into_url())
			.bearer_auth(self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(transport)?;
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

	/// `DELETE /v2/domains/{zone}/records/{id}` — DigitalOcean replies 204.
	async fn delete_record(&self, zone: &str, id: u64) -> Result<(), ProviderError> {
		let url = self.records_url(zone, Some(id))?;
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
		if status.is_success() {
			Ok(())
		} else {
			Err(ProviderError::Remote(format!("HTTP {status}")))
		}
	}

	/// Build the create/update JSON body. The API reference describes
	/// `data` only as "Variable data depending on record type" and the
	/// product guide shows a TXT value unquoted
	/// (<https://docs.digitalocean.com/reference/api/reference/domain-records/>
	/// and <https://docs.digitalocean.com/products/networking/dns/how-to/manage-records/>,
	/// read 2026-10-12); quoting, splitting past 255 octets and escaping are
	/// not documented. A TXT goes as its logical value, which other clients
	/// send too (lego, dnscontrol) and which DigitalOcean lists back as
	/// written. SRV splits the presentation form into the dedicated fields.
	fn record_body(kind: &str, rel: &str, record: &DnsRecord) -> Result<String, ProviderError> {
		if record.kind == RecordKind::Srv {
			let (priority, weight, port, target) = parse_srv(&record.value)
				.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {}", record.value)))?;
			return Ok(serde_json::json!({
				"type": kind,
				"name": rel,
				"data": target,
				"priority": priority,
				"weight": weight,
				"port": port,
				"ttl": record.ttl,
			})
			.to_string());
		}
		if record.kind == RecordKind::Caa {
			let mut parts = record.value.splitn(3, ' ');
			let flags: u8 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?;
			let tag = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?
				.to_string();
			let value = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?
				.trim_matches('"')
				.to_string();
			return Ok(serde_json::json!({
				"type": kind,
				"name": rel,
				"data": value,
				"priority": flags,
				"tag": tag,
				"ttl": record.ttl,
			})
			.to_string());
		}
		if record.kind == RecordKind::Mx {
			let mut parts = record.value.split_whitespace();
			let priority: u16 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = crate::dns::provider::mx_target_for_api(target).to_string();
			return Ok(serde_json::json!({
				"type": kind,
				"name": rel,
				"data": target,
				"priority": priority,
				"ttl": record.ttl,
			})
			.to_string());
		}
		let data = if record.kind == RecordKind::Txt {
			txt_encode(&record.value, TXT_FORM)
		} else {
			record.value.clone()
		};
		Ok(serde_json::json!({
			"type": kind,
			"name": rel,
			"data": data,
			"ttl": record.ttl,
		})
		.to_string())
	}

	async fn upsert_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let rel = self.relative_name(&record.name);
		let existing = self.find_records(zone, kind, &rel).await?;
		let body = Self::record_body(kind, &rel, &record)?;
		// The TXT matching rule from `src/dns/provider/mod.rs` is the
		// contract: an upsert replaces the TXT with the same
		// purpose (version tag) at that name and leaves every
		// other TXT at the name alone. Two records of the same
		// purpose are a configuration mistake (SPF returns
		// permerror, DMARC is ignored): the upsert collapses them
		// by updating the first match and deleting every other.
		// Non-TXT kinds take the whole (type, name) set, so
		// duplicates do not arise.
		if record.kind == RecordKind::Txt {
			let mut matching = existing
				.into_iter()
				.filter(|r| same_txt_purpose(&r.data, &record.value));
			match matching.next() {
				Some(primary) => {
					let primary_id = primary.id;
					self.update(zone, primary_id, body).await?;
					for dup in matching {
						self.delete_record(zone, dup.id).await?;
					}
					Ok(())
				}
				None => {
					self.create(zone, body).await?;
					Ok(())
				}
			}
		} else {
			let mut found = existing.into_iter();
			match found.next() {
				Some(prev) => {
					self.update(zone, prev.id, body).await?;
					for stale in found {
						self.delete_record(zone, stale.id).await?;
					}
					Ok(())
				}
				None => {
					self.create(zone, body).await?;
					Ok(())
				}
			}
		}
	}

	async fn delete_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let rel = self.relative_name(&record.name);
		let existing = self.find_records(zone, kind, &rel).await?;
		// The TXT matching rule from `src/dns/provider/mod.rs` is the
		// contract: a value-bearing delete drops only the record
		// whose data matches the value (a sibling ACME challenge at
		// the same owner survives), an empty-value delete drops
		// every record at the owner (the DKIM rotator's retire
		// path). Other record kinds fall through to the
		// first-by-(type, name) selection, which is the existing
		// whole-set semantics.
		if record.kind == RecordKind::Txt && record.value.is_empty() {
			for prev in existing {
				self.delete_record(zone, prev.id).await?;
			}
			return Ok(());
		}
		match existing.into_iter().find(|r| {
			r.kind == kind
				&& r.name == rel
				&& (record.kind != RecordKind::Txt || same_txt_value(&r.data, &record.value))
		}) {
			Some(prev) => self.delete_record(zone, prev.id).await,
			None => Ok(()), // already absent: idempotent.
		}
	}

	async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		let records = self.list_all(zone).await?;
		Ok(records
			.into_iter()
			.filter_map(|r| {
				let name = if r.name == "@" {
					zone.to_string()
				} else {
					format!("{}.{}", r.name, zone)
				};
				let kind = RecordKind::from_token(&r.kind);
				let value = if kind == RecordKind::Srv {
					match (r.priority, r.weight, r.port) {
						(Some(p), Some(w), Some(port)) => {
							format!("{p} {w} {port} {}", r.data.trim_end_matches('.'))
						}
						_ => return None,
					}
				} else if kind == RecordKind::Mx {
					match r.priority {
						Some(p) => format!("{p} {}", r.data.trim_end_matches('.')),
						_ => return None,
					}
				} else if kind == RecordKind::Txt {
					txt_decode(&r.data, TXT_FORM)
				} else if kind == RecordKind::Caa && r.tag.is_some() {
					format!(
						"{} {} \"{}\"",
						r.flags.unwrap_or(0),
						r.tag.as_deref().unwrap_or_default(),
						r.data
					)
				} else {
					r.data
				};
				Some(DnsRecord {
					name,
					kind,
					value,
					ttl: r.ttl,
					proxied: None,
				})
			})
			.collect())
	}
}

impl DnsProvider for DigitaloceanProvider {
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
	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone = zone.to_string();
		let zone_name = zone.to_string();
		Box::pin(crate::dns::providers::listing(zone_name, async move {
			self.list_inner(&zone).await
		}))
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

#[cfg(test)]
mod tests;
