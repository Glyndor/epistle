//! A DigitalOcean DNS provider implementing [`DnsProvider`]. It authenticates
//! with a zone-scoped personal access token and uses the v2 REST API, where
//! each record carries a server-assigned integer `id`; upsert is read-then-
//! POST-or-PUT against `/v2/domains/{zone}/records/{id}`. MX/SRV need priority
//! fields the API exposes but the rest of epistle does not emit yet, so they
//! return [`ProviderError::Unsupported`].

use std::pin::Pin;

use serde::Deserialize;

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, parse_srv};

/// DigitalOcean's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://api.digitalocean.com";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A DigitalOcean-backed DNS provider.
pub struct DigitaloceanProvider {
	client: reqwest::Client,
	secret: ScopedSecret,
	base: String,
}

#[derive(Deserialize)]
struct ListResponse {
	domain_records: Vec<DomainRecord>,
	#[serde(default)]
	links: Links,
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
}

#[derive(Deserialize)]
struct Envelope {
	domain_record: DomainRecord,
}

impl DigitaloceanProvider {
	/// Build a provider for the token's zone.
	pub fn new(secret: ScopedSecret) -> Self {
		DigitaloceanProvider {
			client: reqwest::Client::new(),
			secret,
			base: DEFAULT_BASE.to_string(),
		}
	}

	/// Point the provider at an alternate API base (tests).
	pub fn with_base(mut self, base: impl Into<String>) -> Self {
		self.base = base.into();
		self
	}

	/// The DigitalOcean type token for a kind we can publish; SRV uses
	/// dedicated `priority`/`weight`/`port`/`data` fields, MX needs the
	/// priority split out (epistle still packs it into the value).
	fn api_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A
			| RecordKind::Aaaa
			| RecordKind::Txt
			| RecordKind::Cname
			| RecordKind::Tlsa
			| RecordKind::Srv
			| RecordKind::Caa => Ok(kind.as_str()),
			RecordKind::Mx => Err(ProviderError::Unsupported),
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

	/// `GET /v2/domains/{zone}/records?per_page=200&name=&type=` — returns the
	/// matching records. DigitalOcean paginates via `links.pages.next`; we
	/// follow it until exhausted so a zone with hundreds of records is not
	/// silently truncated.
	async fn find_records(
		&self,
		zone: &str,
		kind: &str,
		name: &str,
	) -> Result<Vec<DomainRecord>, ProviderError> {
		let mut url = format!(
			"{}/v2/domains/{}/records?per_page=200&type={kind}&name={}",
			self.base, zone, name
		);
		let mut out = Vec::new();
		loop {
			let response = self
				.client
				.get(&url)
				.bearer_auth(self.secret.token())
				.send()
				.await
				.map_err(|e| ProviderError::Remote(e.to_string()))?;
			let status = response.status();
			if status == reqwest::StatusCode::UNAUTHORIZED
				|| status == reqwest::StatusCode::FORBIDDEN
			{
				return Err(ProviderError::Auth);
			}
			let page: ListResponse = decode(response).await?;
			out.extend(page.domain_records);
			match page.links.pages.next {
				Some(next) if !next.is_empty() => url = next,
				_ => break,
			}
		}
		Ok(out)
	}

	/// `GET /v2/domains/{zone}/records?per_page=200` — every record (for
	/// [`DnsProvider::list`]).
	async fn list_all(&self, zone: &str) -> Result<Vec<DomainRecord>, ProviderError> {
		let mut url = format!("{}/v2/domains/{}/records?per_page=200", self.base, zone);
		let mut out = Vec::new();
		loop {
			let response = self
				.client
				.get(&url)
				.bearer_auth(self.secret.token())
				.send()
				.await
				.map_err(|e| ProviderError::Remote(e.to_string()))?;
			let status = response.status();
			if status == reqwest::StatusCode::UNAUTHORIZED
				|| status == reqwest::StatusCode::FORBIDDEN
			{
				return Err(ProviderError::Auth);
			}
			let page: ListResponse = decode(response).await?;
			out.extend(page.domain_records);
			match page.links.pages.next {
				Some(next) if !next.is_empty() => url = next,
				_ => break,
			}
		}
		Ok(out)
	}

	/// `POST /v2/domains/{zone}/records` — create a record; returns the
	/// server-assigned id.
	async fn create(&self, zone: &str, body: String) -> Result<u64, ProviderError> {
		let url = format!("{}/v2/domains/{}/records", self.base, zone);
		let response = self
			.client
			.post(url)
			.bearer_auth(self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
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
		let url = format!("{}/v2/domains/{}/records/{id}", self.base, zone);
		let response = self
			.client
			.put(url)
			.bearer_auth(self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
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
		let url = format!("{}/v2/domains/{}/records/{id}", self.base, zone);
		let response = self
			.client
			.delete(url)
			.bearer_auth(self.secret.token())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
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

	/// Build the create/update JSON body. DigitalOcean stores TXT content
	/// unquoted (the API adds the DNS wire-format quotes server-side), so we
	/// pass `record.value` straight through for TXT and never re-quote. SRV
	/// splits the presentation form into the dedicated fields.
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
		Ok(serde_json::json!({
			"type": kind,
			"name": rel,
			"data": record.value,
			"ttl": record.ttl,
		})
		.to_string())
	}

	async fn upsert_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let rel = self.relative_name(&record.name);
		let existing = self.find_records(zone, kind, &rel).await?;
		let body = Self::record_body(kind, &rel, &record)?;
		match existing
			.into_iter()
			.find(|r| r.kind == kind && r.name == rel)
		{
			Some(prev) => self.update(zone, prev.id, body).await,
			None => {
				self.create(zone, body).await?;
				Ok(())
			}
		}
	}

	async fn delete_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let rel = self.relative_name(&record.name);
		let existing = self.find_records(zone, kind, &rel).await?;
		match existing
			.into_iter()
			.find(|r| r.kind == kind && r.name == rel)
		{
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
				let kind = parse_kind(&r.kind);
				let value = if kind == RecordKind::Srv {
					match (r.priority, r.weight, r.port) {
						(Some(p), Some(w), Some(port)) => {
							format!("{p} {w} {port} {}", r.data.trim_end_matches('.'))
						}
						_ => return None,
					}
				} else {
					r.data
				};
				Some(DnsRecord {
					name,
					kind,
					value,
					ttl: r.ttl,
				})
			})
			.collect())
	}
}

impl DnsProvider for DigitaloceanProvider {
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let zone = zone.to_string();
		Box::pin(async move { self.upsert_inner(&zone, record).await })
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let zone = zone.to_string();
		Box::pin(async move { self.delete_inner(&zone, record).await })
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone = zone.to_string();
		Box::pin(async move { self.list_inner(&zone).await })
	}
}

/// Map a DigitalOcean type token back to a [`RecordKind`], defaulting to TXT.
fn parse_kind(kind: &str) -> RecordKind {
	match kind {
		"A" => RecordKind::A,
		"AAAA" => RecordKind::Aaaa,
		"CAA" => RecordKind::Caa,
		"CNAME" => RecordKind::Cname,
		"MX" => RecordKind::Mx,
		"SRV" => RecordKind::Srv,
		"TLSA" => RecordKind::Tlsa,
		_ => RecordKind::Txt,
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
	let text = response
		.text()
		.await
		.map_err(|e| ProviderError::Remote(e.to_string()))?;
	serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))
}

#[cfg(test)]
#[path = "digitalocean_tests.rs"]
mod tests;
