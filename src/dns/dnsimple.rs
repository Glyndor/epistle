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

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret};

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
	base: String,
}

#[derive(Deserialize)]
struct ListResponse {
	data: Vec<Record>,
	pagination: Pagination,
}

#[derive(Deserialize)]
struct Pagination {
	#[serde(default)]
	total_pages: u32,
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
}

impl DnsimpleProvider {
	/// Build a provider for the token's zone in `account_id`. Without
	/// `account_id` there is no URL to call, so the caller is expected to gate
	/// that case at the config layer.
	pub fn new(secret: ScopedSecret, account_id: impl Into<String>) -> Self {
		DnsimpleProvider {
			client: reqwest::Client::new(),
			secret,
			account_id: account_id.into(),
			base: DEFAULT_BASE.to_string(),
		}
	}

	/// Point the provider at an alternate API root (tests). The account id is
	/// still appended per request.
	pub fn with_base(mut self, base: impl Into<String>) -> Self {
		self.base = base.into();
		self
	}

	/// Build a URL under `/v2/{account_id}` for `path` (which must start with
	/// `/`).
	fn url(&self, path: &str) -> String {
		format!("{}/{}{}", self.base, self.account_id, path)
	}

	/// The DNSimple record type token for a kind we can publish. TXT/A/AAAA/CNAME
	/// go through the plain `content` field; MX/SRV (which need priority/weight)
	/// and TLSA (no structured field) are not yet supported.
	fn api_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A | RecordKind::Aaaa | RecordKind::Txt | RecordKind::Cname => {
				Ok(kind.as_str())
			}
			RecordKind::Mx | RecordKind::Srv | RecordKind::Tlsa => Err(ProviderError::Unsupported),
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
		for page in 1.. {
			let url = format!(
				"{}/zones/{}/records?per_page={PER_PAGE}&page={page}",
				self.url(""),
				zone,
			);
			let response = self
				.client
				.get(&url)
				.bearer_auth(self.secret.token())
				.send()
				.await
				.map_err(|e| ProviderError::Remote(e.to_string()))?;
			let mut batch: ListResponse = decode(response).await?;
			all.append(&mut batch.data);
			if page >= batch.pagination.total_pages {
				break;
			}
		}
		Ok(all)
	}

	/// Find the id of an existing record with matching relative name and kind,
	/// if any.
	async fn find_id(
		&self,
		zone: &str,
		relative_name: &str,
		kind: &str,
	) -> Result<Option<u64>, ProviderError> {
		let records = self.list_page(zone).await?;
		Ok(records
			.into_iter()
			.find(|r| r.name == relative_name && r.kind.eq_ignore_ascii_case(kind))
			.map(|r| r.id))
	}

	async fn upsert_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let relative = self.relative_name(&record.name);
		let body = serde_json::json!({
			"name": relative,
			"type": kind,
			"content": record.value,
			"ttl": record.ttl,
		})
		.to_string();
		let url = self.url(&format!("/zones/{}/records", zone));
		let existing = self.find_id(zone, &relative, kind).await?;
		let request = if let Some(id) = existing {
			self.client.patch(format!("{url}/{id}"))
		} else {
			self.client.post(&url)
		};
		let response = request
			.bearer_auth(self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		check(response)
	}

	async fn delete_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let relative = self.relative_name(&record.name);
		let Some(id) = self.find_id(zone, &relative, kind).await? else {
			return Ok(()); // already absent: idempotent.
		};
		let url = self.url(&format!("/zones/{}/records/{id}", zone));
		let response = self
			.client
			.delete(&url)
			.bearer_auth(self.secret.token())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(ProviderError::Auth);
		}
		// DNSimple returns 204 on a real delete; we accept any 2xx so a future
		// 200-with-body shape still parses as success.
		if status.is_success() {
			Ok(())
		} else {
			Err(ProviderError::Remote(format!("HTTP {status}")))
		}
	}

	async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		let zone_owned = zone.to_string();
		let records = self.list_page(&zone_owned).await?;
		let zone_label = self.secret.zone().to_string();
		Ok(records
			.into_iter()
			.map(|r| {
				let name = if r.name.is_empty() {
					zone_label.clone()
				} else {
					format!("{}.{}", r.name, zone_label)
				};
				DnsRecord {
					name,
					kind: parse_kind(&r.kind),
					value: r.content,
					ttl: r.ttl,
				}
			})
			.collect())
	}
}

impl DnsProvider for DnsimpleProvider {
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

/// Map a DNSimple type token back to a [`RecordKind`], defaulting to TXT.
fn parse_kind(kind: &str) -> RecordKind {
	match kind {
		"A" => RecordKind::A,
		"AAAA" => RecordKind::Aaaa,
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

#[cfg(test)]
#[path = "dnsimple_tests.rs"]
mod tests;
