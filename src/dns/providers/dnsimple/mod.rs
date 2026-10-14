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

use crate::net::HttpsUrl;

use crate::dns::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, parse_srv, same_txt_purpose,
};
use crate::dns::providers::transport;
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
	#[serde(default)]
	priority: Option<u16>,
	#[serde(default)]
	weight: Option<u16>,
	#[serde(default)]
	port: Option<u16>,
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
		RecordKind::Ns
		| RecordKind::Https
		| RecordKind::Svcb
		| RecordKind::Other(_) => Err(ProviderError::Unsupported),
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
			let mut batch: ListResponse = decode(response).await?;
			all.append(&mut batch.data);
			if page >= batch.pagination.total_pages {
				break;
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

	async fn upsert_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let relative = self.relative_name(&record.name);
		// The TXT matching rule from `src/dns/provider.rs` is the
		// contract: an upsert replaces the TXT with the same
		// purpose (version tag) at that name and leaves every
		// other TXT at the name alone. Two records of the same
		// purpose are a configuration mistake (SPF returns
		// permerror, DMARC is ignored): the upsert collapses them
		// by PATCHing the first match and DELETEing every other.
		// `same_txt_purpose` carries the contract; for non-TXT
		// kinds the matching is just (name, kind) and the first
		// match is fine.
		if record.kind == RecordKind::Txt {
			let lookup = record.value.clone();
			let mut ids = self.find_ids(zone, &relative, kind, Some(&lookup)).await?;
			match ids.next() {
				Some(primary) => {
					self.write_record(zone, primary, record).await?;
					for dup in ids {
						self.delete_by_id(self.records_url(zone, Some(dup))?)
							.await?;
					}
					Ok(())
				}
				None => self.create_record(zone, record).await,
			}
		} else {
			match self.find_id(zone, &relative, kind, None).await? {
				Some(id) => self.write_record(zone, id, record).await,
				None => self.create_record(zone, record).await,
			}
		}
	}

	async fn create_record(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		let kind = Self::api_kind(&record.kind)?;
		let relative = self.relative_name(&record.name);
		let body = self.record_body(kind, &relative, &record)?;
		self.write_body(zone, None, body).await
	}

	async fn write_record(
		&self,
		zone: &str,
		id: u64,
		record: DnsRecord,
	) -> Result<(), ProviderError> {
		let kind = Self::api_kind(&record.kind)?;
		let relative = self.relative_name(&record.name);
		let body = self.record_body(kind, &relative, &record)?;
		self.write_body(zone, Some(id), body).await
	}

	async fn write_body(
		&self,
		zone: &str,
		id: Option<u64>,
		body: String,
	) -> Result<(), ProviderError> {
		let url = match id {
			Some(id) => self.records_url(zone, Some(id))?,
			None => self.records_url(zone, None)?,
		};
		let request = if id.is_some() {
			self.client.patch(url.into_url())
		} else {
			self.client.post(url.into_url())
		};
		let response = request
			.bearer_auth(self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		check(response)
	}

	fn record_body(
		&self,
		kind: &str,
		relative: &str,
		record: &DnsRecord,
	) -> Result<String, ProviderError> {
		let body = if record.kind == RecordKind::Srv {
			let (priority, weight, port, target) = parse_srv(&record.value)
				.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {}", record.value)))?;
			serde_json::json!({
				"name": relative,
				"type": kind,
				"content": target,
				"ttl": record.ttl,
				"priority": priority,
				"weight": weight,
				"port": port,
			})
			.to_string()
		} else if record.kind == RecordKind::Caa {
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
			serde_json::json!({
				"name": relative,
				"type": kind,
				"content": value,
				"ttl": record.ttl,
				"flags": flags,
				"caa_tag": tag,
			})
			.to_string()
		} else if record.kind == RecordKind::Mx {
			let mut parts = record.value.split_whitespace();
			let priority: u16 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = crate::dns::provider::mx_target_for_api(target).to_string();
			serde_json::json!({
				"name": relative,
				"type": kind,
				"content": target,
				"ttl": record.ttl,
				"priority": priority,
			})
			.to_string()
		} else {
			// DNSimple serializes an unquoted TXT itself, but content
			// already in double quotes "will store and publish this
			// content verbatim", splitting past 255 is automatic, and
			// pre-split "chunk1" "chunk2" is stored as is
			// (<https://support.dnsimple.com/articles/txt-record-format/>,
			// read 2026-10-12). Sending the presentation form makes the
			// stored content exactly what was sent, the same bytes every
			// time, with the escaping under our control.
			let content = if record.kind == RecordKind::Txt {
				txt_encode(&record.value, TXT_FORM)
			} else {
				record.value.clone()
			};
			serde_json::json!({
				"name": relative,
				"type": kind,
				"content": content,
				"ttl": record.ttl,
			})
			.to_string()
		};
		Ok(body)
	}

	async fn delete_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let relative = self.relative_name(&record.name);
		// The TXT matching rule from `src/dns/provider.rs` is the
		// contract: a value-bearing delete drops only the record
		// whose content matches the value (a sibling ACME challenge
		// at the same owner survives), an empty-value delete drops
		// every record at the owner (the DKIM rotator's retire
		// path). Other record kinds fall through to the
		// first-by-(name, kind) selection, which is the existing
		// whole-set semantics.
		if record.kind == RecordKind::Txt && record.value.is_empty() {
			let pages = self.list_page(zone).await?;
			let to_delete: Vec<u64> = pages
				.into_iter()
				.filter(|r| r.name == relative && r.kind.eq_ignore_ascii_case(kind))
				.map(|r| r.id)
				.collect();
			for id in to_delete {
				let url = self.records_url(zone, Some(id))?;
				self.delete_by_id(url).await?;
			}
			return Ok(());
		}
		let lookup_value = match record.kind {
			RecordKind::Txt => Some(record.value.as_str()),
			_ => None,
		};
		let Some(id) = self.find_id(zone, &relative, kind, lookup_value).await? else {
			return Ok(()); // already absent: idempotent.
		};
		let url = self.records_url(zone, Some(id))?;
		self.delete_by_id(url).await
	}

	async fn delete_by_id(&self, url: HttpsUrl) -> Result<(), ProviderError> {
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
			.filter_map(|r| {
				let name = if r.name.is_empty() {
					zone_label.clone()
				} else {
					format!("{}.{}", r.name, zone_label)
				};
				let kind = parse_kind(&r.kind);
				let value = if kind == RecordKind::Srv {
					match (r.priority, r.weight, r.port) {
						(Some(p), Some(w), Some(port)) => {
							format!("{p} {w} {port} {}", r.content.trim_end_matches('.'))
						}
						_ => return None,
					}
				} else if kind == RecordKind::Txt {
					txt_decode(&r.content, TXT_FORM)
				} else {
					r.content
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
		"CAA" => RecordKind::Caa,
		"CNAME" => RecordKind::Cname,
		"HTTPS" => RecordKind::Https,
		"MX" => RecordKind::Mx,
		"NS" => RecordKind::Ns,
		"SRV" => RecordKind::Srv,
		"SVCB" => RecordKind::Svcb,
		"TLSA" => RecordKind::Tlsa,
		"TXT" => RecordKind::Txt,
		_ => RecordKind::Other(kind.to_string()),
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
	let text = response.text().await.map_err(transport)?;
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
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests_contract.rs"]
mod tests_contract;

#[cfg(test)]
#[path = "tests_path.rs"]
mod path_tests;
