//! A Bunny.net DNS provider implementing [`DnsProvider`]. Bunny references a
//! zone by its numeric id, so on first use we issue `GET /dnszone?search=...`
//! and pick the entry whose `Domain` matches the token's zone (zones are
//! unique by name). Record writes go through `PUT /dnszone/{id}/records` to
//! create or `POST /dnszone/{id}/records/{id}` to update — same `name+type`
//! pair is what makes two Bunny records "the same" record, so upsert checks
//! the zone's `Records` list first and replaces in place when one is there.
//! Authenticates with the account access key in the `AccessKey` header (not
//! Bearer).

use std::pin::Pin;
use std::sync::Mutex;

use serde::Deserialize;

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret};

/// Bunny's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://api.bunny.net";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A Bunny-backed DNS provider for one zone.
pub struct BunnyProvider {
	client: reqwest::Client,
	secret: ScopedSecret,
	base: String,
	/// Cached numeric zone id, looked up on first use. Held in a sync mutex
	/// only across quick reads/writes; never across an `await`.
	zone_id: Mutex<Option<i64>>,
}

/// `GET /dnszone?search=...` response body.
#[derive(Deserialize)]
struct ListZones {
	#[serde(rename = "Items", default)]
	items: Vec<ZoneRef>,
}

#[derive(Deserialize)]
struct ZoneRef {
	#[serde(rename = "Id")]
	id: i64,
	#[serde(rename = "Domain", default)]
	domain: Option<String>,
}

/// `GET /dnszone/{id}` response body (full view — `Records` is included).
#[derive(Deserialize)]
struct ZoneDetail {
	#[serde(rename = "Records", default)]
	records: Vec<DnsRecordRef>,
}

#[derive(Deserialize)]
struct DnsRecordRef {
	#[serde(rename = "Id")]
	id: i64,
	#[serde(rename = "Type")]
	rtype: i64,
	#[serde(rename = "Name", default)]
	name: Option<String>,
	#[serde(rename = "Value", default)]
	value: Option<String>,
	#[serde(rename = "Ttl", default)]
	ttl: i64,
}

impl BunnyProvider {
	/// Build a provider for the token's zone.
	pub fn new(secret: ScopedSecret) -> Self {
		BunnyProvider {
			client: reqwest::Client::new(),
			secret,
			base: DEFAULT_BASE.to_string(),
			zone_id: Mutex::new(None),
		}
	}

	/// Point the provider at an alternate API base (tests).
	pub fn with_base(mut self, base: impl Into<String>) -> Self {
		self.base = base.into();
		self
	}

	/// The relative record name: `name` with the trailing `.zone` stripped,
	/// the apex becoming the empty string (Bunny's convention).
	fn subname(&self, name: &str) -> String {
		let name = name.trim_end_matches('.');
		let zone = self.secret.zone();
		if name.eq_ignore_ascii_case(zone) {
			return String::new();
		}
		name.strip_suffix(&format!(".{zone}"))
			.unwrap_or(name)
			.to_string()
	}

	/// Bunny's numeric record type for a kind we publish. Anything else
	/// (MX/SRV need priority/weight; TLSA needs tag/value we do not emit)
	/// returns [`ProviderError::Unsupported`].
	fn api_type(kind: RecordKind) -> Result<i64, ProviderError> {
		match kind {
			RecordKind::A => Ok(0),
			RecordKind::Aaaa => Ok(1),
			RecordKind::Cname => Ok(2),
			RecordKind::Txt => Ok(3),
			RecordKind::Mx | RecordKind::Srv | RecordKind::Tlsa => Err(ProviderError::Unsupported),
		}
	}

	/// Reject a record the token is not scoped for, before any network call.
	fn authorize(&self, name: &str) -> Result<(), ProviderError> {
		if self.secret.authorizes(name) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	/// Look up the numeric zone id (cached) by searching for the zone's name
	/// and picking the entry whose `Domain` is an exact match — Bunny's
	/// `?search=` is a prefix match, so a zone `example.org` also returns
	/// `evil.example.org` and we must not pick it.
	async fn zone_id(&self) -> Result<i64, ProviderError> {
		if let Some(id) = *self.zone_id.lock().unwrap() {
			return Ok(id);
		}
		let url = format!("{}/dnszone?search={}", self.base, self.secret.zone());
		let resp: ListZones = self.get_json(&url).await?;
		let zone = self.secret.zone().to_string();
		let id = resp
			.items
			.into_iter()
			.find(|z| z.domain.as_deref() == Some(zone.as_str()))
			.map(|z| z.id)
			.ok_or_else(|| ProviderError::Remote(format!("zone not found: {zone}")))?;
		*self.zone_id.lock().unwrap() = Some(id);
		Ok(id)
	}

	/// Fetch the zone detail (which embeds the records list).
	async fn zone_detail(&self, zone_id: i64) -> Result<ZoneDetail, ProviderError> {
		let url = format!("{}/dnszone/{zone_id}", self.base);
		self.get_json(&url).await
	}

	/// GET a JSON body, mapping 401/403 to [`ProviderError::Auth`].
	async fn get_json<T: serde::de::DeserializeOwned>(
		&self,
		url: &str,
	) -> Result<T, ProviderError> {
		let response = self
			.client
			.get(url)
			.header("AccessKey", self.secret.token())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		decode(response).await
	}

	/// Issue a JSON write with the `AccessKey` header.
	async fn send_write(
		&self,
		method: reqwest::Method,
		url: &str,
		body: String,
	) -> Result<reqwest::Response, ProviderError> {
		self.client
			.request(method, url)
			.header("AccessKey", self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))
	}

	/// Build the create/update body for one record.
	fn record_body(&self, record: &DnsRecord, rtype: i64) -> Result<String, ProviderError> {
		Ok(serde_json::json!({
			"Type": rtype,
			"Name": self.subname(&record.name),
			"Value": record.value,
			"Ttl": record.ttl,
		})
		.to_string())
	}

	async fn upsert_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record.name)?;
		let rtype = Self::api_type(record.kind)?;
		let zone_id = self.zone_id().await?;
		let detail = self.zone_detail(zone_id).await?;
		let name = self.subname(&record.name);
		let body = self.record_body(&record, rtype)?;
		let existing = detail
			.records
			.into_iter()
			.find(|r| r.rtype == rtype && r.name.as_deref() == Some(name.as_str()));
		let response = if let Some(rec) = existing {
			let url = format!("{}/dnszone/{zone_id}/records/{}", self.base, rec.id);
			self.send_write(reqwest::Method::POST, &url, body).await?
		} else {
			let url = format!("{}/dnszone/{zone_id}/records", self.base);
			self.send_write(reqwest::Method::PUT, &url, body).await?
		};
		check(response)
	}

	async fn delete_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record.name)?;
		let rtype = Self::api_type(record.kind)?;
		let zone_id = self.zone_id().await?;
		let detail = self.zone_detail(zone_id).await?;
		let name = self.subname(&record.name);
		let Some(rec) = detail
			.records
			.into_iter()
			.find(|r| r.rtype == rtype && r.name.as_deref() == Some(name.as_str()))
		else {
			return Ok(()); // idempotent: nothing to remove.
		};
		let url = format!("{}/dnszone/{zone_id}/records/{}", self.base, rec.id);
		let response = self
			.client
			.delete(&url)
			.header("AccessKey", self.secret.token())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		let status = response.status();
		if status == reqwest::StatusCode::NOT_FOUND {
			return Ok(()); // idempotent: gone between find and delete.
		}
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(ProviderError::Auth);
		}
		if status.is_success() {
			Ok(())
		} else {
			Err(ProviderError::Remote(format!("HTTP {status}")))
		}
	}

	async fn list_inner(&self) -> Result<Vec<DnsRecord>, ProviderError> {
		let zone_id = self.zone_id().await?;
		let detail = self.zone_detail(zone_id).await?;
		let zone = self.secret.zone().to_string();
		Ok(detail
			.records
			.into_iter()
			.map(|r| {
				let name_rel = r.name.unwrap_or_default();
				let name = if name_rel.is_empty() {
					zone.clone()
				} else {
					format!("{name_rel}.{zone}")
				};
				DnsRecord {
					name,
					kind: parse_kind(r.rtype),
					value: r.value.unwrap_or_default(),
					ttl: r.ttl.max(0) as u32,
				}
			})
			.collect())
	}
}

impl DnsProvider for BunnyProvider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move { self.upsert_inner(record).await })
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move { self.delete_inner(record).await })
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async move { self.list_inner().await })
	}
}

/// Map Bunny's numeric record type back to a [`RecordKind`].
fn parse_kind(rtype: i64) -> RecordKind {
	match rtype {
		0 => RecordKind::A,
		1 => RecordKind::Aaaa,
		2 => RecordKind::Cname,
		4 => RecordKind::Mx,
		8 => RecordKind::Srv,
		15 => RecordKind::Tlsa,
		_ => RecordKind::Txt,
	}
}

/// Decode a JSON body, mapping 401/403 to an auth error.
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
#[path = "bunny_tests.rs"]
mod tests;
