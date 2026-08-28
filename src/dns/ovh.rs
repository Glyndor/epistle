//! An OVH (ovh.com) DNS provider implementing [`DnsProvider`]. OVH
//! authenticates every call with a triple — `application_key`,
//! `application_secret` and `consumer_key` — and an `X-Ovh-Signature` header
//! (SHA-1 over the request line and body). Records are addressable by numeric
//! id; `upsert` lists, updates if one already matches, otherwise creates,
//! then triggers a `/refresh` so the zone actually publishes.

use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret};

/// OVH endpoint URLs by region alias; the alias is the value the operator
/// puts in `endpoint` (default `ovh-eu`).
const ENDPOINTS: &[(&str, &str)] = &[
	("ovh-eu", "https://eu.api.ovh.com/1.0"),
	("ovh-ca", "https://ca.api.ovh.com/1.0"),
	("ovh-us", "https://api.us.ovhcloud.com/1.0"),
];
const DEFAULT_BASE: &str = "https://eu.api.ovh.com/1.0";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// An OVH-backed DNS provider for one zone.
pub struct OvhProvider {
	client: reqwest::Client,
	application_key: String,
	application_secret: String,
	consumer_secret: ScopedSecret,
	base: String,
}

/// A record as the OVH API returns it from `GET /domain/zone/{z}/record/{id}`.
#[derive(Clone, Deserialize)]
struct OvhRecord {
	#[serde(rename = "fieldType", default)]
	field_type: String,
	#[serde(rename = "subDomain", default)]
	sub_domain: String,
	#[serde(default)]
	target: String,
	#[serde(default)]
	ttl: u32,
}

impl OvhProvider {
	/// Build a provider with the three credentials. The `consumer_secret` is
	/// scoped to a single zone (least privilege) and never logged; the other
	/// two travel in headers but are also kept off stdout.
	pub fn new(
		application_key: String,
		application_secret: String,
		consumer_secret: ScopedSecret,
	) -> Self {
		OvhProvider {
			client: reqwest::Client::new(),
			application_key,
			application_secret,
			consumer_secret,
			base: DEFAULT_BASE.to_string(),
		}
	}

	/// Point the provider at an alternate API base (tests, or a regional
	/// override via the `endpoint` config key).
	pub fn with_base(mut self, base: impl Into<String>) -> Self {
		self.base = base.into();
		self
	}

	/// The OVH `X-Ovh-Signature` value: `$1$` + hex(SHA1(AS+"+"+CK+"+"+METHOD
	/// +"+"+URL+"+"+BODY+"+"+TIMESTAMP)). The Python reference implementation
	/// (python-ovh) and the OVH docs spell it this way; the verifier on the
	/// server checks the same bytes.
	fn sign(&self, method: &str, url: &str, body: &str, timestamp: u64) -> String {
		let to_sign = format!(
			"{}+{}+{}+{}+{}+{}",
			self.application_secret,
			self.consumer_secret.token(),
			method.to_uppercase(),
			url,
			body,
			timestamp,
		);
		let digest =
			ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, to_sign.as_bytes());
		format!("$1${}", hex_lower(digest.as_ref()))
	}

	/// The OVH fieldType token for a kind we publish.
	fn api_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A
			| RecordKind::Aaaa
			| RecordKind::Txt
			| RecordKind::Cname
			| RecordKind::Mx
			| RecordKind::Srv => Ok(kind.as_str()),
			RecordKind::Tlsa => Err(ProviderError::Unsupported),
		}
	}

	/// The relative subDomain OVH expects: apex → `""`, otherwise the name
	/// with `.zone` stripped.
	fn sub_domain(zone: &str, name: &str) -> String {
		let name = name.trim_end_matches('.');
		if name.eq_ignore_ascii_case(zone) {
			return String::new();
		}
		name.strip_suffix(&format!(".{zone}"))
			.map(str::to_string)
			.unwrap_or_else(|| name.to_string())
	}

	/// Reject a record outside the consumer's zone before any network call.
	fn authorize(&self, record: &DnsRecord) -> Result<(), ProviderError> {
		if self.consumer_secret.authorizes(&record.name) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	/// Send a signed request and parse the JSON body; map 401/403 to `Auth`
	/// and any other non-2xx to `Remote`.
	async fn send_json<T: serde::de::DeserializeOwned>(
		&self,
		method: reqwest::Method,
		url: &str,
		body: &str,
	) -> Result<T, ProviderError> {
		let text = self.send(method, url, body).await?;
		serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))
	}

	/// Send a signed request and read the body as text. Useful when the body
	/// may be empty (PUT/DELETE/refresh) — the parser for JSON would choke.
	async fn send(
		&self,
		method: reqwest::Method,
		url: &str,
		body: &str,
	) -> Result<String, ProviderError> {
		let ts = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		let sig = self.sign(method.as_str(), url, body, ts);
		let response = self
			.client
			.request(method, url)
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.header("X-Ovh-Application", &self.application_key)
			.header("X-Ovh-Consumer", self.consumer_secret.token())
			.header("X-Ovh-Timestamp", ts.to_string())
			.header("X-Ovh-Signature", sig)
			.body(body.to_string())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		check_status(&response)?;
		response
			.text()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))
	}

	/// Variant that ignores the response body (PUT, DELETE, /refresh).
	async fn send_unit(
		&self,
		method: reqwest::Method,
		url: &str,
		body: &str,
	) -> Result<(), ProviderError> {
		let ts = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		let sig = self.sign(method.as_str(), url, body, ts);
		let response = self
			.client
			.request(method, url)
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.header("X-Ovh-Application", &self.application_key)
			.header("X-Ovh-Consumer", self.consumer_secret.token())
			.header("X-Ovh-Timestamp", ts.to_string())
			.header("X-Ovh-Signature", sig)
			.body(body.to_string())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		check_status(&response)?;
		Ok(())
	}

	/// Find the first record at `sub_domain` of `kind`. Returns `None` if
	/// there are none — used to decide between POST and PUT on upsert, and
	/// to detect "already gone" on delete.
	async fn find_record_id(
		&self,
		zone: &str,
		sub_domain: &str,
		kind: &str,
	) -> Result<Option<u64>, ProviderError> {
		let url = format!(
			"{}/domain/zone/{}/record?fieldType={}&subDomain={}",
			self.base, zone, kind, sub_domain
		);
		let ids: Vec<u64> = self.send_json(reqwest::Method::GET, &url, "").await?;
		Ok(ids.into_iter().next())
	}

	/// Fetch one record by id; returns `None` if OVH says 404 (the record
	/// was removed out from under us between the list and the fetch).
	async fn get_record(&self, zone: &str, id: u64) -> Result<Option<OvhRecord>, ProviderError> {
		let url = format!("{}/domain/zone/{}/record/{}", self.base, zone, id);
		let ts = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		let sig = self.sign("GET", &url, "", ts);
		let response = self
			.client
			.get(&url)
			.header("X-Ovh-Application", &self.application_key)
			.header("X-Ovh-Consumer", self.consumer_secret.token())
			.header("X-Ovh-Timestamp", ts.to_string())
			.header("X-Ovh-Signature", sig)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(ProviderError::Auth);
		}
		if status == reqwest::StatusCode::NOT_FOUND {
			return Ok(None);
		}
		if !status.is_success() {
			return Err(ProviderError::Remote(format!("HTTP {status}")));
		}
		let text = response
			.text()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		let rec: OvhRecord =
			serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))?;
		Ok(Some(rec))
	}

	/// POST `/domain/zone/{z}/refresh` after every write so the change
	/// reaches OVH's authoritative nameservers.
	async fn refresh_zone(&self, zone: &str) -> Result<(), ProviderError> {
		let url = format!("{}/domain/zone/{}/refresh", self.base, zone);
		self.send_unit(reqwest::Method::POST, &url, "").await
	}

	async fn upsert_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let sub = Self::sub_domain(zone, &record.name);
		let body = serde_json::json!({
			"fieldType": kind,
			"subDomain": sub,
			"target": record.value,
			"ttl": record.ttl,
		})
		.to_string();
		if let Some(id) = self.find_record_id(zone, &sub, kind).await? {
			let url = format!("{}/domain/zone/{}/record/{}", self.base, zone, id);
			self.send_unit(reqwest::Method::PUT, &url, &body).await?;
		} else {
			let url = format!("{}/domain/zone/{}/record", self.base, zone);
			self.send_unit(reqwest::Method::POST, &url, &body).await?;
		}
		self.refresh_zone(zone).await
	}

	/// `delete` is idempotent: an absent record returns Ok without a refresh
	/// (no zone mutation happened).
	async fn delete_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let sub = Self::sub_domain(zone, &record.name);
		let Some(id) = self.find_record_id(zone, &sub, kind).await? else {
			return Ok(());
		};
		let url = format!("{}/domain/zone/{}/record/{}", self.base, zone, id);
		self.send_unit(reqwest::Method::DELETE, &url, "").await?;
		self.refresh_zone(zone).await
	}

	/// Fetch every record under the zone. The OVH list endpoint only
	/// returns ids, so we fan out one detail GET per id.
	async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		let url = format!("{}/domain/zone/{}/record", self.base, zone);
		let ids: Vec<u64> = self.send_json(reqwest::Method::GET, &url, "").await?;
		let mut records = Vec::with_capacity(ids.len());
		for id in ids {
			if let Some(rec) = self.get_record(zone, id).await? {
				records.push(record_from_ovh(&rec, zone));
			}
		}
		Ok(records)
	}
}

impl DnsProvider for OvhProvider {
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

/// Map an OVH fieldType back to a [`RecordKind`]; anything we do not
/// recognise (incl. the unsupported TLSA shape) comes back as TXT.
fn parse_kind(field_type: &str) -> RecordKind {
	match field_type {
		"A" => RecordKind::A,
		"AAAA" => RecordKind::Aaaa,
		"CNAME" => RecordKind::Cname,
		"MX" => RecordKind::Mx,
		"SRV" => RecordKind::Srv,
		_ => RecordKind::Txt,
	}
}

/// Convert an OVH record to a [`DnsRecord`], reconstructing the FQDN and
/// stripping the quotes the OVH API silently wraps around TXT targets.
fn record_from_ovh(rec: &OvhRecord, zone: &str) -> DnsRecord {
	let name = if rec.sub_domain.is_empty() {
		zone.to_string()
	} else {
		format!("{}.{}", rec.sub_domain, zone)
	};
	DnsRecord {
		name,
		kind: parse_kind(&rec.field_type),
		value: rec.target.trim_matches('"').to_string(),
		ttl: rec.ttl,
	}
}

/// Resolve an endpoint alias (or full URL) to a concrete API base. Unknown
/// aliases fall back to the European endpoint, OVH's default. Used by
/// `config::dns` to map `endpoint = "ovh-ca"` to the URL the provider is
/// pointed at.
pub fn resolve_base(endpoint: Option<&str>) -> String {
	let Some(endpoint) = endpoint else {
		return DEFAULT_BASE.to_string();
	};
	if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
		return endpoint.to_string();
	}
	ENDPOINTS
		.iter()
		.find(|(alias, _)| *alias == endpoint)
		.map(|(_, url)| (*url).to_string())
		.unwrap_or_else(|| DEFAULT_BASE.to_string())
}

/// Map a response status to success / typed error. Returns `Ok(())` when the
/// caller is going to ignore the body.
fn check_status(response: &reqwest::Response) -> Result<(), ProviderError> {
	let status = response.status();
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return Err(ProviderError::Auth);
	}
	if !status.is_success() {
		return Err(ProviderError::Remote(format!("HTTP {status}")));
	}
	Ok(())
}

/// Lowercase hex bytes (matches `hashlib.sha1(...).hexdigest()`).
fn hex_lower(bytes: &[u8]) -> String {
	use std::fmt::Write;
	let mut out = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		let _ = write!(out, "{byte:02x}");
	}
	out
}

#[cfg(test)]
#[path = "ovh_tests.rs"]
mod tests;
