//! A Spaceship (spaceship.dev) DNS provider implementing [`DnsProvider`].
//! Authentication is two header values — `X-API-Key` and `X-API-Secret` — set up
//! at <https://www.spaceship.com/application/api-manager/>. The API at
//! <https://spaceship.dev/api/v1> has no in-place update: `upsert` is
//! read-then-delete-then-add (delete the existing `(type, name)` tuple, then
//! `PUT` the new item). A/AAAA/TXT/CNAME/TLSA are supported; MX and SRV carry
//! priority/weight/port fields the rest of epistle does not emit yet.

use std::pin::Pin;

use serde::Deserialize;

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, parse_srv};

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
	base: String,
}

#[derive(Deserialize)]
struct ListResponse {
	items: Vec<serde_json::Value>,
	#[serde(default)]
	total: i64,
}

impl SpaceshipProvider {
	/// Build a provider for `zone` with the two credential halves.
	pub fn new(api_key: String, api_secret: String, zone: String) -> Self {
		SpaceshipProvider {
			client: reqwest::Client::new(),
			api_key,
			api_secret,
			zone,
			base: DEFAULT_BASE.to_string(),
		}
	}

	/// Point the provider at an alternate API base (tests).
	pub fn with_base(mut self, base: impl Into<String>) -> Self {
		self.base = base.into();
		self
	}

	/// The Spaceship type token for a kind we can publish; SRV splits the
	/// presentation form into `priority`/`weight`/`port`/`target` fields, MX
	/// needs the priority split out (epistle still packs it into the value).
	fn api_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A
			| RecordKind::Aaaa
			| RecordKind::Txt
			| RecordKind::Cname
			| RecordKind::Tlsa
			| RecordKind::Srv => Ok(kind.as_str()),
			RecordKind::Mx => Err(ProviderError::Unsupported),
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
	fn value_field(kind: RecordKind) -> &'static str {
		match kind {
			RecordKind::Txt => "value",
			RecordKind::A | RecordKind::Aaaa => "address",
			RecordKind::Cname => "cname",
			RecordKind::Tlsa => "associationData",
			RecordKind::Srv => "target",
			RecordKind::Mx => unreachable!("filtered by api_kind"),
		}
	}

	/// Add a fresh request with the Spaceship auth headers attached.
	fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
		self.client
			.request(method, format!("{}{path}", self.base))
			.header("X-API-Key", &self.api_key)
			.header("X-API-Secret", &self.api_secret)
			.header(reqwest::header::CONTENT_TYPE, "application/json")
	}

	/// `PUT /dns/records/{zone}` — append items with `force: true`. Spaceship
	/// documents the body as `{ force: true, items: [ ... ] }` and replies 204
	/// on success. SRV uses dedicated `priority`/`weight`/`port`/`target`
	/// fields; everything else uses the kind-specific value field.
	async fn add(&self, kind: &str, rel: &str, record: &DnsRecord) -> Result<(), ProviderError> {
		let path = format!("/dns/records/{}", self.zone);
		let mut item = serde_json::json!({
			"type": kind,
			"name": rel,
			"ttl": record.ttl,
		});
		if record.kind == RecordKind::Srv {
			let (priority, weight, port, target) = parse_srv(&record.value)
				.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {}", record.value)))?;
			let map = item.as_object_mut().expect("object");
			map.insert("priority".to_string(), priority.into());
			map.insert("weight".to_string(), weight.into());
			map.insert("port".to_string(), port.into());
			map.insert("target".to_string(), target.into());
		} else {
			let map = item.as_object_mut().expect("object");
			map.insert(Self::value_field(record.kind).to_string(), record.value.clone().into());
		}
		let body = serde_json::json!({
			"force": true,
			"items": [item],
		})
		.to_string();
		let response = self
			.request(reqwest::Method::PUT, &path)
			.body(body)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		check(response)
	}

	/// `DELETE /dns/records/{zone}` — remove the matching item(s). The body is
	/// an array of `{type, name, [value]}` records; TXT deletes require
	/// `value` per the schema. Replies 204 whether or not anything matched
	/// (idempotent by definition).
	async fn remove(&self, kind: &str, rel: &str, record: &DnsRecord) -> Result<(), ProviderError> {
		let path = format!("/dns/records/{}", self.zone);
		let mut item = serde_json::json!({"type": kind, "name": rel});
		// TXT deletes need the value to disambiguate same-name records.
		if record.kind == RecordKind::Txt {
			item["value"] = serde_json::Value::String(record.value.clone());
		}
		let response = self
			.request(reqwest::Method::DELETE, &path)
			.body(serde_json::json!([item]).to_string())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		check(response)
	}

	/// `GET /dns/records/{zone}?take=500&skip=N` — list records. Spaceship
	/// caps `take` at 500; we page through `skip` until we have fetched
	/// `total` records so a large zone is not silently truncated.
	async fn list_all(&self) -> Result<Vec<serde_json::Value>, ProviderError> {
		let path = format!("/dns/records/{}", self.zone);
		let mut out = Vec::new();
		let mut skip: i64 = 0;
		loop {
			let url = format!("{}?take={PAGE_MAX}&skip={skip}", path);
			let response = self
				.request(reqwest::Method::GET, &url)
				.send()
				.await
				.map_err(|e| ProviderError::Remote(e.to_string()))?;
			let status = response.status();
			if status == reqwest::StatusCode::UNAUTHORIZED
				|| status == reqwest::StatusCode::FORBIDDEN
			{
				return Err(ProviderError::Auth);
			}
			let page: ListResponse = response
				.text()
				.await
				.map_err(|e| ProviderError::Remote(e.to_string()))
				.and_then(|text| {
					serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))
				})?;
			let count = page.items.len() as i64;
			out.extend(page.items);
			if out.len() as i64 >= page.total || count == 0 {
				break;
			}
			skip += count;
		}
		Ok(out)
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

	/// Map a Spaceship list item back to a [`RecordKind`], defaulting to TXT
	/// so an unknown kind we did not emit still surfaces instead of being
	/// silently dropped.
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

	async fn upsert_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let rel = self.relative_name(&record.name);
		// Spaceship has no in-place update: remove the existing matching
		// record first, then add the new one. remove() is a 204 either way,
		// so this is also the idempotent path when the record is absent.
		self.remove(kind, &rel, &record).await?;
		self.add(kind, &rel, &record).await
	}

	async fn delete_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let rel = self.relative_name(&record.name);
		self.remove(kind, &rel, &record).await
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
				let value = if matches!(Self::parse_kind(kind), RecordKind::Srv) {
					let priority = item.get("priority").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
					let weight = item.get("weight").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
					let port = item.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
					let target = item.get("target").and_then(|v| v.as_str())?;
					format!("{priority} {weight} {port} {}", target.trim_end_matches('.'))
				} else {
					Self::extract_value(&item)?
				};
				Some(DnsRecord {
					name: fqdn,
					kind: Self::parse_kind(kind),
					value,
					ttl,
				})
			})
			.collect())
	}
}

impl DnsProvider for SpaceshipProvider {
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

#[cfg(test)]
#[path = "spaceship_tests.rs"]
mod tests;
