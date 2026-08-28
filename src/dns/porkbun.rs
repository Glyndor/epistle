//! A Porkbun DNS provider implementing [`DnsProvider`]. Porkbun's v3 API is
//! JSON over POST only, and it carries the credentials in the request **body**
//! (`apikey` / `secretapikey`) rather than in a header, so there is no
//! `Authorization` header on any call. Records are addressed by numeric id, so
//! writes are a retrieve-then-create-or-edit: `POST /dns/retrieve/{zone}`
//! locates the matching name/type, then `POST /dns/create/{zone}` or
//! `POST /dns/edit/{zone}/{id}` publishes it.
//!
//! Porkbun answers `200 OK` with `{"status":"ERROR", …}` for application-level
//! failures as readily as it answers `400`, so every reply is decoded and the
//! `status` field checked; a non-`SUCCESS` status is an error regardless of the
//! HTTP code, and the authentication-flavoured `code` values map to
//! [`ProviderError::Auth`].
//!
//! Endpoints and payloads follow <https://porkbun.com/llms/dns> and the
//! OpenAPI spec at <https://porkbun.com/api/json/v3/spec>.

use std::pin::Pin;

use serde::Deserialize;

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret};

/// Porkbun's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://api.porkbun.com/api/json/v3";

/// Porkbun's floor for a record TTL, in seconds. Shorter values are rejected;
/// the API also treats `0` as "use the account minimum".
const MIN_TTL: u32 = 600;

/// Error `code` values Porkbun returns when the credentials, the account, or
/// the key's allowlists reject the call. Everything else is a remote error.
const AUTH_CODES: &[&str] = &[
	"API_KEY_REQUIRED",
	"INVALID_API_KEYS_001",
	"INVALID_TOKEN",
	"INVALID_USER",
	"IP_NOT_ALLOWED",
	"DOMAIN_NOT_ALLOWED",
];

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A Porkbun-backed DNS provider for one zone.
pub struct PorkbunProvider {
	client: reqwest::Client,
	/// The secret API key, scoped to the zone it may write to.
	secret: ScopedSecret,
	/// The (non-secret) API key that pairs with it.
	api_key: String,
	base: String,
}

/// A Porkbun reply. Every endpoint returns `status`; the rest of the fields are
/// endpoint-specific and absent elsewhere. Porkbun serialises the record `id`,
/// `ttl` and `prio` as strings.
#[derive(Deserialize)]
struct Reply {
	#[serde(default)]
	status: String,
	#[serde(default)]
	message: Option<String>,
	#[serde(default)]
	code: Option<String>,
	#[serde(default)]
	records: Vec<Record>,
}

/// One record as `POST /dns/retrieve/{zone}` returns it. `name` is the
/// fully-qualified name, not the label.
#[derive(Deserialize)]
struct Record {
	#[serde(default)]
	id: String,
	#[serde(default)]
	name: String,
	#[serde(rename = "type", default)]
	kind: String,
	#[serde(default)]
	content: String,
	#[serde(default)]
	ttl: String,
}

impl PorkbunProvider {
	/// Build a provider for the secret's zone. `secret` holds the secret API
	/// key (`secretapikey`); `api_key` is the API key (`apikey`) it pairs with.
	pub fn new(secret: ScopedSecret, api_key: impl Into<String>) -> Self {
		PorkbunProvider {
			client: reqwest::Client::new(),
			secret,
			api_key: api_key.into(),
			base: DEFAULT_BASE.to_string(),
		}
	}

	/// Point the provider at an alternate API base (tests).
	pub fn with_base(mut self, base: impl Into<String>) -> Self {
		self.base = base.into();
		self
	}

	/// The Porkbun record type for a kind we can publish. A/AAAA/TXT/CNAME and
	/// TLSA go through the plain `content` field; MX and SRV need the separate
	/// `prio` field (and a target split out of the value), which epistle does
	/// not emit yet.
	fn api_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A
			| RecordKind::Aaaa
			| RecordKind::Txt
			| RecordKind::Cname
			| RecordKind::Tlsa => Ok(kind.as_str()),
			RecordKind::Mx | RecordKind::Srv => Err(ProviderError::Unsupported),
		}
	}

	/// The `name` Porkbun expects: the label relative to the zone, with the
	/// apex as the empty string (Porkbun's "blank for root").
	fn label(&self, name: &str) -> String {
		let name = name.trim_end_matches('.');
		let zone = self.secret.zone().trim_end_matches('.');
		if name.eq_ignore_ascii_case(zone) {
			return String::new();
		}
		name.strip_suffix(&format!(".{zone}"))
			.unwrap_or(name)
			.to_string()
	}

	/// Reject a record the secret is not scoped for, before any network call.
	fn authorize(&self, record: &DnsRecord) -> Result<(), ProviderError> {
		if self.secret.authorizes(&record.name) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	/// POST `path` with the credentials merged into `fields`, and decode the
	/// reply. Porkbun takes `apikey`/`secretapikey` in the body on every call.
	async fn call(&self, path: &str, fields: serde_json::Value) -> Result<Reply, ProviderError> {
		let mut body = serde_json::Map::new();
		body.insert("apikey".to_string(), self.api_key.clone().into());
		body.insert(
			"secretapikey".to_string(),
			self.secret.token().to_string().into(),
		);
		if let serde_json::Value::Object(fields) = fields {
			body.extend(fields);
		}
		let response = self
			.client
			.post(format!("{}{path}", self.base))
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(serde_json::Value::Object(body).to_string())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		decode(response).await
	}

	/// Every record in the zone, as Porkbun reports it.
	async fn retrieve(&self) -> Result<Vec<Record>, ProviderError> {
		let path = format!("/dns/retrieve/{}", self.secret.zone());
		Ok(self.call(&path, serde_json::Value::Null).await?.records)
	}

	/// The ids of every record with this fully-qualified name and type. More
	/// than one means the zone already holds duplicates (two TXT at the same
	/// name is the classic case), which an upsert has to collapse rather than
	/// add to.
	async fn matching_ids(&self, name: &str, kind: &str) -> Result<Vec<String>, ProviderError> {
		let name = name.trim_end_matches('.');
		Ok(self
			.retrieve()
			.await?
			.into_iter()
			.filter(|r| {
				r.kind.eq_ignore_ascii_case(kind)
					&& r.name.trim_end_matches('.').eq_ignore_ascii_case(name)
			})
			.map(|r| r.id)
			.collect())
	}

	/// Remove the record with `id`.
	async fn delete_id(&self, id: &str) -> Result<(), ProviderError> {
		let path = format!("/dns/delete/{}/{id}", self.secret.zone());
		self.call(&path, serde_json::Value::Null).await.map(drop)
	}

	async fn upsert_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let fields = serde_json::json!({
			"name": self.label(&record.name),
			"type": kind,
			"content": record.value,
			"ttl": record.ttl.max(MIN_TTL),
		});
		let existing = self.matching_ids(&record.name, kind).await?;
		match existing.split_first() {
			// Replace in place, then drop any duplicate left at the same
			// name/type so an upsert never widens the record set.
			Some((id, duplicates)) => {
				let path = format!("/dns/edit/{}/{id}", self.secret.zone());
				self.call(&path, fields).await?;
				for extra in duplicates {
					self.delete_id(extra).await?;
				}
				Ok(())
			}
			None => {
				let path = format!("/dns/create/{}", self.secret.zone());
				self.call(&path, fields).await.map(drop)
			}
		}
	}

	async fn delete_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		// No match: already absent, so nothing to do (idempotent).
		for id in self.matching_ids(&record.name, kind).await? {
			self.delete_id(&id).await?;
		}
		Ok(())
	}

	async fn list_inner(&self) -> Result<Vec<DnsRecord>, ProviderError> {
		Ok(self
			.retrieve()
			.await?
			.into_iter()
			.map(|r| DnsRecord {
				name: r.name.trim_end_matches('.').to_string(),
				kind: parse_kind(&r.kind),
				value: r.content.trim_matches('"').to_string(),
				ttl: r.ttl.parse().unwrap_or(MIN_TTL),
			})
			.collect())
	}
}

impl DnsProvider for PorkbunProvider {
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

/// Map a Porkbun type token back to a [`RecordKind`], defaulting to TXT.
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

/// Decode a reply, treating anything but `status: "SUCCESS"` as a failure even
/// when it arrives with `200 OK`, and mapping credential/allowlist rejections
/// to [`ProviderError::Auth`]. The error message carries Porkbun's `message`,
/// never the credentials.
async fn decode(response: reqwest::Response) -> Result<Reply, ProviderError> {
	let http = response.status();
	if http == reqwest::StatusCode::UNAUTHORIZED || http == reqwest::StatusCode::FORBIDDEN {
		return Err(ProviderError::Auth);
	}
	let text = response
		.text()
		.await
		.map_err(|e| ProviderError::Remote(e.to_string()))?;
	let reply: Reply =
		serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))?;
	if reply.status.eq_ignore_ascii_case("SUCCESS") {
		return Ok(reply);
	}
	if reply
		.code
		.as_deref()
		.is_some_and(|code| AUTH_CODES.contains(&code))
	{
		return Err(ProviderError::Auth);
	}
	Err(ProviderError::Remote(
		reply.message.unwrap_or_else(|| format!("HTTP {http}")),
	))
}

#[cfg(test)]
#[path = "porkbun_tests.rs"]
mod tests;
