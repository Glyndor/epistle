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

use crate::net::HttpsUrl;

use crate::dns::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, parse_srv, record_description,
	same_txt_purpose, unwrap_quotes,
};
use crate::dns::providers::transport;
use crate::dns::publish::provider::{Change, ReceiptOp, SnapshotOp};
use crate::dns::txt::{TxtForm, same_txt_value, txt_decode, txt_encode};

/// How Porkbun takes a TXT `content` and lists it back; see `upsert_inner`.
const TXT_FORM: TxtForm = TxtForm::Logical;

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
	base: HttpsUrl,
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
	#[serde(default)]
	prio: String,
}

impl PorkbunProvider {
	/// Build a provider for the secret's zone. `secret` holds the secret API
	/// key (`secretapikey`); `api_key` is the API key (`apikey`) it pairs with.
	pub fn new(secret: ScopedSecret, api_key: impl Into<String>) -> Self {
		PorkbunProvider {
			client: crate::dns::providers::http_client(),
			secret,
			api_key: api_key.into(),
			base: HttpsUrl::from_static(DEFAULT_BASE),
		}
	}

	/// Point the provider at an alternate API base (tests).
	pub fn with_base(mut self, base: HttpsUrl) -> Self {
		self.base = base;
		self
	}

	/// The Porkbun record type for a kind we can publish. A/AAAA/TXT/CNAME and
	/// TLSA go through the plain `content` field; SRV uses the same field plus
	/// a separate `prio` (priority in the upper bits, weight in the lower —
	/// Porkbun packs them into a single integer, see below); MX uses the same
	/// `prio` field as a plain preference and is not yet supported because
	/// the rest of epistle still builds MX with the priority embedded in the
	/// value string.
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

	/// Validate that `record.value` is a well-formed SRV. Returns the priority
	/// so the upsert path can populate the `prio` field (Porkbun treats it
	/// as the plain preference for SRV). Returns `Remote` on malformed input.
	fn sr_prio(record: &DnsRecord) -> Result<u16, ProviderError> {
		let (priority, _weight, _port, _target) = parse_srv(&record.value)
			.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {}", record.value)))?;
		Ok(priority)
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

	/// POST to `{base}/<segments...>` (each segment escaped as one path
	/// segment) with the credentials merged into `fields`, and decode the
	/// reply. Porkbun takes `apikey`/`secretapikey` in the body on every call.
	async fn call(
		&self,
		segments: &[&str],
		fields: serde_json::Value,
	) -> Result<Reply, ProviderError> {
		let url = self.base.with_segments(segments)?;
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
			.post(url.into_url())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(serde_json::Value::Object(body).to_string())
			.send()
			.await
			.map_err(transport)?;
		decode(response).await
	}

	/// Every record in the zone, as Porkbun reports it.
	async fn retrieve(&self) -> Result<Vec<Record>, ProviderError> {
		let segments = ["dns", "retrieve", self.secret.zone()];
		Ok(self.call(&segments, serde_json::Value::Null).await?.records)
	}

	/// The ids of every record an upsert of `record` replaces: same
	/// fully-qualified name and type, and for TXT the same purpose (the
	/// contract in `src/dns/provider/mod.rs`), so a sibling TXT at the name is
	/// left alone. More than one means the zone already holds duplicates,
	/// which the upsert collapses rather than adds to.
	async fn matching_ids(
		&self,
		record: &DnsRecord,
		kind: &str,
	) -> Result<Vec<String>, ProviderError> {
		let name = record.name.trim_end_matches('.');
		Ok(self
			.retrieve()
			.await?
			.into_iter()
			.filter(|r| {
				r.kind.eq_ignore_ascii_case(kind)
					&& r.name.trim_end_matches('.').eq_ignore_ascii_case(name)
					&& (record.kind != RecordKind::Txt
						|| same_txt_purpose(&r.content, &record.value))
			})
			.map(|r| r.id)
			.collect())
	}

	/// Remove the record with `id`.
	async fn delete_id(&self, id: &str) -> Result<(), ProviderError> {
		let segments = ["dns", "delete", self.secret.zone(), id];
		self.call(&segments, serde_json::Value::Null)
			.await
			.map(drop)
	}

	async fn upsert_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let fields = self.record_fields(&record, kind)?;
		let existing = self.matching_ids(&record, kind).await?;
		match existing.split_first() {
			// Replace in place, then drop any duplicate left at the same
			// name/type so an upsert never widens the record set.
			Some((id, duplicates)) => {
				let segments = ["dns", "edit", self.secret.zone(), id];
				self.call(&segments, fields).await?;
				for extra in duplicates {
					self.delete_id(extra).await?;
				}
				Ok(())
			}
			None => {
				let segments = ["dns", "create", self.secret.zone()];
				self.call(&segments, fields).await.map(drop)
			}
		}
	}

	async fn delete_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		// Porkbun addresses every record by numeric id, so a delete is
		// a read-then-delete loop. The TXT matching rule from
		// `src/dns/provider/mod.rs` is the contract: a value-bearing delete
		// drops only the row whose content matches the value (sibling
		// ACME challenges at the same owner survive), an empty-value
		// delete drops every row at the owner (the DKIM rotator's
		// retire path). Other record kinds fall through to the
		// name+kind match, which is already whole-set semantics.
		let name = record.name.trim_end_matches('.');
		let targets = self
			.retrieve()
			.await?
			.into_iter()
			.filter(|r| {
				r.kind.eq_ignore_ascii_case(kind)
					&& r.name.trim_end_matches('.').eq_ignore_ascii_case(name)
					&& (record.kind != RecordKind::Txt
						|| record.value.is_empty()
						|| same_txt_value(&r.content, &record.value))
			})
			.map(|r| r.id)
			.collect::<Vec<_>>();
		for id in targets {
			self.delete_id(&id).await?;
		}
		Ok(())
	}

	async fn list_inner(&self) -> Result<Vec<DnsRecord>, ProviderError> {
		Ok(self
			.retrieve()
			.await?
			.iter()
			.filter_map(record_of)
			.collect())
	}
}

/// The record a retrieved entry stands for, read back into the shape the rest
/// of epistle uses; `None` for an SRV it cannot read.
fn record_of(r: &Record) -> Option<DnsRecord> {
	let kind = RecordKind::from_token(&r.kind);
	// SRV records Porkbun returns without a usable `prio` are
	// malformed: drop them so the rest of the list does not
	// carry a misleading empty value.
	if kind == RecordKind::Srv && r.prio.is_empty() {
		return None;
	}
	let value = if kind == RecordKind::Srv {
		exact::stored_srv(&r.content, &r.prio)?
	} else if kind == RecordKind::Txt {
		txt_decode(&r.content, TXT_FORM)
	} else if kind == RecordKind::Mx && r.prio.parse::<u16>().is_ok() {
		format!("{} {}", r.prio, r.content)
	} else {
		unwrap_quotes(&r.content).to_string()
	};
	Some(DnsRecord {
		name: r.name.trim_end_matches('.').to_string(),
		kind,
		value,
		ttl: r.ttl.parse().unwrap_or(MIN_TTL),
		proxied: None,
	})
}

impl DnsProvider for PorkbunProvider {
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
	fn delete_exact(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(crate::dns::providers::within(async move {
			self.delete_exact_inner(record).await
		}))
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone_name = zone.to_string();
		Box::pin(crate::dns::providers::listing(zone_name, async move {
			self.list_inner().await
		}))
	}
	fn publish_snapshot<'a>(&'a self, zone: &'a str) -> SnapshotOp<'a> {
		Box::pin(crate::dns::providers::within(self.snapshot_inner(zone)))
	}
	fn apply_guarded<'a>(&'a self, zone: &'a str, change: Change) -> ReceiptOp<'a> {
		Box::pin(crate::dns::providers::guarded::apply(self, zone, change))
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
	let text = crate::dns::providers::read_body(response).await?;
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

mod exact;
mod fields;
mod guarded;

#[cfg(test)]
mod tests;
