//! A Cloudflare DNS provider (RFC-less, vendor API) implementing
//! [`DnsProvider`]. It authenticates with a zone-scoped API token and supports
//! the record kinds epistle publishes — TXT/A/AAAA/CNAME via a `content` field
//! and TLSA via a structured `data` object; MX/SRV (priorities/weights) return
//! [`ProviderError::Unsupported`] for now.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Deserialize;

use crate::net::HttpsUrl;

use super::cloudflare_tags;
use super::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, parse_srv, record_description,
	same_txt_purpose,
};

/// Cloudflare's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://api.cloudflare.com/client/v4";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A Cloudflare-backed DNS provider.
pub struct CloudflareProvider {
	client: reqwest::Client,
	secret: ScopedSecret,
	base: HttpsUrl,
	/// `epistle:<hostname>` tag written on every record, when a hostname is set.
	host_tag: Option<String>,
	/// Cleared for the life of the provider once Cloudflare refuses a write
	/// because of tags (Free plan), so later writes do not try them again.
	tags_allowed: AtomicBool,
}

#[derive(Deserialize)]
struct ListZones {
	result: Vec<ZoneRef>,
}

#[derive(Deserialize)]
struct ZoneRef {
	id: String,
}

#[derive(Deserialize)]
struct ListRecords {
	result: Vec<RecordRef>,
}

#[derive(Deserialize)]
struct RecordRef {
	id: String,
	name: String,
	#[serde(rename = "type")]
	kind: String,
	content: String,
	#[serde(default)]
	ttl: u32,
	/// Tags already on the record, kept (but for epistle's own) on update.
	#[serde(default)]
	tags: Vec<String>,
}

impl CloudflareProvider {
	/// Build a provider for the token's zone.
	pub fn new(secret: ScopedSecret) -> Self {
		CloudflareProvider {
			client: reqwest::Client::new(),
			secret,
			base: HttpsUrl::from_static(DEFAULT_BASE),
			host_tag: None,
			tags_allowed: AtomicBool::new(true),
		}
	}

	/// Tag every record with `epistle:<hostname>` so a zone shared by several
	/// servers shows which one wrote it. Tags need a paid plan; see the
	/// `cloudflare_tags` module.
	pub fn with_hostname(mut self, hostname: &str) -> Self {
		self.host_tag = cloudflare_tags::host_tag(hostname);
		self
	}

	/// Point the provider at an alternate API base (tests).
	pub fn with_base(mut self, base: HttpsUrl) -> Self {
		self.base = base;
		self
	}

	/// The Cloudflare record type for a kind we can publish. TXT/A/AAAA/CNAME
	/// go through a plain `content` field; TLSA, SRV, MX, and CAA use a
	/// structured `data` object — each carries its kind-specific shape
	/// (`usage selector matching cert` / `priority weight port target` /
	/// `priority host` / `flags tag value`).
	fn api_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A
			| RecordKind::Aaaa
			| RecordKind::Txt
			| RecordKind::Cname
			| RecordKind::Tlsa
			| RecordKind::Srv
			| RecordKind::Mx
			| RecordKind::Caa => Ok(kind.as_str()),
		}
	}

	/// The Cloudflare record body for a record: TLSA and SRV carry a
	/// structured `data` object (`usage selector matching_type certificate` /
	/// `priority weight port target`), everything else a plain `content`
	/// string. SRV splits the presentation form on whitespace.
	#[cfg(test)]
	fn record_body(kind: &str, record: &DnsRecord) -> Result<String, ProviderError> {
		Ok(Self::record_value(kind, record)?.to_string())
	}

	/// The record body as JSON, before tags are added.
	fn record_value(kind: &str, record: &DnsRecord) -> Result<serde_json::Value, ProviderError> {
		let mut value = if record.kind == RecordKind::Tlsa {
			let mut parts = record.value.split_whitespace();
			let usage: u8 =
				parts
					.next()
					.and_then(|p| p.parse().ok())
					.ok_or(ProviderError::Remote(
						"TLSA needs usage selector matching cert".into(),
					))?;
			let selector: u8 =
				parts
					.next()
					.and_then(|p| p.parse().ok())
					.ok_or(ProviderError::Remote(
						"TLSA needs usage selector matching cert".into(),
					))?;
			let matching: u8 =
				parts
					.next()
					.and_then(|p| p.parse().ok())
					.ok_or(ProviderError::Remote(
						"TLSA needs usage selector matching cert".into(),
					))?;
			let cert = parts.next().ok_or(ProviderError::Remote(
				"TLSA needs usage selector matching cert".into(),
			))?;
			serde_json::json!({
				"type": kind,
				"name": record.name,
				"ttl": record.ttl,
				"data": {
					"usage": usage,
					"selector": selector,
					"matching_type": matching,
					"certificate": cert,
				},
			})
		} else if record.kind == RecordKind::Srv {
			let (priority, weight, port, target) = parse_srv(&record.value)
				.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {}", record.value)))?;
			serde_json::json!({
				"type": kind,
				"name": record.name,
				"ttl": record.ttl,
				"data": {
					"priority": priority,
					"weight": weight,
					"port": port,
					"target": target,
				},
			})
		} else if record.kind == RecordKind::Caa {
			serde_json::json!({
				"type": kind,
				"name": record.name,
				"ttl": record.ttl,
				"data": Self::caa_data(&record.value)?,
			})
		} else if record.kind == RecordKind::Mx {
			// MX value: `<priority> <target>` — split into `priority` and
			// `host` fields per Cloudflare's MX data shape.
			let mut parts = record.value.split_whitespace();
			let priority: u8 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?
				.trim_end_matches('.')
				.to_string();
			serde_json::json!({
				"type": kind,
				"name": record.name,
				"ttl": record.ttl,
				"data": {
					"priority": priority,
					"host": target,
				},
			})
		} else {
			serde_json::json!({
				"type": kind,
				"name": record.name,
				"content": record.value,
				"ttl": record.ttl,
			})
		};
		value["comment"] = serde_json::Value::from(record_description());
		Ok(value)
	}

	/// The Cloudflare wire shape for a CAA record body: per
	/// <https://developers.cloudflare.com/api/operations/dns-records-create-dns-record>
	/// CAA uses a `data` object with `flags`, `tag` and `value`. We parse the
	/// presentation form `"<flags> <tag> <value>"` we emit.
	fn caa_data(value: &str) -> Result<serde_json::Value, ProviderError> {
		let mut parts = value.splitn(3, ' ');
		let flags: u8 = parts
			.next()
			.and_then(|p| p.parse().ok())
			.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?;
		let tag = parts
			.next()
			.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?
			.to_string();
		let v = parts
			.next()
			.ok_or_else(|| ProviderError::Remote("CAA needs flags tag value".into()))?
			.trim_matches('"')
			.to_string();
		Ok(serde_json::json!({
			"flags": flags,
			"tag": tag,
			"value": v,
		}))
	}

	/// Reject a record the token is not scoped for, before any network call.
	fn authorize(&self, record: &DnsRecord) -> Result<(), ProviderError> {
		if self.secret.authorizes(&record.name) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	async fn get_json<T: serde::de::DeserializeOwned>(
		&self,
		url: HttpsUrl,
	) -> Result<T, ProviderError> {
		let response = self
			.client
			.get(url.into_url())
			.bearer_auth(self.secret.token())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		decode(response).await
	}

	/// `{base}/zones/{zone_id}/dns_records[/{record_id}]`, each identifier
	/// escaped as one path segment.
	fn records_url(
		&self,
		zone_id: &str,
		record_id: Option<&str>,
	) -> Result<HttpsUrl, ProviderError> {
		let mut segments = vec!["zones", zone_id, "dns_records"];
		segments.extend(record_id);
		Ok(self.base.with_segments(segments)?)
	}

	async fn zone_id(&self, zone: &str) -> Result<String, ProviderError> {
		let url = self.base.with_segments(["zones"])?.with_query("name", zone);
		let zones: ListZones = self.get_json(url).await?;
		zones
			.result
			.into_iter()
			.next()
			.map(|z| z.id)
			.ok_or(ProviderError::Remote(format!("zone not found: {zone}")))
	}

	async fn find_record(
		&self,
		zone_id: &str,
		name: &str,
		kind: &str,
		value: Option<&str>,
	) -> Result<Option<RecordRef>, ProviderError> {
		let url = self
			.records_url(zone_id, None)?
			.with_query("type", kind)
			.with_query("name", name);
		let records: ListRecords = self.get_json(url).await?;
		// The TXT matching rule from `src/dns/provider.rs` is the
		// contract: a value-bearing delete drops only the record
		// whose content matches the value, and an upsert that
		// targets the same purpose finds the existing record by
		// the same rule. `same_txt_purpose` carries the contract:
		// two tagged values match when their tag is the same
		// (case-insensitive), two untagged values match only when
		// identical. A `None` value (the wholesale path) keeps
		// the first-by-(type, name) selection.
		Ok(records.result.into_iter().find(|r| match value {
			Some(v) => same_txt_purpose(&r.content, v),
			None => true,
		}))
	}

	async fn upsert_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let zone_id = self.zone_id(zone).await?;
		let body = Self::record_value(kind, &record)?;
		let existing = self
			.find_record(&zone_id, &record.name, kind, Some(&record.value))
			.await?;
		let operator_tags: Vec<String> = existing
			.as_ref()
			.map(|r| r.tags.clone())
			.unwrap_or_default();
		let url = self.records_url(&zone_id, existing.as_ref().map(|r| r.id.as_str()))?;
		let own = self
			.host_tag
			.as_deref()
			.filter(|_| self.tags_allowed.load(Ordering::Relaxed));
		let response = self
			.write(
				&url,
				existing.is_some(),
				&body,
				&cloudflare_tags::merge(&operator_tags, own),
			)
			.await?;
		if own.is_some() && retry_without_tags(response.status()) {
			let retry = self
				.write(
					&url,
					existing.is_some(),
					&body,
					&cloudflare_tags::merge(&operator_tags, None),
				)
				.await?;
			if retry.status().is_success() {
				self.tags_allowed.store(false, Ordering::Relaxed);
				tracing::warn!(
					"Cloudflare refused DNS record tags (they need a paid plan); records are written without them from now on"
				);
			}
			return decode_ok(retry).await;
		}
		decode_ok(response).await
	}

	/// Send one create (POST) or update (PUT) with `tags`; the body is
	/// `body` plus a `tags` array when there are any.
	async fn write(
		&self,
		url: &HttpsUrl,
		update: bool,
		body: &serde_json::Value,
		tags: &[String],
	) -> Result<reqwest::Response, ProviderError> {
		let mut body = body.clone();
		if !tags.is_empty() {
			body["tags"] = serde_json::Value::from(tags.to_vec());
		}
		let method = if update {
			reqwest::Method::PUT
		} else {
			reqwest::Method::POST
		};
		self.client
			.request(method, url.clone().into_url())
			.bearer_auth(self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body.to_string())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))
	}

	async fn delete_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let zone_id = self.zone_id(zone).await?;
		// The TXT matching rule from `src/dns/provider.rs` is the
		// contract: a value-bearing delete drops only the record
		// whose content matches the value (a sibling ACME challenge
		// at the same owner survives), an empty-value delete drops
		// every record at the owner (the DKIM rotator's retire
		// path). Other record kinds fall through to the
		// first-by-(type, name) selection, which is the existing
		// whole-set semantics.
		let needle = if record.kind == RecordKind::Txt {
			if record.value.is_empty() {
				None
			} else {
				Some(record.value.as_str())
			}
		} else {
			None
		};
		let Some(found) = self
			.find_record(&zone_id, &record.name, kind, needle)
			.await?
		else {
			return Ok(()); // already absent: idempotent.
		};
		let id = found.id;
		let response = self
			.client
			.delete(self.records_url(&zone_id, Some(&id))?.into_url())
			.bearer_auth(self.secret.token())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		decode_ok(response).await
	}

	async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		let zone_id = self.zone_id(zone).await?;
		let url = self.records_url(&zone_id, None)?;
		let records: ListRecords = self.get_json(url).await?;
		Ok(records
			.result
			.into_iter()
			.map(|r| DnsRecord {
				name: r.name,
				kind: parse_kind(&r.kind),
				value: r.content,
				ttl: r.ttl,
			})
			.collect())
	}
}

impl DnsProvider for CloudflareProvider {
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

/// Map a Cloudflare type token back to a [`RecordKind`], defaulting to TXT.
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

/// Whether a refused write may have been refused over its tags: a client
/// error that is not an auth failure or a rate limit. Cloudflare documents no
/// error code for tags on the Free plan, so the retry without tags decides.
fn retry_without_tags(status: reqwest::StatusCode) -> bool {
	status.is_client_error() && !matches!(status.as_u16(), 401 | 403 | 429)
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
async fn decode_ok(response: reqwest::Response) -> Result<(), ProviderError> {
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
#[path = "cloudflare_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "cloudflare_tests_path.rs"]
mod path_tests;
