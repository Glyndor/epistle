//! A Cloudflare DNS provider (RFC-less, vendor API) implementing
//! [`DnsProvider`]. It authenticates with a zone-scoped API token and supports
//! the record kinds epistle publishes — TXT/A/AAAA/CNAME via a `content` field
//! and TLSA via a structured `data` object; MX/SRV (priorities/weights) return
//! [`ProviderError::Unsupported`] for now.

use std::pin::Pin;

use serde::Deserialize;

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, parse_srv};

/// Cloudflare's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://api.cloudflare.com/client/v4";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A Cloudflare-backed DNS provider.
pub struct CloudflareProvider {
	client: reqwest::Client,
	secret: ScopedSecret,
	base: String,
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
}

impl CloudflareProvider {
	/// Build a provider for the token's zone.
	pub fn new(secret: ScopedSecret) -> Self {
		CloudflareProvider {
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

	/// The Cloudflare record type for a kind we can publish. TXT/A/AAAA/CNAME
	/// go through a plain `content` field; TLSA and SRV use a structured `data`
	/// object. MX (priority in `data.priority`) is not yet supported because
	/// the priority lives outside `content` and we have no caller emitting it
	/// — the only consumer (the SRV helper here) uses the same shape and
	/// already maps through `data`.
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

	/// The Cloudflare record body for a record: TLSA and SRV carry a
	/// structured `data` object (`usage selector matching_type certificate` /
	/// `priority weight port target`), everything else a plain `content`
	/// string. SRV splits the presentation form on whitespace.
	fn record_body(kind: &str, record: &DnsRecord) -> Result<String, ProviderError> {
		let value = if record.kind == RecordKind::Tlsa {
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
		} else {
			serde_json::json!({
				"type": kind,
				"name": record.name,
				"content": record.value,
				"ttl": record.ttl,
			})
		};
		Ok(value.to_string())
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
		url: &str,
	) -> Result<T, ProviderError> {
		let response = self
			.client
			.get(url)
			.bearer_auth(self.secret.token())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		decode(response).await
	}

	async fn zone_id(&self, zone: &str) -> Result<String, ProviderError> {
		let url = format!("{}/zones?name={zone}", self.base);
		let zones: ListZones = self.get_json(&url).await?;
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
	) -> Result<Option<String>, ProviderError> {
		let url = format!(
			"{}/zones/{zone_id}/dns_records?type={kind}&name={name}",
			self.base
		);
		let records: ListRecords = self.get_json(&url).await?;
		Ok(records.result.into_iter().next().map(|r| r.id))
	}

	async fn upsert_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let zone_id = self.zone_id(zone).await?;
		let body = Self::record_body(kind, &record)?;
		let existing = self.find_record(&zone_id, &record.name, kind).await?;
		let request = match &existing {
			Some(id) => self
				.client
				.put(format!("{}/zones/{zone_id}/dns_records/{id}", self.base)),
			None => self
				.client
				.post(format!("{}/zones/{zone_id}/dns_records", self.base)),
		};
		let response = request
			.bearer_auth(self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		decode_ok(response).await
	}

	async fn delete_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(record.kind)?;
		let zone_id = self.zone_id(zone).await?;
		let Some(id) = self.find_record(&zone_id, &record.name, kind).await? else {
			return Ok(()); // already absent: idempotent.
		};
		let response = self
			.client
			.delete(format!("{}/zones/{zone_id}/dns_records/{id}", self.base))
			.bearer_auth(self.secret.token())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		decode_ok(response).await
	}

	async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		let zone_id = self.zone_id(zone).await?;
		let url = format!("{}/zones/{zone_id}/dns_records", self.base);
		let records: ListRecords = self.get_json(&url).await?;
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
