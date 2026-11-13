//! A DigitalOcean DNS provider implementing [`DnsProvider`]. It authenticates
//! with a zone-scoped personal access token and uses the v2 REST API, where
//! each record carries a server-assigned integer `id`; upsert is read-then-
//! POST-or-PUT against `/v2/domains/{zone}/records/{id}`. MX/SRV need priority
//! fields the API exposes but the rest of epistle does not emit yet, so they
//! return [`ProviderError::Unsupported`].

use std::pin::Pin;

use serde::Deserialize;

use crate::dns::providers::{
	LIST_MAX_PAGES, LIST_MAX_RECORDS, inconsistent_pages, listing_too_long,
};
use crate::net::HttpsUrl;

use crate::dns::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, parse_srv, same_txt_purpose,
};
use crate::dns::providers::transport;
use crate::dns::publish::provider::{Change, ReceiptOp, SnapshotOp};
use crate::dns::txt::{TxtForm, same_txt_value, txt_decode, txt_encode};

/// How DigitalOcean takes a TXT `data` and lists it back; see `record_body`.
const TXT_FORM: TxtForm = TxtForm::Logical;

/// DigitalOcean's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://api.digitalocean.com";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A DigitalOcean-backed DNS provider.
pub struct DigitaloceanProvider {
	client: reqwest::Client,
	secret: ScopedSecret,
	base: HttpsUrl,
}

#[derive(Deserialize)]
struct ListResponse {
	domain_records: Vec<DomainRecord>,
	#[serde(default)]
	links: Links,
	#[serde(default)]
	meta: Meta,
}

#[derive(Deserialize, Default)]
struct Meta {
	/// How many records the whole listing holds.
	#[serde(default)]
	total: Option<usize>,
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
	/// The flags and the tag of a CAA; its `data` is the issuer alone.
	#[serde(default)]
	flags: Option<u8>,
	#[serde(default)]
	tag: Option<String>,
}

#[derive(Deserialize)]
struct Envelope {
	domain_record: DomainRecord,
}

impl DigitaloceanProvider {
	/// Build a provider for the token's zone.
	pub fn new(secret: ScopedSecret) -> Self {
		DigitaloceanProvider {
			client: crate::dns::providers::http_client(),
			secret,
			base: HttpsUrl::from_static(DEFAULT_BASE),
		}
	}

	/// Point the provider at an alternate API base (tests).
	pub fn with_base(mut self, base: HttpsUrl) -> Self {
		self.base = base;
		self
	}

	/// The DigitalOcean type token for a kind we can publish; SRV uses
	/// dedicated `priority`/`weight`/`port`/`data` fields, MX needs the
	/// priority split out (epistle still packs it into the value).
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

	/// `{base}/v2/domains/{zone}/records[/{id}]`, with the zone escaped as one
	/// path segment.
	fn records_url(&self, zone: &str, id: Option<u64>) -> Result<HttpsUrl, ProviderError> {
		let mut segments = vec!["v2".to_string(), "domains".to_string(), zone.to_string()];
		segments.push("records".to_string());
		segments.extend(id.map(|id| id.to_string()));
		Ok(self.base.with_segments(segments)?)
	}

	async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		let records = self.list_all(zone).await?;
		Ok(records.iter().filter_map(|r| record_of(zone, r)).collect())
	}
}

/// The record a listed entry stands for, read back into the shape the rest
/// of epistle uses; `None` for an entry that cannot be read as one (an SRV or
/// an MX without its priority).
fn record_of(zone: &str, r: &DomainRecord) -> Option<DnsRecord> {
	let name = if r.name == "@" {
		zone.to_string()
	} else {
		format!("{}.{}", r.name, zone)
	};
	let kind = RecordKind::from_token(&r.kind);
	let value = if kind == RecordKind::Srv {
		match (r.priority, r.weight, r.port) {
			(Some(p), Some(w), Some(port)) => {
				format!("{p} {w} {port} {}", r.data.trim_end_matches('.'))
			}
			_ => return None,
		}
	} else if kind == RecordKind::Mx {
		match r.priority {
			Some(p) => format!("{p} {}", r.data.trim_end_matches('.')),
			_ => return None,
		}
	} else if kind == RecordKind::Txt {
		txt_decode(&r.data, TXT_FORM)
	} else if kind == RecordKind::Caa && r.tag.is_some() {
		format!(
			"{} {} \"{}\"",
			r.flags.unwrap_or(0),
			r.tag.as_deref().unwrap_or_default(),
			r.data
		)
	} else {
		r.data.clone()
	};
	Some(DnsRecord {
		name,
		kind,
		value,
		ttl: r.ttl,
		proxied: None,
	})
}

impl DnsProvider for DigitaloceanProvider {
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let zone = zone.to_string();
		Box::pin(crate::dns::providers::within(async move {
			self.upsert_inner(&zone, record).await
		}))
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let zone = zone.to_string();
		Box::pin(crate::dns::providers::within(async move {
			self.delete_inner(&zone, record).await
		}))
	}
	fn delete_exact(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let zone = zone.to_string();
		Box::pin(crate::dns::providers::within(async move {
			self.delete_exact_inner(&zone, record).await
		}))
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone = zone.to_string();
		let zone_name = zone.to_string();
		Box::pin(crate::dns::providers::listing(zone_name, async move {
			self.list_inner(&zone).await
		}))
	}
	fn publish_snapshot<'a>(&'a self, zone: &'a str) -> SnapshotOp<'a> {
		Box::pin(crate::dns::providers::within(self.snapshot_inner(zone)))
	}
	fn apply_guarded<'a>(&'a self, zone: &'a str, change: Change) -> ReceiptOp<'a> {
		Box::pin(crate::dns::providers::guarded::apply(self, zone, change))
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
	let text = crate::dns::providers::read_body(response).await?;
	serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))
}

mod guarded;
mod pages;
mod requests;
mod write;

mod exact;

#[cfg(test)]
mod tests;
