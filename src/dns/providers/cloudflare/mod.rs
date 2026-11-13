//! A Cloudflare DNS provider (RFC-less, vendor API) implementing
//! [`DnsProvider`]. It authenticates with a zone-scoped API token and supports
//! the record kinds epistle publishes — TXT/A/AAAA/CNAME via a `content` field
//! and TLSA via a structured `data` object; MX/SRV (priorities/weights) return
//! [`ProviderError::Unsupported`] for now.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Deserialize;

use crate::net::HttpsUrl;

mod check;
mod list;
mod tags;
use crate::dns::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, ZoneOp, parse_srv,
	record_description, same_txt_purpose,
};
use crate::dns::providers::transport;
use crate::dns::publish::provider::{Change, ReceiptOp, SnapshotOp};
use crate::dns::txt::{TxtForm, txt_encode};
use tags as cloudflare_tags;

/// How Cloudflare wants a TXT `content` written and lists it back; see
/// `record_value`.
const TXT_FORM: TxtForm = TxtForm::Presentation;

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
	/// Whether the reply is an answer at all. Cloudflare says it failed
	/// in the same envelope a successful answer uses, with an empty
	/// result, so the flag is what tells the two apart.
	success: bool,
	result: Vec<ZoneRef>,
}

#[derive(Deserialize)]
struct ZoneRef {
	id: String,
}

#[derive(Deserialize)]
struct ListRecords {
	result: Vec<RecordRef>,
	/// Paging: `total_pages` says how many pages the list has.
	#[serde(default)]
	result_info: Option<ResultInfo>,
}

#[derive(Deserialize)]
struct ResultInfo {
	#[serde(default)]
	total_pages: Option<u32>,
	/// How many records the whole listing holds.
	#[serde(default)]
	total_count: Option<usize>,
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
	/// Whether the record is proxied through Cloudflare's orange cloud. Only
	/// present for the record kinds Cloudflare can proxy (A, AAAA, CNAME); other
	/// kinds do not return the field and `None` means "not applicable".
	#[serde(default)]
	proxied: Option<bool>,
	/// The MX preference; Cloudflare lists it apart from the target.
	#[serde(default)]
	priority: Option<u16>,
}

impl CloudflareProvider {
	/// Build a provider for the token's zone.
	pub fn new(secret: ScopedSecret) -> Self {
		CloudflareProvider {
			client: crate::dns::providers::http_client(),
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
			.map_err(transport)?;
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

	/// The id of the zone named `zone`, or `None` when the account holds
	/// no zone with that name. The lookup is an exact match, so a name
	/// below a zone (`mail.example.org`) is not a zone of its own.
	async fn find_zone_id(&self, zone: &str) -> Result<Option<String>, ProviderError> {
		let url = self.base.with_segments(["zones"])?.with_query("name", zone);
		let zones: ListZones = self.get_json(url).await?;
		if !zones.success {
			// The reply says it failed: the empty result it carries
			// says nothing about the zone, and the zone is not absent.
			return Err(ProviderError::Remote(
				"Cloudflare answered that the zone lookup failed".into(),
			));
		}
		Ok(zones.result.into_iter().next().map(|z| z.id))
	}

	async fn zone_id(&self, zone: &str) -> Result<String, ProviderError> {
		self.find_zone_id(zone)
			.await?
			.ok_or_else(|| ProviderError::ZoneNotFound(zone.to_string()))
	}

	async fn find_record(
		&self,
		zone_id: &str,
		name: &str,
		kind: &str,
		value: Option<&str>,
	) -> Result<Option<RecordRef>, ProviderError> {
		// The TXT matching rule from `src/dns/provider/mod.rs` is the
		// contract: a value-bearing delete drops only the record
		// whose content matches the value. `same_txt_purpose` carries
		// it: two tagged values match when their tag is the same
		// (case-insensitive), two untagged values match only when
		// identical. A `None` value (the wholesale path) keeps the
		// first-by-(type, name) selection.
		Ok(self
			.find_records(zone_id, name, kind)
			.await?
			.into_iter()
			.find(|r| match value {
				Some(v) => same_txt_purpose(&r.content, v),
				None => true,
			}))
	}

	/// Every record of `kind` at `name`.
	async fn find_records(
		&self,
		zone_id: &str,
		name: &str,
		kind: &str,
	) -> Result<Vec<RecordRef>, ProviderError> {
		let url = self
			.records_url(zone_id, None)?
			.with_query("type", kind)
			.with_query("name", name);
		let records: ListRecords = self.get_json(url).await?;
		Ok(records.result)
	}
}

impl DnsProvider for CloudflareProvider {
	/// Cloudflare flattens a CNAME at the apex and accepts other record
	/// types next to it.
	fn flattens_apex_cname(&self, _zone: &str) -> bool {
		true
	}
	fn check_access<'a>(
		&'a self,
		_: &'a str,
		names: &'a [String],
	) -> crate::dns::providers::check::CheckOp<'a> {
		Box::pin(async move {
			crate::dns::providers::within(self.check_inner(names))
				.await
				.unwrap_or_else(|error| {
					crate::dns::providers::check::AccessReport::failed(
						crate::dns::providers::check::failure_cause(&error),
					)
				})
		})
	}
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
		Box::pin(self.apply_guarded_inner(zone, change))
	}
	fn has_zone(&self, zone: &str) -> ZoneOp<'_> {
		let zone = zone.to_string();
		Box::pin(crate::dns::providers::within(async move {
			// The zone lookup answers the question on its own: it reads
			// one zone by name, not the records of a zone.
			Ok(self.find_zone_id(&zone).await?.is_some())
		}))
	}
}

/// Whether a refused write may have been refused over its tags: a client
/// error that is not an auth failure or a rate limit. Cloudflare documents no
/// error code for tags on the Free plan, so the retry without tags decides.
fn retry_without_tags(status: reqwest::StatusCode) -> bool {
	status.is_client_error() && !matches!(status.as_u16(), 401 | 403 | 429)
}

/// Decode a JSON body, mapping a 401/403 to an auth error and every other
/// unsuccessful status to a remote error, before the body is read at all: a
/// reply that is not an answer never gets to be one.
async fn decode<T: serde::de::DeserializeOwned>(
	response: reqwest::Response,
) -> Result<T, ProviderError> {
	let status = response.status();
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return Err(ProviderError::Auth);
	}
	if !status.is_success() {
		return Err(ProviderError::Remote(format!("HTTP {status}")));
	}
	let text = crate::dns::providers::read_body(response).await?;
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

mod guarded;
mod record;
mod write;

mod exact;

#[cfg(test)]
mod tests;
