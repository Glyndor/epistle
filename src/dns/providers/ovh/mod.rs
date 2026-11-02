//! An OVH (ovh.com) DNS provider implementing [`DnsProvider`]. OVH
//! authenticates every call with a triple — `application_key`,
//! `application_secret` and `consumer_key` — and an `X-Ovh-Signature` header
//! (SHA-1 over the request line and body). Records are addressable by numeric
//! id; `upsert` lists, updates if one already matches, otherwise creates,
//! then triggers a `/refresh` so the zone actually publishes.

use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::dns::providers::{LIST_MAX_RECORDS, inconsistent_pages, listing_too_long};
use crate::net::{HttpsUrl, HttpsUrlError};

use crate::dns::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, same_txt_purpose,
	unwrap_quotes,
};
use crate::dns::providers::transport;
use crate::dns::txt::{TxtForm, txt_decode, txt_encode};

/// How OVH takes a TXT `target` (logical) and lists it back (quoted and
/// split, which `txt_decode` reads either way); see `upsert_inner`.
const TXT_FORM: TxtForm = TxtForm::Logical;

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
	base: HttpsUrl,
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
			client: crate::dns::providers::http_client(),
			application_key,
			application_secret,
			consumer_secret,
			base: HttpsUrl::from_static(DEFAULT_BASE),
		}
	}

	/// Point the provider at an alternate API base (tests, or a regional
	/// override via the `endpoint` config key).
	pub fn with_base(mut self, base: HttpsUrl) -> Self {
		self.base = base;
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

	/// `{base}/domain/zone/{zone}/<tail...>`, with the zone and every tail
	/// segment escaped as one path segment.
	fn zone_url(&self, zone: &str, tail: &[&str]) -> Result<HttpsUrl, ProviderError> {
		let mut segments = vec!["domain", "zone", zone];
		segments.extend_from_slice(tail);
		Ok(self.base.with_segments(segments)?)
	}

	/// `{base}/domain/zone/{zone}/record` filtered by `fieldType` and
	/// `subDomain`.
	fn find_url(&self, zone: &str, kind: &str, sub: &str) -> Result<HttpsUrl, ProviderError> {
		Ok(self
			.zone_url(zone, &["record"])?
			.with_query("fieldType", kind)
			.with_query("subDomain", sub))
	}

	/// The OVH fieldType token for a kind we publish.
	fn api_kind(kind: &RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A => Ok("A"),
			RecordKind::Aaaa => Ok("AAAA"),
			RecordKind::Txt => Ok("TXT"),
			RecordKind::Cname => Ok("CNAME"),
			RecordKind::Mx => Ok("MX"),
			RecordKind::Srv => Ok("SRV"),
			RecordKind::Caa => Ok("CAA"),
			RecordKind::Tlsa => Err(ProviderError::Unsupported),
			RecordKind::Ns | RecordKind::Https | RecordKind::Svcb | RecordKind::Other(_) => {
				Err(ProviderError::Unsupported)
			}
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

	/// Fetch every record under the zone. The OVH list endpoint only
	/// returns ids, so we fan out one detail GET per id.
	async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		let url = self.zone_url(zone, &["record"])?;
		let ids: Vec<u64> = self.send_json(reqwest::Method::GET, &url, "").await?;
		// One request per id follows, so the cap is checked before any.
		if ids.len() > LIST_MAX_RECORDS {
			return Err(listing_too_long(zone));
		}
		let mut records = Vec::with_capacity(ids.len());
		for id in ids {
			// A record the list names and the detail denies is a listing that
			// does not add up, not a shorter zone.
			let Some(rec) = self.get_record(zone, id).await? else {
				return Err(inconsistent_pages(zone));
			};
			records.push(record_from_ovh(&rec, zone));
		}
		Ok(records)
	}
}

impl DnsProvider for OvhProvider {
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
	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone = zone.to_string();
		let zone_name = zone.to_string();
		Box::pin(crate::dns::providers::listing(zone_name, async move {
			self.list_inner(&zone).await
		}))
	}
}

/// Convert an OVH record to a [`DnsRecord`], reconstructing the FQDN and
/// reading a TXT target, which OVH lists quoted and split, back to its
/// logical value.
fn record_from_ovh(rec: &OvhRecord, zone: &str) -> DnsRecord {
	let name = if rec.sub_domain.is_empty() {
		zone.to_string()
	} else {
		format!("{}.{}", rec.sub_domain, zone)
	};
	let kind = RecordKind::from_token(&rec.field_type);
	let is_txt = kind == RecordKind::Txt;
	DnsRecord {
		name,
		kind,
		value: if is_txt {
			txt_decode(&rec.target, TXT_FORM)
		} else {
			unwrap_quotes(&rec.target).to_string()
		},
		ttl: rec.ttl,
		proxied: None,
	}
}

/// Resolve an endpoint alias (or full URL) to a concrete API base. Unknown
/// aliases fall back to the European endpoint, OVH's default. Used by
/// `config::dns` to map `endpoint = "ovh-ca"` to the URL the provider is
/// pointed at. A full URL must be `https`: the application key, the consumer
/// key and the request signature travel with every call, so a cleartext
/// endpoint is refused instead of used.
pub fn resolve_base(endpoint: Option<&str>) -> Result<HttpsUrl, HttpsUrlError> {
	let Some(endpoint) = endpoint else {
		return Ok(HttpsUrl::from_static(DEFAULT_BASE));
	};
	if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
		return HttpsUrl::parse(endpoint);
	}
	let url = ENDPOINTS
		.iter()
		.find(|(alias, _)| *alias == endpoint)
		.map_or(DEFAULT_BASE, |(_, url)| url);
	HttpsUrl::parse(url)
}

/// Map a response status to success / typed error. Returns `Ok(())` when the
/// caller is going to ignore the body.
fn check_status(response: &reqwest::Response, zone: Option<&str>) -> Result<(), ProviderError> {
	let status = response.status();
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return Err(ProviderError::Auth);
	}
	if status == reqwest::StatusCode::NOT_FOUND
		&& let Some(zone) = zone
	{
		// OVH answers 404 for a zone it does not hold: the zone is not
		// there, which is not a failure of the provider, and the search
		// goes on to the parent.
		return Err(ProviderError::ZoneNotFound(zone.to_string()));
	}
	if !status.is_success() {
		return Err(ProviderError::Remote(format!("HTTP {status}")));
	}
	Ok(())
}

/// The zone an OVH URL is about, when the URL addresses the zone's records:
/// `/domain/zone/{zone}/record`. Every call that names the zone does it
/// that way, and a 404 there says the zone is not there. A URL about one
/// record (`/domain/zone/{zone}/record/{id}`) says nothing about the zone:
/// a 404 there is about that record.
///
/// The path is read relative to the base the provider was pointed at, because
/// the real endpoints carry a version prefix (`/1.0`) that the paths of the
/// API start after. A URL outside that base, or one whose path does not
/// address the records of a zone, says nothing about any zone.
fn zone_of(base: &HttpsUrl, url: &HttpsUrl) -> Option<String> {
	let rest = relative_path(base, url)?;
	let rest = rest.strip_prefix("/domain/zone/")?;
	let (zone, tail) = rest.split_once('/')?;
	if tail != "record" {
		return None;
	}
	// The zone travelled through the URL percent-encoded. The error names
	// the zone the operation asked for, not the encoded form of it.
	let zone = percent_encoding::percent_decode_str(zone)
		.decode_utf8()
		.ok()?;
	(!zone.is_empty()).then(|| zone.into_owned())
}

/// The path of `url` relative to the base it was built from. The base of
/// OVH ends in `/1.0`, so the path of a request reads
/// `/1.0/domain/zone/{zone}/record` and the version prefix has to come off
/// before the rest of the path can be read. A URL that does not start with
/// the path of the base is not one of ours and has no relative path.
fn relative_path<'a>(base: &HttpsUrl, url: &'a HttpsUrl) -> Option<&'a str> {
	let prefix = base.as_url().path().trim_end_matches('/');
	let path = url.as_url().path();
	if prefix.is_empty() {
		return Some(path);
	}
	let rest = path.strip_prefix(prefix)?;
	// `/1.0` must not match the start of `/1.0something`.
	if rest.is_empty() || rest.starts_with('/') {
		Some(rest)
	} else {
		None
	}
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

mod transport;
mod write;

#[cfg(test)]
mod tests;
