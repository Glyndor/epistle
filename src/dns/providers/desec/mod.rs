//! A deSEC (desec.io) DNS provider implementing [`DnsProvider`]. deSEC's API
//! is rrset-oriented: a single bulk `PUT /domains/{zone}/rrsets/` upserts (or,
//! with an empty `records` list, deletes) record sets, so no record-id or
//! zone-id lookup is needed. Authenticates with a zone-scoped API token.

use std::pin::Pin;

use serde::Deserialize;

use crate::net::HttpsUrl;

use crate::dns::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, same_txt_purpose,
};
use crate::dns::providers::{
	LIST_MAX_PAGES, LIST_MAX_RECORDS, inconsistent_pages, listing_too_long, transport,
};
use crate::dns::txt::{TxtForm, same_txt_value, txt_decode, txt_encode};

/// How deSEC wants a TXT value written and lists it back; see
/// `record_content`.
const TXT_FORM: TxtForm = TxtForm::Presentation;

/// deSEC's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://desec.io/api/v1";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A deSEC-backed DNS provider.
pub struct DesecProvider {
	client: reqwest::Client,
	secret: ScopedSecret,
	base: HttpsUrl,
}

#[derive(Deserialize)]
struct Rrset {
	#[serde(default)]
	subname: String,
	#[serde(rename = "type", default)]
	kind: String,
	#[serde(default)]
	records: Vec<String>,
	#[serde(default)]
	ttl: u32,
}

impl DesecProvider {
	/// Build a provider for the token's zone.
	pub fn new(secret: ScopedSecret) -> Self {
		DesecProvider {
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

	/// `{base}/domains/{zone}/rrsets/`, with the zone escaped as one segment.
	fn rrsets_url(&self) -> Result<HttpsUrl, ProviderError> {
		Ok(self
			.base
			.with_segments(["domains", self.secret.zone(), "rrsets", ""])?)
	}

	/// The record type token for a kind we can publish (deSEC handles each as
	/// an rrset; MX needs the priority split out into a separate field which
	/// epistle does not build yet).
	fn rrset_kind(kind: &RecordKind) -> Result<&'static str, ProviderError> {
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

	/// The subname (label relative to the zone): the name with the trailing
	/// `.zone` removed; the apex is the empty string.
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

	/// deSEC takes every record in presentation format, and a TXT must be
	/// quoted: "The contents of the TXT record must be enclosed in double
	/// quotes" and "Records must be given in presentation format"
	/// (<https://desec.readthedocs.io/en/latest/dns/rrsets.html>, read
	/// 2026-10-12). Each `records` entry is a separate TXT record, so a long
	/// value goes as ONE entry carrying its 255-octet character-strings
	/// separated by spaces; several entries would be several records, which
	/// no DKIM verifier stitches back together. deSEC lists the canonical
	/// form, the same quoted strings, and reads `\DDD` as decimal (RFC 1035
	/// §5.1), which is [`TXT_FORM`]. Other kinds go verbatim.
	fn record_content(kind: &RecordKind, value: &str) -> Vec<String> {
		if kind == &RecordKind::Txt {
			vec![txt_encode(value, TXT_FORM)]
		} else {
			vec![value.to_string()]
		}
	}

	/// Reject a record outside the token's zone before any network call.
	fn authorize(&self, record: &DnsRecord) -> Result<(), ProviderError> {
		if self.secret.authorizes(&record.name) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	/// Bulk PUT one rrset (an empty `records` list deletes it).
	async fn put_rrset(
		&self,
		record: &DnsRecord,
		records: Vec<String>,
	) -> Result<(), ProviderError> {
		self.authorize(record)?;
		let kind = Self::rrset_kind(&record.kind)?;
		let body = serde_json::json!([{
			"subname": self.subname(&record.name),
			"type": kind,
			"ttl": record.ttl.max(3600),
			"records": records,
		}])
		.to_string();
		let url = self.rrsets_url()?;
		let response = self
			.client
			.put(url.into_url())
			.header(
				reqwest::header::AUTHORIZATION,
				format!("Token {}", self.secret.token()),
			)
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		check(response)
	}

	/// `GET /domains/{zone}/rrsets/` filtered to the rrset at
	/// `(name, kind)`. Returns the records as deSEC lists them
	/// (presentation form for TXT); the value-bearing delete compares
	/// them with the caller's value through `same_txt_value`.
	async fn fetch_rrset(&self, name: &str, kind: &str) -> Result<Option<Rrset>, ProviderError> {
		self.authorize_for(name)?;
		let url = self.rrsets_url()?;
		let response = self
			.client
			.get(url.into_url())
			.header(
				reqwest::header::AUTHORIZATION,
				format!("Token {}", self.secret.token()),
			)
			.send()
			.await
			.map_err(transport)?;
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(ProviderError::Auth);
		}
		if !status.is_success() {
			return Err(ProviderError::Remote(format!("HTTP {status}")));
		}
		let text = crate::dns::providers::read_body(response).await?;
		let rrsets: Vec<Rrset> =
			serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))?;
		let sub = self.subname(name);
		Ok(rrsets
			.into_iter()
			.find(|r| r.subname == sub && r.kind.eq_ignore_ascii_case(kind)))
	}

	/// Reject a name the secret is not scoped for, before any
	/// network call. The existing `authorize` takes a `&DnsRecord`;
	/// `fetch_rrset` only has the FQDN, so it uses this thin shim.
	fn authorize_for(&self, name: &str) -> Result<(), ProviderError> {
		if self.secret.authorizes(name) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}
}

impl DnsProvider for DesecProvider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(crate::dns::providers::within(async move {
			let mut content = Self::record_content(&record.kind, &record.value);
			// The bulk PUT replaces the whole rrset. The upsert contract
			// in `src/dns/provider.rs` replaces only the TXT of the same
			// purpose, so the siblings the live rrset holds go back in.
			if record.kind == RecordKind::Txt {
				self.authorize(&record)?;
				let kind = Self::rrset_kind(&record.kind)?;
				if let Some(rrset) = self.fetch_rrset(&record.name, kind).await? {
					let siblings = rrset
						.records
						.into_iter()
						.filter(|r| !same_txt_purpose(r, &record.value));
					content = siblings.chain(content).collect();
				}
			}
			self.put_rrset(&record, content).await
		}))
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		let record_value = record.value.clone();
		Box::pin(crate::dns::providers::within(async move {
			self.authorize(&record)?;
			let kind = Self::rrset_kind(&record.kind)?;
			// The TXT matching rule from `src/dns/provider.rs` is
			// the contract: a value-bearing delete drops only the
			// record whose content matches the value (a sibling ACME
			// challenge at the same owner survives), an empty-value
			// delete drops every record at the owner (the DKIM
			// rotator's retire path). Other record kinds fall
			// through to the wholesale path. deSEC's bulk PUT
			// replaces the rrset, so the value-bearing case reads
			// the live rrset, removes the matching record, and
			// PUTs the remainder (or an empty list when the rrset
			// is fully gone).
			//
			// The match is on the logical value, so a record deSEC
			// re-chunked or re-escaped in its canonical form is still
			// found.
			if record.kind == RecordKind::Txt && !record_value.is_empty() {
				let remainder: Vec<String> = match self.fetch_rrset(&record.name, kind).await? {
					Some(rrset) => rrset
						.records
						.into_iter()
						.filter(|r| !same_txt_value(r, &record_value))
						.collect(),
					None => return Ok(()),
				};
				self.put_rrset(&record, remainder).await
			} else {
				self.put_rrset(&record, Vec::new()).await
			}
		}))
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone_name = zone.to_string();
		Box::pin(crate::dns::providers::listing(zone_name, async move {
			// deSEC answers 400 to a list past 500 rrsets unless the request
			// asks for a page; an empty `cursor` asks for the first, and the
			// `Link` header of each page names the next one.
			let mut url = self.rrsets_url()?.with_query("cursor", "");
			let mut rrsets: Vec<Rrset> = Vec::new();
			let mut pages = 0;
			let mut records = 0;
			loop {
				let response = self
					.client
					.get(url.clone().into_url())
					.header(
						reqwest::header::AUTHORIZATION,
						format!("Token {}", self.secret.token()),
					)
					.send()
					.await
					.map_err(transport)?;
				let status = response.status();
				if status == reqwest::StatusCode::UNAUTHORIZED
					|| status == reqwest::StatusCode::FORBIDDEN
				{
					return Err(ProviderError::Auth);
				}
				if !status.is_success() {
					return Err(ProviderError::Remote(format!("HTTP {status}")));
				}
				let links: Vec<&str> = response
					.headers()
					.get_all(reqwest::header::LINK)
					.iter()
					.filter_map(|value| value.to_str().ok())
					.collect();
				let next = links.iter().find_map(|value| next_link(value));
				// A Link that mentions a next page nobody could read is a
				// listing cut short, not a listing that ended.
				if next.is_none()
					&& links
						.iter()
						.any(|value| value.to_ascii_lowercase().contains("next"))
				{
					return Err(inconsistent_pages(self.secret.zone()));
				}
				let text = crate::dns::providers::read_body(response).await?;
				let page: Vec<Rrset> = serde_json::from_str(&text)
					.map_err(|e| ProviderError::Remote(e.to_string()))?;
				// An rrset with no records still costs memory: it counts as one.
				records += page.iter().map(|r| r.records.len().max(1)).sum::<usize>();
				rrsets.extend(page);
				if records > LIST_MAX_RECORDS {
					return Err(listing_too_long(self.secret.zone()));
				}
				let Some(next) = next else { break };
				pages += 1;
				if pages >= LIST_MAX_PAGES {
					return Err(listing_too_long(self.secret.zone()));
				}
				url = self.base.follow(&next)?;
			}
			Ok(rrsets
				.into_iter()
				.flat_map(|r| {
					let zone = self.secret.zone().to_string();
					let name = if r.subname.is_empty() {
						zone.clone()
					} else {
						format!("{}.{}", r.subname, zone)
					};
					let kind = RecordKind::from_token(&r.kind);
					r.records.into_iter().map(move |value| {
						let kind_for_value = &kind;
						DnsRecord {
							name: name.clone(),
							kind: kind.clone(),
							value: if kind_for_value == &RecordKind::Txt {
								txt_decode(&value, TXT_FORM)
							} else {
								value
							},
							ttl: r.ttl,
							proxied: None,
						}
					})
				})
				.collect())
		}))
	}
}

/// The target of the `rel="next"` entry of a `Link` header value
/// (`<url>; rel="next", <url>; rel="first"`), if it has one. Entries start at
/// each `<`, so a comma inside a URL does not split it, and `rel` may list
/// several relations (`rel="prev next"`).
fn next_link(header: &str) -> Option<String> {
	let mut rest = header;
	while let Some(start) = rest.find('<') {
		let after = &rest[start + 1..];
		let end = after.find('>')?;
		let target = &after[..end];
		let tail = &after[end + 1..];
		let params = &tail[..tail.find('<').unwrap_or(tail.len())];
		let is_next = params.split(';').any(|param| {
			let param = param.trim().trim_end_matches(',').trim();
			param.split_once('=').is_some_and(|(key, value)| {
				key.trim().eq_ignore_ascii_case("rel")
					&& value
						.trim()
						.trim_matches('"')
						.split_whitespace()
						.any(|relation| relation.eq_ignore_ascii_case("next"))
			})
		});
		if is_next {
			return Some(target.to_string());
		}
		rest = tail;
	}
	None
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
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests_path.rs"]
mod path_tests;
