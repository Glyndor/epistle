//! A deSEC (desec.io) DNS provider implementing [`DnsProvider`]. deSEC's API
//! is rrset-oriented: a single bulk `PUT /domains/{zone}/rrsets/` upserts (or,
//! with an empty `records` list, deletes) record sets, so no record-id or
//! zone-id lookup is needed. Authenticates with a zone-scoped API token.

use std::pin::Pin;

use serde::Deserialize;

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret};
use super::records::txt_strings;

/// deSEC's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://desec.io/api/v1";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A deSEC-backed DNS provider.
pub struct DesecProvider {
	client: reqwest::Client,
	secret: ScopedSecret,
	base: String,
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

	/// The record type token for a kind we can publish (deSEC handles each as
	/// an rrset; MX needs the priority split out into a separate field which
	/// epistle does not build yet).
	fn rrset_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
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

	/// deSEC stores TXT content as an array of quoted character strings
	/// (RFC 1035 §3.3.14), each at most 255 octets; other kinds use the
	/// value verbatim. A long value (an RSA-2048 DKIM `p=` runs ~410
	/// bytes, an RSA-4096 ~755) has to be split into ≤255-octet
	/// character-strings. But several entries would be several TXT
	/// records, a single rrset only stitches the character-strings
	/// into one logical value when they all belong to a single
	/// records entry. The wire form is one entry carrying the quoted
	/// pieces separated by single spaces. The per-piece backslash
	/// and quote escaping is applied to the chunk so a mid-chunk
	/// `\"` does not bleed across the boundary. Resolvers concatenate
	/// the pieces back into one logical value on read.
	fn record_content(kind: RecordKind, value: &str) -> Vec<String> {
		if kind == RecordKind::Txt {
			let joined = txt_strings(value)
				.into_iter()
				.map(|piece| {
					let escaped = piece.replace('\\', "\\\\").replace('"', "\\\"");
					format!("\"{escaped}\"")
				})
				.collect::<Vec<_>>()
				.join(" ");
			vec![joined]
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
		let kind = Self::rrset_kind(record.kind)?;
		let body = serde_json::json!([{
			"subname": self.subname(&record.name),
			"type": kind,
			"ttl": record.ttl.max(3600),
			"records": records,
		}])
		.to_string();
		let url = format!("{}/domains/{}/rrsets/", self.base, self.secret.zone());
		let response = self
			.client
			.put(url)
			.header(
				reqwest::header::AUTHORIZATION,
				format!("Token {}", self.secret.token()),
			)
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		check(response)
	}

	/// `GET /domains/{zone}/rrsets/` filtered to the rrset at
	/// `(name, kind)`. Returns the live wire form (records are
	/// quoted for TXT) so the value-bearing delete path can compare
	/// against the caller-supplied value after the same
	/// quote-stripping the upsert path uses.
	async fn fetch_rrset(&self, name: &str, kind: &str) -> Result<Option<Rrset>, ProviderError> {
		self.authorize_for(name)?;
		let url = format!("{}/domains/{}/rrsets/", self.base, self.secret.zone());
		let response = self
			.client
			.get(url)
			.header(
				reqwest::header::AUTHORIZATION,
				format!("Token {}", self.secret.token()),
			)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(ProviderError::Auth);
		}
		if !status.is_success() {
			return Err(ProviderError::Remote(format!("HTTP {status}")));
		}
		let text = response
			.text()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
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
		Box::pin(async move {
			let content = Self::record_content(record.kind, &record.value);
			self.put_rrset(&record, content).await
		})
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		let record_value = record.value.clone();
		Box::pin(async move {
			self.authorize(&record)?;
			let kind = Self::rrset_kind(record.kind)?;
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
			// Long TXT values are stored as one records entry with
			// the joined character-strings form, so the needle is
			// the same joined form on both the upsert and the
			// listing. The matching compares the joined value
			// verbatim against the records deSEC lists back.
			if record.kind == RecordKind::Txt && !record_value.is_empty() {
				let target = Self::record_content(RecordKind::Txt, &record_value)
					.into_iter()
					.next()
					.expect("TXT always produces one joined record");
				let remainder: Vec<String> = match self.fetch_rrset(&record.name, kind).await? {
					Some(rrset) => rrset.records.into_iter().filter(|r| r != &target).collect(),
					None => return Ok(()),
				};
				self.put_rrset(&record, remainder).await
			} else {
				self.put_rrset(&record, Vec::new()).await
			}
		})
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async move {
			let url = format!("{}/domains/{}/rrsets/", self.base, self.secret.zone());
			let response = self
				.client
				.get(url)
				.header(
					reqwest::header::AUTHORIZATION,
					format!("Token {}", self.secret.token()),
				)
				.send()
				.await
				.map_err(|e| ProviderError::Remote(e.to_string()))?;
			let status = response.status();
			if status == reqwest::StatusCode::UNAUTHORIZED
				|| status == reqwest::StatusCode::FORBIDDEN
			{
				return Err(ProviderError::Auth);
			}
			let text = response
				.text()
				.await
				.map_err(|e| ProviderError::Remote(e.to_string()))?;
			let rrsets: Vec<Rrset> =
				serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))?;
			Ok(rrsets
				.into_iter()
				.flat_map(|r| {
					let zone = self.secret.zone().to_string();
					let name = if r.subname.is_empty() {
						zone.clone()
					} else {
						format!("{}.{}", r.subname, zone)
					};
					let kind = parse_kind(&r.kind);
					r.records.into_iter().map(move |value| DnsRecord {
						name: name.clone(),
						kind,
						value: value.trim_matches('"').to_string(),
						ttl: r.ttl,
					})
				})
				.collect())
		})
	}
}

/// Map a deSEC type token to a [`RecordKind`], defaulting to TXT.
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
#[path = "desec_tests.rs"]
mod tests;
