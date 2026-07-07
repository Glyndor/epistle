//! A deSEC (desec.io) DNS provider implementing [`DnsProvider`]. deSEC's API
//! is rrset-oriented: a single bulk `PUT /domains/{zone}/rrsets/` upserts (or,
//! with an empty `records` list, deletes) record sets, so no record-id or
//! zone-id lookup is needed. Authenticates with a zone-scoped API token.

use std::pin::Pin;

use serde::Deserialize;

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret};

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

	/// The record type token for a kind we can publish (deSEC handles each as an
	/// rrset; MX/SRV need priority/weight handling we do not emit yet).
	fn rrset_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A
			| RecordKind::Aaaa
			| RecordKind::Txt
			| RecordKind::Cname
			| RecordKind::Tlsa => Ok(kind.as_str()),
			RecordKind::Mx | RecordKind::Srv => Err(ProviderError::Unsupported),
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

	/// deSEC stores TXT content quoted; other kinds use the value verbatim.
	fn record_content(kind: RecordKind, value: &str) -> String {
		if kind == RecordKind::Txt {
			format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
		} else {
			value.to_string()
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
}

impl DnsProvider for DesecProvider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			let content = Self::record_content(record.kind, &record.value);
			self.put_rrset(&record, vec![content]).await
		})
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move { self.put_rrset(&record, Vec::new()).await })
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
