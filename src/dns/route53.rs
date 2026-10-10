//! An AWS Route 53 DNS provider implementing [`DnsProvider`], signed with AWS
//! Signature Version 4 (no SDK dependency). Record changes go through
//! `ChangeResourceRecordSets` (UPSERT/DELETE) against a configured hosted zone;
//! `list` is not implemented (Route 53 returns XML we do not parse).

use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind};

/// Route 53 is a global service signed in `us-east-1`.
const REGION: &str = "us-east-1";
const SERVICE: &str = "route53";
const HOST: &str = "route53.amazonaws.com";
const API_VERSION: &str = "2013-04-01";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A Route 53-backed DNS provider for one hosted zone.
pub struct Route53Provider {
	client: reqwest::Client,
	access_key: String,
	secret_key: String,
	hosted_zone_id: String,
	base: String,
}

impl Route53Provider {
	/// Build a provider for `hosted_zone_id` with static credentials.
	pub fn new(access_key: String, secret_key: String, hosted_zone_id: String) -> Self {
		Route53Provider {
			client: reqwest::Client::new(),
			access_key,
			secret_key,
			hosted_zone_id,
			base: format!("https://{HOST}"),
		}
	}

	/// Point at an alternate endpoint (tests).
	pub fn with_base(mut self, base: impl Into<String>) -> Self {
		self.base = base.into();
		self
	}

	/// Submit a ChangeResourceRecordSets request with the given action.
	async fn change(&self, action: &str, record: &DnsRecord) -> Result<(), ProviderError> {
		let kind = record_type(record.kind)?;
		let value = if record.kind == RecordKind::Txt {
			// Route 53 stores TXT values quoted.
			format!(
				"\"{}\"",
				record.value.replace('\\', "\\\\").replace('"', "\\\"")
			)
		} else {
			record.value.clone()
		};
		let body = format!(
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/{API_VERSION}/\">\
<ChangeBatch><Changes><Change>\
<Action>{action}</Action>\
<ResourceRecordSet>\
<Name>{}</Name><Type>{kind}</Type><TTL>{}</TTL>\
<ResourceRecords><ResourceRecord><Value>{}</Value></ResourceRecord></ResourceRecords>\
</ResourceRecordSet></Change></Changes></ChangeBatch>\
</ChangeResourceRecordSetsRequest>",
			xml_escape(&record.name),
			record.ttl,
			xml_escape(&value),
		);

		let path = format!("/{API_VERSION}/hostedzone/{}/rrset", self.hosted_zone_id);
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default();
		let (amz_date, date) = timestamps(now.as_secs());
		let auth = self.authorization(&path, &body, &amz_date, &date);

		let response = self
			.client
			.post(format!("{}{path}", self.base))
			.header("x-amz-date", &amz_date)
			.header(reqwest::header::HOST, HOST)
			.header(reqwest::header::AUTHORIZATION, auth)
			.header(reqwest::header::CONTENT_TYPE, "application/xml")
			.body(body)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		let status = response.status();
		if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
			return Err(ProviderError::Auth);
		}
		if status.is_success() {
			Ok(())
		} else {
			Err(ProviderError::Remote(format!("HTTP {status}")))
		}
	}

	/// The SigV4 `Authorization` header for a POST with this body.
	fn authorization(&self, path: &str, body: &str, amz_date: &str, date: &str) -> String {
		let payload_hash = sha256_hex(body.as_bytes());
		// Host and x-amz-date are signed; headers must be sorted, lowercased.
		let canonical_headers = format!("host:{HOST}\nx-amz-date:{amz_date}\n");
		let signed_headers = "host;x-amz-date";
		let canonical_request =
			format!("POST\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
		let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
		let string_to_sign = format!(
			"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
			sha256_hex(canonical_request.as_bytes())
		);
		let sig = signature(&self.secret_key, date, REGION, SERVICE, &string_to_sign);
		format!(
			"AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={sig}",
			self.access_key
		)
	}

	/// SigV4 authorization for a GET (the same shape; the canonical
	/// request swaps `POST` for `GET`).
	fn authorization_get(&self, path: &str, body: &str, amz_date: &str, date: &str) -> String {
		let payload_hash = sha256_hex(body.as_bytes());
		let canonical_headers = format!("host:{HOST}\nx-amz-date:{amz_date}\n");
		let signed_headers = "host;x-amz-date";
		let canonical_request =
			format!("GET\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
		let scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
		let string_to_sign = format!(
			"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
			sha256_hex(canonical_request.as_bytes())
		);
		let sig = signature(&self.secret_key, date, REGION, SERVICE, &string_to_sign);
		format!(
			"AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={sig}",
			self.access_key
		)
	}

	/// `GET /2013-04-01/hostedzone/{id}/rrset` and return the first
	/// TXT rrset whose `<Name>` matches `name` (case-insensitive on
	/// the wire, AWS folds). The XML the API returns is parsed with
	/// a small hand-rolled reader because pulling in a full XML
	/// parser for one path is overkill; the response is well-formed
	/// by API contract.
	async fn fetch_txt_rrset(&self, name: &str) -> Result<Option<TxtRrset>, ProviderError> {
		let path = format!("/{API_VERSION}/hostedzone/{}/rrset", self.hosted_zone_id);
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default();
		let (amz_date, date) = timestamps(now.as_secs());
		let auth = self.authorization_get(&path, "", &amz_date, &date);
		let response = self
			.client
			.get(format!("{}{path}", self.base))
			.header("x-amz-date", &amz_date)
			.header(reqwest::header::HOST, HOST)
			.header(reqwest::header::AUTHORIZATION, auth)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		let status = response.status();
		if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
			return Err(ProviderError::Auth);
		}
		if !status.is_success() {
			return Err(ProviderError::Remote(format!("HTTP {status}")));
		}
		let text = response
			.text()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		Ok(parse_txt_rrset(&text, name))
	}

	/// UPSERT one rrset carrying the given values verbatim. Used by
	/// the value-bearing TXT delete to drop a single rdata and keep
	/// the siblings.
	async fn upsert_rrset(
		&self,
		name: &str,
		kind: &str,
		ttl: u32,
		values: &[String],
	) -> Result<(), ProviderError> {
		let path = format!("/{API_VERSION}/hostedzone/{}/rrset", self.hosted_zone_id);
		let value_xml: String = values
			.iter()
			.map(|v| {
				format!(
					"<ResourceRecord><Value>{}</Value></ResourceRecord>",
					xml_escape(v)
				)
			})
			.collect();
		let body = format!(
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<ChangeResourceRecordSetsRequest xmlns=\"https://route53.amazonaws.com/doc/{API_VERSION}/\">\
<ChangeBatch><Changes><Change>\
<Action>UPSERT</Action>\
<ResourceRecordSet>\
<Name>{}</Name><Type>{kind}</Type><TTL>{ttl}</TTL>\
<ResourceRecords>{value_xml}</ResourceRecords>\
</ResourceRecordSet></Change></Changes></ChangeBatch>\
</ChangeResourceRecordSetsRequest>",
			xml_escape(name),
		);
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default();
		let (amz_date, date) = timestamps(now.as_secs());
		let auth = self.authorization(&path, &body, &amz_date, &date);
		let response = self
			.client
			.post(format!("{}{path}", self.base))
			.header("x-amz-date", &amz_date)
			.header(reqwest::header::HOST, HOST)
			.header(reqwest::header::AUTHORIZATION, auth)
			.header(reqwest::header::CONTENT_TYPE, "application/xml")
			.body(body)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		let status = response.status();
		if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
			return Err(ProviderError::Auth);
		}
		if status.is_success() {
			Ok(())
		} else {
			Err(ProviderError::Remote(format!("HTTP {status}")))
		}
	}
}

/// A TXT rrset as the API returns it. `name` is the FQDN with the
/// trailing dot AWS always uses; `values` is the per-rdata wire
/// form (already quoted, no further wrapping needed).
#[derive(Debug)]
struct TxtRrset {
	name: String,
	kind: String,
	ttl: u32,
	values: Vec<String>,
}

/// Walk `LISTResourceRecordSetsResult` for the first `<ResourceRecordSet>`
/// whose `<Name>` matches `target` and whose `<Type>` is `TXT`. The
/// reader uses a lowercased view to find tag boundaries (the wire
/// form is case-insensitive) and slices the original `xml` to keep
/// the byte case of the values. The response is well-formed by API
/// contract.
fn parse_txt_rrset(xml: &str, target: &str) -> Option<TxtRrset> {
	let lower = xml.to_ascii_lowercase();
	let mut cursor = 0;
	loop {
		let rel_start = lower[cursor..].find("<resourcerecordset>")?;
		let abs = cursor + rel_start;
		let rel_end = lower[abs..].find("</resourcerecordset>")?;
		let end = abs + rel_end;
		let block_lower = &lower[abs..end];
		let name = extract_tag_lower(block_lower, "name")?;
		let kind = extract_tag_lower(block_lower, "type")?;
		let mut values: Vec<String> = Vec::new();
		let mut value_cursor = 0;
		while let Some(rel_value) = block_lower[value_cursor..].find("<value>") {
			let vstart = value_cursor + rel_value + "<value>".len();
			let rel_close = block_lower[vstart..].find("</value>")?;
			let vend = vstart + rel_close;
			// Slice the original XML (the lowercased view kept the
			// byte positions, but the bytes themselves are the
			// lowercased ones, slice the original instead).
			let abs_start = abs + vstart;
			let abs_end = abs + vend;
			values.push(xml[abs_start..abs_end].to_string());
			value_cursor = vend;
		}
		if kind.eq_ignore_ascii_case("TXT")
			&& name
				.trim_end_matches('.')
				.eq_ignore_ascii_case(target.trim_end_matches('.'))
		{
			let ttl: u32 = extract_tag_lower(block_lower, "ttl")
				.and_then(|s| s.parse().ok())
				.unwrap_or(300);
			return Some(TxtRrset {
				name,
				kind: "TXT".to_string(),
				ttl,
				values,
			});
		}
		cursor = end + "</resourcerecordset>".len();
	}
}

/// The text content of the first `<tag>...</tag>` in `block_lower`,
/// with both halves already lowercased. The caller picks the original
/// bytes from `xml` if it needs case preserved.
fn extract_tag_lower(block_lower: &str, tag: &str) -> Option<String> {
	let open = format!("<{tag}>");
	let close = format!("</{tag}>");
	let start = block_lower.find(&open)? + open.len();
	let end = block_lower[start..].find(&close)? + start;
	Some(block_lower[start..end].to_string())
}

impl DnsProvider for Route53Provider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move { self.change("UPSERT", &record).await })
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			// The TXT matching rule from `src/dns/provider.rs` is
			// the contract: a value-bearing delete drops only the
			// rdata whose value matches (a sibling ACME challenge
			// at the same owner survives), an empty-value delete
			// drops every rdata at the rrset (the DKIM rotator's
			// retire path). Other record kinds fall through to the
			// wholesale DELETE. Route 53's `DELETE` matches on
			// Name+Type only, so the value-bearing case LISTs the
			// rrset, drops the matching rdata, and UPSERTs the
			// remainder (a wholesale DELETE only when the rrset
			// is fully gone).
			if record.kind == RecordKind::Txt && !record.value.is_empty() {
				let needle = format!(
					"\"{}\"",
					record.value.replace('\\', "\\\\").replace('"', "\\\"")
				);
				if let Some(rrset) = self.fetch_txt_rrset(&record.name).await? {
					let remainder: Vec<String> = rrset
						.values
						.iter()
						.filter(|v| v.as_str() != needle.as_str())
						.cloned()
						.collect();
					if remainder.len() != rrset.values.len() {
						if remainder.is_empty() {
							self.change("DELETE", &record).await
						} else {
							self.upsert_rrset(&rrset.name, &rrset.kind, rrset.ttl, &remainder)
								.await
						}
					} else {
						// No rdata matched: idempotent, nothing to do.
						Ok(())
					}
				} else {
					Ok(())
				}
			} else {
				self.change("DELETE", &record).await
			}
		})
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		// Route 53 lists records as XML, which this provider does not parse.
		Box::pin(async move { Err(ProviderError::Unsupported) })
	}
}

/// The Route 53 record type for a kind we can publish. SRV, MX, and CAA
/// all use the same presentation form we emit (the value goes verbatim
/// into `<Value>`), which Route 53 accepts.
fn record_type(kind: RecordKind) -> Result<&'static str, ProviderError> {
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

/// `(YYYYMMDDTHHMMSSZ, YYYYMMDD)` for `epoch` seconds, UTC.
fn timestamps(epoch: u64) -> (String, String) {
	let days = epoch / 86_400;
	let secs = epoch % 86_400;
	let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
	let (y, mo, d) = civil_from_days(days as i64);
	(
		format!("{y:04}{mo:02}{d:02}T{h:02}{m:02}{s:02}Z"),
		format!("{y:04}{mo:02}{d:02}"),
	)
}

/// Convert a day count since the Unix epoch to a (year, month, day), using
/// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
	let z = z + 719_468;
	let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
	let doe = z - era * 146_097;
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let y = yoe + era * 400;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
	let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
	(if m <= 2 { y + 1 } else { y }, m, d)
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
	let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
	ring::hmac::sign(&k, data).as_ref().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
	hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().fold(String::new(), |mut acc, byte| {
		use std::fmt::Write;
		let _ = write!(acc, "{byte:02x}");
		acc
	})
}

/// The SigV4 signature: HMAC chain to derive the signing key, then sign.
fn signature(
	secret: &str,
	date: &str,
	region: &str,
	service: &str,
	string_to_sign: &str,
) -> String {
	let k_date = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
	let k_region = hmac(&k_date, region.as_bytes());
	let k_service = hmac(&k_region, service.as_bytes());
	let k_signing = hmac(&k_service, b"aws4_request");
	hex(&hmac(&k_signing, string_to_sign.as_bytes()))
}

/// Escape the XML special characters for safe interpolation.
fn xml_escape(value: &str) -> String {
	value
		.replace('&', "&amp;")
		.replace('<', "&lt;")
		.replace('>', "&gt;")
}

#[cfg(test)]
#[path = "route53_tests.rs"]
mod tests;
