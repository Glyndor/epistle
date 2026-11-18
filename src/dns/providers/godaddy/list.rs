//! Zone listing and conversion from GoDaddy wire records.

use serde::Deserialize;

use crate::dns::provider::{DnsRecord, ProviderError, RecordKind};
use crate::dns::providers::transport;
use crate::dns::txt::txt_decode;

use super::GodaddyProvider;
use super::errors::auth_error;
use super::records::TXT_FORM;

/// One record as `GET /domains/{domain}/records/{type}/{name}` returns it. MX
/// and SRV add the dedicated fields GoDaddy stores; the others are `None`
/// for non-applicable kinds. `service` and `protocol` are part of the SRV
/// wire shape but epistle does not build them today, they sit on the struct
/// so the deserializer does not drop the rest of the record on a known-shape
/// field.
#[derive(Deserialize)]
struct Record {
	#[serde(default)]
	name: String,
	#[serde(rename = "type", default)]
	kind: String,
	#[serde(default)]
	data: String,
	#[serde(default)]
	ttl: u32,
	#[serde(default)]
	priority: Option<u16>,
	#[serde(default)]
	weight: Option<u16>,
	#[serde(default)]
	port: Option<u16>,
	#[allow(dead_code)]
	#[serde(default)]
	service: Option<String>,
	#[allow(dead_code)]
	#[serde(default)]
	protocol: Option<String>,
}

impl GodaddyProvider {
	pub(super) async fn list_inner(&self) -> Result<Vec<DnsRecord>, ProviderError> {
		// GoDaddy does not paginate `GET /domains/{domain}/records`, the
		// zone-wide endpoint returns the full set. We read the whole
		// thing and filter to the kinds the provider publishes.
		let url = self.records_url(None)?;
		let path = url.as_url().path().to_string();
		let response = self
			.client
			.get(url.into_url())
			.header(reqwest::header::AUTHORIZATION, self.auth_header())
			.send()
			.await
			.map_err(transport)?;
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(auth_error(status));
		}
		if !status.is_success() {
			return Err(ProviderError::Remote(format!("HTTP {status}")));
		}
		let text = crate::dns::providers::read_body(response).await?;
		// The body is not echoed into the error: a 200 with a
		// diagnostic body (the response from a misbehaving gateway) can
		// carry credentials that belong in the `Authorization` header we
		// just sent, and serde's type-error text quotes the bytes that
		// failed to parse. `Display`/`Debug` on `ProviderError::Remote`
		// exposes the string verbatim to operators. The path and the
		// body shape (unparseable) are enough to act on; the body is
		// not echoed into the error.
		let records: Vec<Record> = serde_json::from_str(&text).map_err(|_| {
			ProviderError::Remote(format!("GET {path} returned an unparseable body"))
		})?;
		Ok(records
			.into_iter()
			.filter_map(|r| {
				// GoDaddy returns names relative to the zone. The
				// previous code guessed whether a returned name was
				// already absolute by checking for the zone suffix,
				// which produced a wrong FQDN for a legitimate
				// relative label like `mail.example.org` (the label
				// means `mail.example.org.example.org`, not
				// `mail.example.org`). The fix is deterministic:
				// the apex maps to the zone, every other returned
				// name is treated as relative and joined to the
				// zone.
				let name = r.name.trim_end_matches('.').to_string();
				let fqdn = if name == "@" {
					self.zone.clone()
				} else {
					format!("{name}.{}", self.zone)
				};
				// Every type the zone holds is listed, the apex NS and a
				// delegation's NS included; a type epistle does not publish
				// keeps its own kind (`RecordKind::from_token`), never TXT.
				let kind = RecordKind::from_token(&r.kind);
				let value = if kind == RecordKind::Mx {
					let priority = r.priority?;
					format!("{} {}", priority, r.data.trim_end_matches('.'))
				} else if kind == RecordKind::Srv {
					let priority = r.priority?;
					let weight = r.weight?;
					let port = r.port?;
					let target = r.data.trim_end_matches('.');
					format!("{priority} {weight} {port} {target}")
				} else if kind == RecordKind::Txt {
					txt_decode(&r.data, TXT_FORM)
				} else {
					r.data
				};
				Some(DnsRecord {
					name: fqdn,
					kind,
					value,
					ttl: r.ttl,
					proxied: None,
				})
			})
			.collect())
	}
}
