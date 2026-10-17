//! A GoDaddy DNS provider implementing [`DnsProvider`]. The v1 API expects
//! `Authorization: sso-key <api_key>:<api_secret>` and replaces the whole
//! record set at `(type, name)` with `PUT /domains/{domain}/records/{type}/{name}`.
//! A list of records is a single JSON array; the body the upsert path builds
//! holds one element per call because the [`DnsProvider`] trait takes a single
//! [`DnsRecord`] at a time. MX/SRV need their extra fields (`priority` for MX,
//! `priority`/`weight`/`port`/`service`/`protocol` for SRV) on the array
//! element. The apex is the literal `@`.
//!
//! GoDaddy restricts production API access by account eligibility; a 403 is
//! not a bad key but a "your account is not enabled for production API" verdict,
//! so the error message spells that out instead of the generic
//! `provider authentication failed` the other providers return for 403.
//!
//! Endpoints and payloads follow <https://developer.godaddy.com/doc/endpoints/dns>.

use std::pin::Pin;

use serde::Deserialize;

use crate::net::HttpsUrl;

use crate::dns::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, parse_srv, same_txt_purpose,
};
use crate::dns::providers::transport;
use crate::dns::txt::{TxtForm, txt_decode, txt_encode};

/// How GoDaddy takes a TXT `data` and lists it back; see `record_element`.
const TXT_FORM: TxtForm = TxtForm::Logical;

/// GoDaddy's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://api.godaddy.com/v1";

/// GoDaddy's floor for a record TTL, in seconds. Shorter values are rejected
/// by the API; the provider raises the configured TTL to the floor at write
/// time so a low-TTL DKIM/SPF never hits the wire.
const MIN_TTL: u32 = 600;

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A GoDaddy-backed DNS provider for one zone.
pub struct GodaddyProvider {
	client: reqwest::Client,
	/// The (non-secret) API key paired with the secret.
	api_key: String,
	/// The secret half of the API key pair. The provider never logs it; the
	/// only place it leaves the struct is the `sso-key` header.
	api_secret: String,
	/// The zone every record is scoped to.
	zone: String,
	base: HttpsUrl,
}

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

/// Translate an FQDN into the relative name GoDaddy's API expects: the
/// label minus the zone suffix, or `@` for the apex. The strip is
/// case-insensitive on the suffix so `_dmarc.EXAMPLE.ORG` is mapped
/// to `_dmarc` for a `example.org` zone; a trailing dot is stripped
/// first so `example.org.` also maps to `@` and the
/// authorisation check in [`Self::secret_zone_authorizes`] agrees
/// on the apex. The returned label keeps the input's case for the
/// part that is not the zone suffix; an apex absolute name (zone,
/// zone with a trailing dot, or any case variant) maps to the
/// literal `@`.
fn fqdn_to_relative(name: &str, zone: &str) -> String {
	let name = name.trim_end_matches('.');
	let zone = zone.trim_end_matches('.');
	if name.is_empty() {
		return "@".to_string();
	}
	let name_lower = name.to_ascii_lowercase();
	let zone_lower = zone.to_ascii_lowercase();
	if name_lower == zone_lower {
		return "@".to_string();
	}
	let suffix = format!(".{zone_lower}");
	match name_lower.strip_suffix(&suffix) {
		Some(prefix) if !prefix.is_empty() => {
			// Reconstruct the original case for the prefix portion.
			// `name` is at least as long as `name_lower` (ASCII), so
			// the byte slice is safe.
			name[..prefix.len()].to_string()
		}
		_ => name.to_string(),
	}
}

/// Split an SRV owner name into `(service, protocol)`. The owner
/// always starts with `_service._proto` for a non-apex SRV; the
/// `_service._proto.` prefix is stripped, the rest is treated as
/// the host part of the record. An owner that does not follow the
/// shape (a single label, or a label that is not a service name)
/// returns empty strings; the API rejects the empty wire shape, so
/// the upstream caller will see the failure through the standard
/// error path.
fn service_protocol_from_owner(rel: &str) -> (String, String) {
	let labels: Vec<&str> = rel.split('.').collect();
	if labels.len() < 2 || !labels[0].starts_with('_') || !labels[1].starts_with('_') {
		return (String::new(), String::new());
	}
	(labels[0].to_string(), labels[1].to_string())
}

impl GodaddyProvider {
	/// Build a provider for `zone` with the two credential halves. `api_key`
	/// is the public half; `api_secret` is the secret half and travels only in
	/// the `sso-key` header. The zone is stripped of a trailing dot so an
	/// operator who authors `zone = "example.org."` reaches the same path
	/// the API expects (`/domains/example.org/records/...`) as one who
	/// authors `zone = "example.org"`.
	pub fn new(api_key: String, api_secret: String, zone: String) -> Self {
		GodaddyProvider {
			client: crate::dns::providers::http_client(),
			api_key,
			api_secret,
			zone: zone.trim_end_matches('.').to_string(),
			base: HttpsUrl::from_static(DEFAULT_BASE),
		}
	}

	/// Point the provider at an alternate API base (tests).
	pub fn with_base(mut self, base: HttpsUrl) -> Self {
		self.base = base;
		self
	}

	/// The GoDaddy record type for a kind we can publish. A/AAAA/TXT/CNAME
	/// go through the plain `data` field; MX and SRV add the kind's extra
	/// fields to the array element. TLSA is rejected with `Unsupported`:
	/// the v1 endpoints' allowed-type set excludes it
	/// (https://developer.godaddy.com/en/docs/references/rest/domains/v1/record-replace-type-name),
	/// so a TLSA publish would round-trip a 4xx instead of a clean
	/// "this provider does not support TLSA" verdict.
	fn api_kind(kind: &RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A => Ok("A"),
			RecordKind::Aaaa => Ok("AAAA"),
			RecordKind::Txt => Ok("TXT"),
			RecordKind::Cname => Ok("CNAME"),
			RecordKind::Mx => Ok("MX"),
			RecordKind::Srv => Ok("SRV"),
			RecordKind::Caa => Ok("CAA"),
			// TLSA has no structured field on GoDaddy.
			RecordKind::Tlsa => Err(ProviderError::Unsupported),
			RecordKind::Ns | RecordKind::Https | RecordKind::Svcb | RecordKind::Other(_) => {
				Err(ProviderError::Unsupported)
			}
		}
	}

	/// Reject a record outside the configured zone before any network call.
	fn authorize(&self, record: &DnsRecord) -> Result<(), ProviderError> {
		if self.secret_zone_authorizes(&record.name) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	/// The zone-scope check the trait expects: every record name must
	/// equal `self.zone` or fall inside it. The trailing dot is
	/// stripped first so the apex is accepted with or without the
	/// presentation-form dot (`example.org` and `example.org.` both
	/// land on `@`); without the strip the FQDN form would be rejected
	/// even though the FQDN-to-relative converter would map it to the
	/// apex.
	fn secret_zone_authorizes(&self, name: &str) -> bool {
		let name = name.trim_end_matches('.').to_ascii_lowercase();
		let zone = self.zone.to_ascii_lowercase();
		name == zone || name.ends_with(&format!(".{zone}"))
	}

	/// A request with the `sso-key` header attached. The header carries the
	/// credentials in the form `<api_key>:<api_secret>`, key first, secret
	/// second. A wrong order makes GoDaddy answer 401, which the other
	/// providers' 401 path treats as a missing token.
	fn auth_header(&self) -> String {
		format!("sso-key {}:{}", self.api_key, self.api_secret)
	}

	/// `{base}/domains/{zone}/records[/{type}/{name}]`, with the zone and the
	/// record name each escaped as one path segment.
	fn records_url(&self, set: Option<(&str, &str)>) -> Result<HttpsUrl, ProviderError> {
		let mut segments = vec!["domains", self.zone.as_str(), "records"];
		if let Some((kind, rel)) = set {
			segments.extend([kind, rel]);
		}
		Ok(self.base.with_segments(segments)?)
	}

	/// `PUT /domains/{domain}/records/{type}/{name}`, replace the entire
	/// record set at `(type, name)` with `body`. GoDaddy replies 200 on
	/// success; the body is empty.
	async fn put_records(&self, kind: &str, rel: &str, body: String) -> Result<(), ProviderError> {
		let url = self.records_url(Some((kind, rel)))?;
		let response = self
			.client
			.put(url.into_url())
			.header(reqwest::header::AUTHORIZATION, self.auth_header())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		check(response)
	}

	/// `GET /domains/{domain}/records/{type}/{name}`, the current record
	/// set at `(type, name)`. Returns an empty array when no records
	/// exist. Used by the upsert and delete paths so they can merge
	/// against the live set rather than PUT the singleton element the
	/// caller asked for (GoDaddy's PUT replaces the whole set, a
	/// singleton PUT would wipe every other value at the same
	/// `(type, name)`).
	async fn fetch_set(
		&self,
		kind: &str,
		rel: &str,
	) -> Result<Vec<serde_json::Value>, ProviderError> {
		let url = self.records_url(Some((kind, rel)))?;
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
		// The body is not echoed into the error: an HTTP 200 with a
		// diagnostic body (the response from a misbehaving gateway) can
		// carry credentials that belong in the `Authorization` header we
		// just sent, and `Display`/`Debug` on `ProviderError::Remote`
		// exposes the string verbatim to operators. The status and the
		// endpoint are enough to act on; the body shape (non-array,
		// parse error) is reported as a flag, not as the value.
		match serde_json::from_str::<serde_json::Value>(&text) {
			Ok(serde_json::Value::Array(items)) => Ok(items),
			Ok(_) => Err(ProviderError::Remote(format!(
				"GET {path} returned a non-array body"
			))),
			Err(_) => Err(ProviderError::Remote(format!(
				"GET {path} returned an unparseable body"
			))),
		}
	}

	/// `DELETE /domains/{domain}/records/{type}/{name}`, remove every
	/// record at that `(type, name)`. GoDaddy replies 204.
	async fn delete_records(&self, kind: &str, rel: &str) -> Result<(), ProviderError> {
		let url = self.records_url(Some((kind, rel)))?;
		let response = self
			.client
			.delete(url.into_url())
			.header(reqwest::header::AUTHORIZATION, self.auth_header())
			.send()
			.await
			.map_err(transport)?;
		check(response)
	}

	/// The JSON array element for one record. MX adds `priority`; SRV adds
	/// `priority`/`weight`/`port`/`service`/`protocol`; every other kind
	/// carries just `data` and `ttl`. The TTL is raised to the API floor
	/// so a low-TTL DKIM/SPF never hits the wire.
	fn record_element(&self, record: &DnsRecord) -> Result<serde_json::Value, ProviderError> {
		let ttl = record.ttl.max(MIN_TTL);
		if record.kind == RecordKind::Mx {
			let mut parts = record.value.split_whitespace();
			let priority: u16 = parts
				.next()
				.and_then(|p| p.parse().ok())
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = parts
				.next()
				.ok_or_else(|| ProviderError::Remote("MX needs priority target".into()))?;
			let target = crate::dns::provider::mx_target_for_api(target).to_string();
			return Ok(serde_json::json!({
				"data": target,
				"ttl": ttl,
				"priority": priority,
			}));
		}
		if record.kind == RecordKind::Srv {
			let (priority, weight, port, target) = parse_srv(&record.value)
				.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {}", record.value)))?;
			// GoDaddy's SRV record splits the owner into `service` and
			// `protocol` and uses a string `data` for the target host.
			// epistle stores the value in the standard SRV presentation
			// form (`prio weight port target.`) and encodes the owner
			// name as `_service._proto.zone`; the labels before the
			// zone are the service and protocol. A blank `data` and
			// empty `service` / `protocol` are rejected by the API.
			let owner_rel = fqdn_to_relative(&record.name, &self.zone);
			let (service, protocol) = service_protocol_from_owner(&owner_rel);
			return Ok(serde_json::json!({
				"data": target.trim_end_matches('.'),
				"ttl": ttl,
				"priority": priority,
				"weight": weight,
				"port": port,
				"service": service,
				"protocol": protocol,
				"host": target.trim_end_matches('.'),
			}));
		}
		// The v1 OpenAPI gives `data` as a bare string with nothing on
		// TXT quoting, length or escaping
		// (<https://developer.godaddy.com/openapi/domains-v1.json>,
		// DNSRecord, read 2026-10-12). The logical value is the form that
		// is the same bytes every time it is sent and the one other
		// clients send (lego), and `elements_match_kind` compares logical
		// values so a set GoDaddy hands back quoted still matches.
		let data = if record.kind == RecordKind::Txt {
			txt_encode(&record.value, TXT_FORM)
		} else {
			record.value.clone()
		};
		Ok(serde_json::json!({
			"data": data,
			"ttl": ttl,
		}))
	}

	async fn upsert_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let rel = fqdn_to_relative(&record.name, &self.zone);
		let new_element = self.record_element(&record)?;
		// GoDaddy's PUT replaces the whole record set at (type, name).
		// An upsert is "publish this one record" without affecting
		// unrelated values at the same (type, name); the implementation
		// fetches the current set, swaps every matching element in
		// place (or appends the new one when nothing matches), and
		// PUTs the whole set back. A naive singleton PUT would erase
		// every other value at the owner, which is the bug a DKIM
		// publish on top of an existing SPF would otherwise trigger.
		// Two records of the same purpose at the same name are a
		// configuration mistake (SPF returns permerror, DMARC is
		// ignored): the upsert collapses them by dropping the
		// duplicates before the PUT.
		let mut set = self.fetch_set(kind, &rel).await?;
		let initial_len = set.len();
		set.retain(|element| !elements_match_kind(kind, element, &new_element));
		if set.len() < initial_len {
			// A matching element (or elements) was dropped. The new
			// value goes back as the one record of that purpose.
			set.push(new_element);
		} else {
			// No match by value: the new value is the first record
			// of this purpose at the owner.
			set.push(new_element);
		}
		let body = serde_json::Value::Array(set).to_string();
		self.put_records(kind, &rel, body).await
	}

	async fn delete_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		let kind = Self::api_kind(&record.kind)?;
		let rel = fqdn_to_relative(&record.name, &self.zone);
		// A TXT delete with an empty value retires the whole TXT set
		// at the owner (the DKIM rotator retires a selector this way).
		// The match-against-live-set path below would compare "" against
		// the live DKIM TXT and PUT the DKIM back as the remainder.
		if record.kind == RecordKind::Txt && record.value.is_empty() {
			return self.delete_records(kind, &rel).await;
		}
		let new_element = self.record_element(&record)?;
		// GoDaddy's DELETE removes every record at (type, name). A
		// delete is "remove this one record" without affecting other
		// values at the same (type, name); the implementation fetches
		// the current set, drops the matching element, and either PUTs
		// the remainder back or DELETEs the whole set when nothing
		// remains. A naive DELETE on a multi-value name would wipe
		// every value at the owner, which is the bug a stale ACME
		// challenge cleanup would otherwise trigger against a second
		// certificate order at the same owner.
		let set = self.fetch_set(kind, &rel).await?;
		let remainder: Vec<serde_json::Value> = set
			.into_iter()
			.filter(|element| !elements_match_kind(kind, element, &new_element))
			.collect();
		if remainder.is_empty() {
			self.delete_records(kind, &rel).await
		} else {
			let body = serde_json::Value::Array(remainder).to_string();
			self.put_records(kind, &rel, body).await
		}
	}

	async fn list_inner(&self) -> Result<Vec<DnsRecord>, ProviderError> {
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

impl DnsProvider for GodaddyProvider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(crate::dns::providers::within(async move {
			self.upsert_inner(record).await
		}))
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(crate::dns::providers::within(async move {
			self.delete_inner(record).await
		}))
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone_name = zone.to_string();
		Box::pin(crate::dns::providers::listing(zone_name, async move {
			self.list_inner().await
		}))
	}
}

/// Compare two wire elements by their value-identifying fields for
/// `kind`, per the upsert/delete contract in
/// [`crate::dns::provider::DnsProvider`]. The matching rule differs by
/// kind:
///
/// - TXT: `data` is compared through [`same_txt_purpose`], so two
///   values with the same version tag match (an SPF change replaces
///   the SPF rather than appending a second one) and an untagged
///   value matches only an identical value (an ACME DNS-01 cleanup
///   does not wipe a sibling challenge at the same owner). Untagged
///   values compare as logical values (quoting and string splits do not
///   count); dots are never trimmed.
/// - MX / SRV / CNAME: `data` is the FQDN target. GoDaddy stores the
///   target with a trailing dot, epistle publishes without one; the
///   compare is case-insensitive and ignores one trailing dot so a
///   `MAIL.Example.Org.` round-trip matches `mail.example.org`.
/// - A / AAAA / TLSA / CAA: the `data` is the address or hash bytes;
///   it is compared verbatim, no case folding or dot stripping.
///
/// The TTL is intentionally not part of the match: a re-upsert with
/// a different TTL is an update of the same value, not a second
/// record. The structured fields (MX `priority`, SRV `priority`/
/// `weight`/`port`/`service`/`protocol`) still have to match
/// alongside the data so a priority change lands as a replacement
/// rather than a duplicate.
fn elements_match_kind(kind: &str, existing: &serde_json::Value, new: &serde_json::Value) -> bool {
	let data_eq = match (existing.get("data"), new.get("data")) {
		(Some(serde_json::Value::String(a)), Some(serde_json::Value::String(b))) => match kind {
			"TXT" => same_txt_purpose(a, b),
			"MX" | "SRV" | "CNAME" => {
				let a = a.trim_end_matches('.').to_ascii_lowercase();
				let b = b.trim_end_matches('.').to_ascii_lowercase();
				a == b
			}
			_ => a == b,
		},
		(a, b) => a == b,
	};
	match kind {
		"MX" => data_eq && existing.get("priority") == new.get("priority"),
		"SRV" => {
			data_eq
				&& existing.get("priority") == new.get("priority")
				&& existing.get("weight") == new.get("weight")
				&& existing.get("port") == new.get("port")
				&& existing.get("service") == new.get("service")
				&& existing.get("protocol") == new.get("protocol")
		}
		_ => data_eq,
	}
}

/// Map a 401/403 to a typed auth error. 401 is a bad key; 403 is the
/// GoDaddy-specific "your account is not eligible for production API
/// access" verdict, so the message names the eligibility check instead
/// of the generic "authentication failed" the other providers use.
fn auth_error(status: reqwest::StatusCode) -> ProviderError {
	if status == reqwest::StatusCode::FORBIDDEN {
		ProviderError::Remote(
			"GoDaddy account is not eligible for production API access; \
			 see https://developer.godaddy.com/getstarted for eligibility"
				.into(),
		)
	} else {
		ProviderError::Auth
	}
}

/// Map a write response to success or a typed error. 401 maps to
/// `ProviderError::Auth`; 403 maps to the eligibility-flavoured error.
fn check(response: reqwest::Response) -> Result<(), ProviderError> {
	let status = response.status();
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return Err(auth_error(status));
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
#[path = "tests_b.rs"]
mod tests_b;

#[cfg(test)]
#[path = "tests_contract.rs"]
mod tests_contract;

#[cfg(test)]
#[path = "tests_txt_forms.rs"]
mod tests_txt_forms;

#[cfg(test)]
#[path = "tests_path.rs"]
mod path_tests;
