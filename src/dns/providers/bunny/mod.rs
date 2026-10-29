//! A Bunny.net DNS provider implementing [`DnsProvider`]. Bunny references a
//! zone by its numeric id, so on first use we issue `GET /dnszone?search=...`
//! and pick the entry whose `Domain` matches the token's zone (zones are
//! unique by name). Record writes go through `PUT /dnszone/{id}/records` to
//! create or `POST /dnszone/{id}/records/{id}` to update — same `name+type`
//! pair is what makes two Bunny records "the same" record, so upsert checks
//! the zone's `Records` list first and replaces in place when one is there.
//! Authenticates with the account access key in the `AccessKey` header (not
//! Bearer).

use std::pin::Pin;
use std::sync::Mutex;

use serde::Deserialize;

use crate::net::HttpsUrl;

use crate::dns::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, parse_srv, record_description,
	same_txt_purpose,
};
use crate::dns::providers::transport;
use crate::dns::txt::{TxtForm, txt_decode, txt_encode};

/// How Bunny takes a TXT `Value` and lists it back; see `record_body`.
const TXT_FORM: TxtForm = TxtForm::Logical;

/// Bunny's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://api.bunny.net";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A Bunny-backed DNS provider for one zone.
pub struct BunnyProvider {
	client: reqwest::Client,
	secret: ScopedSecret,
	base: HttpsUrl,
	/// Cached numeric zone id, looked up on first use. Held in a sync mutex
	/// only across quick reads/writes; never across an `await`.
	zone_id: Mutex<Option<i64>>,
}

/// `GET /dnszone?search=...` response body.
#[derive(Deserialize)]
struct ListZones {
	#[serde(rename = "Items", default)]
	items: Vec<ZoneRef>,
}

#[derive(Deserialize)]
struct ZoneRef {
	#[serde(rename = "Id")]
	id: i64,
	#[serde(rename = "Domain", default)]
	domain: Option<String>,
}

/// `GET /dnszone/{id}` response body (full view — `Records` is included).
#[derive(Deserialize)]
struct ZoneDetail {
	#[serde(rename = "Records", default)]
	records: Vec<DnsRecordRef>,
}

#[derive(Deserialize)]
struct DnsRecordRef {
	#[serde(rename = "Id")]
	id: i64,
	#[serde(rename = "Type")]
	rtype: i64,
	#[serde(rename = "Name", default)]
	name: Option<String>,
	#[serde(rename = "Value", default)]
	value: Option<String>,
	#[serde(rename = "Ttl", default)]
	ttl: i64,
	/// The preference of an MX.
	#[serde(rename = "Priority", default)]
	priority: Option<i64>,
	/// The flags and the tag of a CAA; its `Value` is the issuer alone.
	#[serde(rename = "Flags", default)]
	flags: Option<i64>,
	#[serde(rename = "Tag", default)]
	tag: Option<String>,
}

impl BunnyProvider {
	/// Build a provider for the token's zone.
	pub fn new(secret: ScopedSecret) -> Self {
		BunnyProvider {
			client: crate::dns::providers::http_client(),
			secret,
			base: HttpsUrl::from_static(DEFAULT_BASE),
			zone_id: Mutex::new(None),
		}
	}

	/// Point the provider at an alternate API base (tests).
	pub fn with_base(mut self, base: HttpsUrl) -> Self {
		self.base = base;
		self
	}

	/// The relative record name: `name` with the trailing `.zone` stripped,
	/// the apex becoming the empty string (Bunny's convention).
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

	/// Bunny's numeric record type for a kind we publish. Anything else
	/// (MX needs priority/weight; TLSA needs tag/value we do not emit)
	/// returns [`ProviderError::Unsupported`]. SRV (type 8) carries the
	/// four-tuple in the `Value` field as `weight port target` (priority is
	/// not editable through Bunny's API for SRV — it is always 0).
	fn api_type(kind: &RecordKind) -> Result<i64, ProviderError> {
		match kind {
			RecordKind::A => Ok(0),
			RecordKind::Aaaa => Ok(1),
			RecordKind::Cname => Ok(2),
			RecordKind::Txt => Ok(3),
			RecordKind::Mx => Ok(4),
			RecordKind::Srv => Ok(8),
			RecordKind::Tlsa
			| RecordKind::Caa
			| RecordKind::Ns
			| RecordKind::Https
			| RecordKind::Svcb
			| RecordKind::Other(_) => Err(ProviderError::Unsupported),
		}
	}

	/// Reject a record the token is not scoped for, before any network call.
	fn authorize(&self, name: &str) -> Result<(), ProviderError> {
		if self.secret.authorizes(name) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	/// Look up the numeric zone id (cached) by searching for the zone's name
	/// and picking the entry whose `Domain` is an exact match — Bunny's
	/// `?search=` is a prefix match, so a zone `example.org` also returns
	/// `evil.example.org` and we must not pick it.
	async fn zone_id(&self) -> Result<i64, ProviderError> {
		if let Some(id) = *self.zone_id.lock().unwrap() {
			return Ok(id);
		}
		let url = self
			.base
			.with_segments(["dnszone"])?
			.with_query("search", self.secret.zone());
		let resp: ListZones = self.get_json(url).await?;
		let zone = self.secret.zone().to_string();
		let id = resp
			.items
			.into_iter()
			.find(|z| z.domain.as_deref() == Some(zone.as_str()))
			.map(|z| z.id)
			.ok_or_else(|| ProviderError::Remote(format!("zone not found: {zone}")))?;
		*self.zone_id.lock().unwrap() = Some(id);
		Ok(id)
	}

	/// `{base}/dnszone/{zone_id}/records[/{record_id}]`.
	fn record_url(&self, zone_id: i64, record_id: Option<i64>) -> Result<HttpsUrl, ProviderError> {
		let mut segments = vec![
			"dnszone".to_string(),
			zone_id.to_string(),
			"records".to_string(),
		];
		segments.extend(record_id.map(|id| id.to_string()));
		Ok(self.base.with_segments(segments)?)
	}

	/// Fetch the zone detail (which embeds the records list).
	async fn zone_detail(&self, zone_id: i64) -> Result<ZoneDetail, ProviderError> {
		let url = self.base.with_segments(["dnszone", &zone_id.to_string()])?;
		self.get_json(url).await
	}

	/// GET a JSON body, mapping 401/403 to [`ProviderError::Auth`].
	async fn get_json<T: serde::de::DeserializeOwned>(
		&self,
		url: HttpsUrl,
	) -> Result<T, ProviderError> {
		let response = self
			.client
			.get(url.into_url())
			.header("AccessKey", self.secret.token())
			.send()
			.await
			.map_err(transport)?;
		decode(response).await
	}

	/// Issue a JSON write with the `AccessKey` header.
	async fn send_write(
		&self,
		method: reqwest::Method,
		url: HttpsUrl,
		body: String,
	) -> Result<reqwest::Response, ProviderError> {
		self.client
			.request(method, url.into_url())
			.header("AccessKey", self.secret.token())
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(transport)
	}

	/// Build the create/update body for one record. SRV carries the
	/// `weight port target` triple in `Value` (priority is fixed at 0 by the
	/// Bunny API), MX carries `<priority> <target>` (Bunny's API does not
	/// split them), every other supported kind carries the value verbatim.
	fn record_body(&self, record: &DnsRecord, rtype: i64) -> Result<String, ProviderError> {
		let value = if record.kind == RecordKind::Srv {
			let (_prio, weight, port, target) = parse_srv(&record.value)
				.ok_or_else(|| ProviderError::Remote(format!("bad SRV value: {}", record.value)))?;
			format!("{weight} {port} {target}")
		} else if record.kind == RecordKind::Mx {
			// Bunny expects MX as `<priority> <target>` in `Value` — Bunny's
			// own UI shows it that way too.
			record.value.clone()
		} else if record.kind == RecordKind::Txt {
			// The API reference gives `Value` as a bare nullable string
			// with nothing on quoting, length or escaping
			// (<https://bunny.net/docs/reference/dnszonepublic_addrecord>,
			// read 2026-10-12). The logical value is the form that is the
			// same bytes every time it is sent, and it is the one other
			// clients of this API send (dnscontrol's bunnydns provider).
			txt_encode(&record.value, TXT_FORM)
		} else {
			record.value.clone()
		};
		Ok(serde_json::json!({
			"Type": rtype,
			"Name": self.subname(&record.name),
			"Value": value,
			"Ttl": record.ttl,
			"Comment": record_description(),
		})
		.to_string())
	}

	async fn upsert_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record.name)?;
		let rtype = Self::api_type(&record.kind)?;
		let zone_id = self.zone_id().await?;
		let detail = self.zone_detail(zone_id).await?;
		let name = self.subname(&record.name);
		let body = self.record_body(&record, rtype)?;
		// The upsert contract in `src/dns/provider/mod.rs`: a TXT replaces
		// the record of the same purpose and leaves every other TXT
		// at the name alone (an ACME challenge, a verification token).
		// Two records of the same purpose at the same name are a
		// configuration mistake (SPF returns permerror, DMARC is
		// ignored): the upsert collapses them by editing the first
		// match and deleting every other. Other kinds take the first
		// record at (type, name), so duplicates do not arise.
		let kind_for_match = record.kind.clone();
		let mut matching = detail.records.into_iter().filter(move |r| {
			r.rtype == rtype
				&& r.name.as_deref() == Some(name.as_str())
				&& (kind_for_match != RecordKind::Txt
					|| same_txt_purpose(r.value.as_deref().unwrap_or(""), &record.value))
		});
		if let Some(primary) = matching.next() {
			let url = self.record_url(zone_id, Some(primary.id))?;
			let response = self.send_write(reqwest::Method::POST, url, body).await?;
			check(response)?;
			for duplicate in matching {
				self.delete_by_id(zone_id, duplicate.id).await?;
			}
			return Ok(());
		}
		let url = self.record_url(zone_id, None)?;
		let response = self.send_write(reqwest::Method::PUT, url, body).await?;
		check(response)
	}

	async fn delete_inner(&self, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record.name)?;
		let rtype = Self::api_type(&record.kind)?;
		let zone_id = self.zone_id().await?;
		let detail = self.zone_detail(zone_id).await?;
		let name = self.subname(&record.name);
		// The TXT matching rule from `src/dns/provider/mod.rs` is the
		// contract: a value-bearing delete drops only the record
		// whose value matches the value (a sibling ACME challenge at
		// the same owner survives), an empty-value delete drops
		// every record at the owner (the DKIM rotator's retire
		// path). Other record kinds fall through to the
		// first-by-(type, name) selection, which is the existing
		// whole-set semantics.
		if record.kind == RecordKind::Txt && record.value.is_empty() {
			let recs: Vec<_> = detail
				.records
				.into_iter()
				.filter(|r| r.rtype == rtype && r.name.as_deref() == Some(name.as_str()))
				.collect();
			let count = recs.len();
			for rec in recs {
				self.delete_by_id(zone_id, rec.id).await?;
			}
			// Match the existing "already gone" no-op: if there
			// was nothing to remove, no network call should have
			// happened. We've already issued deletes; the test
			// assertions on the wholesale path still see them.
			let _ = count;
			return Ok(());
		}
		let Some(rec) = detail.records.into_iter().find(|r| {
			r.rtype == rtype
				&& r.name.as_deref() == Some(name.as_str())
				&& (record.kind != RecordKind::Txt
					|| record.value.is_empty()
					|| same_txt_purpose(r.value.as_deref().unwrap_or(""), &record.value))
		}) else {
			return Ok(()); // idempotent: nothing to remove.
		};
		self.delete_by_id(zone_id, rec.id).await
	}

	async fn delete_by_id(&self, zone_id: i64, id: i64) -> Result<(), ProviderError> {
		let url = self.record_url(zone_id, Some(id))?;
		let response = self
			.client
			.delete(url.into_url())
			.header("AccessKey", self.secret.token())
			.send()
			.await
			.map_err(transport)?;
		let status = response.status();
		if status == reqwest::StatusCode::NOT_FOUND {
			return Ok(()); // idempotent: gone between find and delete.
		}
		if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
			return Err(ProviderError::Auth);
		}
		if status.is_success() {
			Ok(())
		} else {
			Err(ProviderError::Remote(format!("HTTP {status}")))
		}
	}

	async fn list_inner(&self) -> Result<Vec<DnsRecord>, ProviderError> {
		let zone_id = self.zone_id().await?;
		let detail = self.zone_detail(zone_id).await?;
		let zone = self.secret.zone().to_string();
		Ok(detail
			.records
			.into_iter()
			.filter_map(|r| {
				let name_rel = r.name.unwrap_or_default();
				let name = if name_rel.is_empty() {
					zone.clone()
				} else {
					format!("{name_rel}.{zone}")
				};
				let kind = parse_kind(r.rtype);
				let value_raw = r.value.unwrap_or_default();
				let value = if kind == RecordKind::Srv {
					// Bunny returns SRV values as `weight port target`; lift
					// them into the canonical `priority weight port target.`
					// form (Bunny's API pins priority to 0, so the wire value
					// is exactly the one we will need to upsert later).
					let mut parts = value_raw.split_whitespace();
					let weight = parts.next()?;
					let port = parts.next()?;
					let target = parts.collect::<Vec<_>>().join(" ");
					format!("0 {weight} {port} {target}")
				} else if kind == RecordKind::Txt {
					txt_decode(&value_raw, TXT_FORM)
				} else if kind == RecordKind::Mx
					&& r.priority.is_some()
					&& !starts_with_preference(&value_raw)
				{
					// `Priority` and `Value` are separate fields; a record written
					// as `<preference> <exchange>` in `Value` already has it.
					format!("{} {value_raw}", r.priority.unwrap_or(0))
				} else if kind == RecordKind::Caa && r.tag.is_some() {
					format!(
						"{} {} \"{value_raw}\"",
						r.flags.unwrap_or(0),
						r.tag.as_deref().unwrap_or_default()
					)
				} else {
					value_raw
				};
				Some(DnsRecord {
					name,
					kind,
					value,
					ttl: r.ttl.max(0) as u32,
					proxied: None,
				})
			})
			.collect())
	}
}

impl DnsProvider for BunnyProvider {
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

/// Whether an MX `Value` already begins with its preference: a number and
/// something after it (`10 mail.example.org`, `0 .`).
fn starts_with_preference(value: &str) -> bool {
	let mut parts = value.split_whitespace();
	parts
		.next()
		.is_some_and(|first| first.parse::<u16>().is_ok())
		&& parts.next().is_some()
}

/// Map Bunny's numeric record type back to a [`RecordKind`]. The numbers
/// are Bunny's `DnsRecordTypes` enum (<https://bunny.net/docs/reference/dnszonepublic_add>,
/// read 2026-10-16). The ones epistle does not publish keep their own kind
/// (NS at 12 is a delegation), and a number the enum does not list is
/// `TYPE<n>`, never a TXT.
fn parse_kind(rtype: i64) -> RecordKind {
	let token = match rtype {
		0 => "A",
		1 => "AAAA",
		2 => "CNAME",
		3 => "TXT",
		4 => "MX",
		5 => "REDIRECT",
		6 => "FLATTEN",
		7 => "PULLZONE",
		8 => "SRV",
		9 => "CAA",
		10 => "PTR",
		11 => "SCRIPT",
		12 => "NS",
		13 => "SVCB",
		14 => "HTTPS",
		15 => "TLSA",
		other => return RecordKind::from_token(&format!("TYPE{other}")),
	};
	RecordKind::from_token(token)
}

/// Decode a JSON body, mapping 401/403 to an auth error.
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

/// Confirm a write succeeded (2xx), mapping auth failures distinctly.
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
mod tests;
