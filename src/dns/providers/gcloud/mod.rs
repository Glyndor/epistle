//! A Google Cloud DNS provider implementing [`DnsProvider`].
//!
//! Authentication runs as a Google service account: a JWT (RS256) minted from
//! the service-account private key is exchanged at
//! `https://oauth2.googleapis.com/token` for a short-lived OAuth access token
//! (scope `ndev.clouddns.readwrite`), cached in-process until one minute before
//! it expires. The cached token is then used as `Authorization: Bearer …` on
//! every request to `https://dns.googleapis.com/dns/v1`.
//!
//! The Google API is zone-keyed: every record lives in a `managedZone` whose
//! `dnsName` ends in a dot (`example.org.`). Each epistle change lists the
//! zone's rrsets and submits one change request carrying `additions` (and,
//! when replacing, `deletions`). Deleting an absent rrset is a no-op (`Ok`).
//!
//! Endpoints (Cloud DNS REST API v1):
//!   - List managed zones:
//!     <https://cloud.google.com/dns/docs/reference/v1/managedZones/list>
//!   - List rrsets:
//!     <https://cloud.google.com/dns/docs/reference/v1/resourceRecordSets/list>
//!   - Create a change:
//!     <https://cloud.google.com/dns/docs/reference/v1/changes/create>
//!
//! OAuth: <https://developers.google.com/identity/protocols/oauth2/service-account>.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64STD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use ring::rand::SystemRandom;
use ring::signature::{self, RsaKeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::net::HttpsUrl;

use crate::dns::provider::{
	DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret, same_txt_purpose,
};
use crate::dns::providers::transport;
use crate::dns::txt::{TxtForm, same_txt_value, txt_decode, txt_encode};

mod list;

/// How Cloud DNS wants a TXT value written and lists it back; see
/// `GcloudProvider::rrdatas`.
const TXT_FORM: TxtForm = TxtForm::Presentation;

const TOKEN_AUDIENCE: &str = "https://oauth2.googleapis.com/token";
const DNS_SCOPE: &str = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";
const JWT_TTL_SECS: u64 = 3600;
const TOKEN_LEEWAY_SECS: u64 = 60;
const DEFAULT_TOKEN_BASE: &str = "https://oauth2.googleapis.com";
const DEFAULT_DNS_BASE: &str = "https://dns.googleapis.com/dns/v1";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// Parsed Google service-account JSON. The other fields (`type`,
/// `private_key_id`, `universe_domain`, …) are ignored so an unchanged
/// upstream JSON keeps working.
#[derive(Clone, Deserialize)]
pub struct ServiceAccount {
	/// Service-account email (`<id>@<project>.iam.gserviceaccount.com`).
	#[serde(rename = "client_email")]
	pub client_email: String,
	/// PKCS#8 PEM private key used to sign the JWT.
	#[serde(rename = "private_key")]
	pub private_key: String,
	/// GCP project id that owns the zone.
	#[serde(rename = "project_id")]
	pub project_id: String,
}

#[derive(Clone)]
struct CachedToken {
	access_token: String,
	expires_at: Instant,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ListZonesResp {
	#[serde(default)]
	managedZones: Vec<ZoneRef>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ZoneRef {
	name: String,
	dnsName: String,
}

#[derive(Deserialize, Clone, Serialize)]
pub(crate) struct Rrset {
	name: String,
	#[serde(rename = "type")]
	kind: String,
	#[serde(default)]
	ttl: u32,
	#[serde(default)]
	rrdatas: Vec<String>,
}

#[derive(Deserialize)]
struct ListRrsetsResp {
	#[serde(default)]
	rrsets: Vec<Rrset>,
	/// Set when more rrsets follow on another page.
	#[serde(default, rename = "nextPageToken")]
	next_page_token: Option<String>,
}

/// A Google Cloud DNS-backed DNS provider for one managed zone.
pub struct GcloudProvider {
	client: reqwest::Client,
	account: ServiceAccount,
	zone: String,
	cached: Arc<Mutex<Option<CachedToken>>>,
	token_base: HttpsUrl,
	dns_base: HttpsUrl,
}

impl GcloudProvider {
	/// Build a provider for `secret.zone()` using the parsed service account.
	/// `secret.token()` is unused: Google authenticates by signature, not
	/// bearer, so the [`ScopedSecret`] is only a zone handle here.
	pub fn new(secret: ScopedSecret, account: ServiceAccount) -> Self {
		GcloudProvider {
			client: crate::dns::providers::http_client(),
			account,
			zone: secret.zone().to_string(),
			cached: Arc::new(Mutex::new(None)),
			token_base: HttpsUrl::from_static(DEFAULT_TOKEN_BASE),
			dns_base: HttpsUrl::from_static(DEFAULT_DNS_BASE),
		}
	}

	/// Point the OAuth2 token endpoint at an alternate URL (tests).
	pub fn with_token_base(mut self, base: HttpsUrl) -> Self {
		self.token_base = base;
		self
	}

	/// Point the Cloud DNS API at an alternate URL (tests).
	/// The base is the API root including its version (`.../dns/v1`).
	pub fn with_dns_base(mut self, base: HttpsUrl) -> Self {
		self.dns_base = base;
		self
	}

	/// The Google API type token for a kind we can publish; MX/SRV need
	/// priority/weight handling we do not emit yet.
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

	/// Whether `record` sits inside `self.zone` (case-insensitive). Reject
	/// before any network call.
	fn authorize(&self, record: &DnsRecord) -> Result<(), ProviderError> {
		let name = record.name.trim_end_matches('.').to_ascii_lowercase();
		let zone = self.zone.trim_end_matches('.').to_ascii_lowercase();
		if name == zone || name.ends_with(&format!(".{zone}")) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	/// The fully-qualified, trailing-dot name Cloud DNS expects for `record`.
	/// `authorize()` must have already approved the name.
	fn fqdn(&self, record: &DnsRecord) -> String {
		let name = record.name.trim_end_matches('.').to_ascii_lowercase();
		let zone = self.zone.trim_end_matches('.').to_ascii_lowercase();
		if name == zone {
			format!("{zone}.")
		} else {
			let label = name.strip_suffix(&format!(".{zone}")).unwrap_or(&name);
			format!("{label}.{zone}.")
		}
	}

	/// Cloud DNS takes `rrdatas` in RFC 1035 presentation form and asks for
	/// a TXT to be quoted and pre-split: "If your record data is more than
	/// 255 bytes, divide your record into 255-byte strings and enclose each
	/// string in quotation marks", with `"String one" "String two"` as its
	/// example (<https://docs.cloud.google.com/dns/docs/records-overview>, TXT
	/// section, read 2026-10-12). Each `rrdatas` element is a separate
	/// record, so the strings go space-separated in ONE element; several
	/// elements would be several TXT records, which no DKIM verifier
	/// stitches back together. The read form is not documented; it is read
	/// as the same presentation form ([`TXT_FORM`]). Every other kind
	/// carries one verbatim rdata.
	fn rrdatas(&self, record: &DnsRecord) -> Vec<String> {
		if record.kind == RecordKind::Txt {
			vec![txt_encode(&record.value, TXT_FORM)]
		} else {
			vec![record.value.clone()]
		}
	}

	/// Classify a `reqwest` response: `Auth` for 401/403/404, `Remote` for
	/// anything else non-2xx, success otherwise. Body is left in `response`.
	fn classify(
		response: &reqwest::Response,
		treat_404_as_auth: bool,
	) -> Result<(), ProviderError> {
		let status = response.status();
		if status == reqwest::StatusCode::UNAUTHORIZED
			|| status == reqwest::StatusCode::FORBIDDEN
			|| (treat_404_as_auth && status == reqwest::StatusCode::NOT_FOUND)
		{
			return Err(ProviderError::Auth);
		}
		if status.is_success() {
			Ok(())
		} else {
			Err(ProviderError::Remote(format!("HTTP {status}")))
		}
	}

	/// `{dns_base}/projects/{project}/managedZones[/{tail...}]`, with the
	/// project id and every tail segment escaped as one path segment. The
	/// base already ends in `/dns/v1`, which is not repeated here.
	fn managed_zones_url(&self, tail: &[&str]) -> Result<HttpsUrl, ProviderError> {
		let mut segments = vec!["projects", self.account.project_id.as_str(), "managedZones"];
		segments.extend_from_slice(tail);
		Ok(self.dns_base.with_segments(segments)?)
	}

	/// The managed-zone id (`name`) whose `dnsName` matches `zone`.
	async fn find_managed_zone(&self, zone: &str) -> Result<String, ProviderError> {
		let token = self.ensure_token().await?;
		let dns_name = format!("{}.", zone.trim_end_matches('.'));
		let url = self
			.managed_zones_url(&[])?
			.with_query("dnsName", &dns_name);
		let response = self
			.client
			.get(url.into_url())
			.bearer_auth(&token)
			.send()
			.await
			.map_err(transport)?;
		Self::classify(&response, true)?;
		let text = self.read_body(response).await?;
		let parsed: ListZonesResp =
			serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))?;
		parsed
			.managedZones
			.into_iter()
			.find(|z| z.dnsName.trim_end_matches('.') == zone.trim_end_matches('.'))
			.map(|z| z.name)
			.ok_or_else(|| ProviderError::Remote(format!("zone not found: {zone}")))
	}

	async fn post_change(
		&self,
		managed_zone: &str,
		additions: &[Rrset],
		deletions: &[Rrset],
	) -> Result<(), ProviderError> {
		let token = self.ensure_token().await?;
		let url = self.managed_zones_url(&[managed_zone, "changes"])?;
		let body = serde_json::to_string(&json!({
			"additions": additions,
			"deletions": deletions,
		}))
		.map_err(|e| ProviderError::Remote(e.to_string()))?;
		let response = self
			.client
			.post(url.into_url())
			.bearer_auth(&token)
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		Self::classify(&response, false)
	}

	async fn read_body(&self, response: reqwest::Response) -> Result<String, ProviderError> {
		crate::dns::providers::read_body(response).await
	}

	/// Return a valid bearer access token, refreshing the cache when needed.
	async fn ensure_token(&self) -> Result<String, ProviderError> {
		if let Some(cached) = self.cached.lock().unwrap().clone()
			&& cached.expires_at > Instant::now()
		{
			return Ok(cached.access_token);
		}
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		let claims = json!({
			"iss": self.account.client_email,
			"scope": DNS_SCOPE,
			"aud": TOKEN_AUDIENCE,
			"iat": now,
			"exp": now + JWT_TTL_SECS,
		});
		let jwt = sign_rs256(&self.account.private_key, &claims)
			.map_err(|e| ProviderError::Remote(format!("jwt signing: {e:?}")))?;
		let body =
			format!("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={jwt}");
		let response = self
			.client
			.post(self.token_base.with_segments(["token"])?.into_url())
			.header(
				reqwest::header::CONTENT_TYPE,
				"application/x-www-form-urlencoded",
			)
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		Self::classify(&response, true)?;
		let text = self.read_body(response).await?;
		let parsed: Value =
			serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))?;
		let access_token = parsed
			.get("access_token")
			.and_then(Value::as_str)
			.ok_or_else(|| ProviderError::Remote("missing access_token".into()))?
			.to_string();
		let expires_in = parsed
			.get("expires_in")
			.and_then(Value::as_u64)
			.unwrap_or(JWT_TTL_SECS);
		let expires_at =
			Instant::now() + Duration::from_secs(expires_in.saturating_sub(TOKEN_LEEWAY_SECS));
		*self.cached.lock().unwrap() = Some(CachedToken {
			access_token: access_token.clone(),
			expires_at,
		});
		Ok(access_token)
	}

	async fn upsert_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		Self::api_kind(&record.kind)?;
		let managed_zone = self.find_managed_zone(zone).await?;
		let rrsets = self.list_rrsets(&managed_zone).await?;
		let kind_str = record.kind.as_str();
		let fqdn = self.fqdn(&record);
		let existing = rrsets
			.into_iter()
			.find(|r| r.name == fqdn && r.kind == kind_str);
		let mut rrdatas = self.rrdatas(&record);
		// A change replaces the whole rrset. The upsert contract in
		// `src/dns/provider.rs` replaces only the TXT of the same
		// purpose, so the siblings the live rrset holds go back in.
		if record.kind == RecordKind::Txt
			&& let Some(old) = &existing
		{
			let siblings = old
				.rrdatas
				.iter()
				.filter(|r| !same_txt_purpose(r, &record.value))
				.cloned();
			rrdatas = siblings.chain(rrdatas).collect();
		}
		let new_rrset = Rrset {
			name: fqdn.clone(),
			kind: kind_str.to_string(),
			ttl: record.ttl,
			rrdatas,
		};
		match existing {
			None => self.post_change(&managed_zone, &[new_rrset], &[]).await,
			Some(old) if old.ttl == new_rrset.ttl && same_rdatas(&record, &old, &new_rrset) => {
				Ok(())
			}
			Some(old) => self.post_change(&managed_zone, &[new_rrset], &[old]).await,
		}
	}

	async fn delete_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		Self::api_kind(&record.kind)?;
		let managed_zone = self.find_managed_zone(zone).await?;
		let rrsets = self.list_rrsets(&managed_zone).await?;
		let kind_str = record.kind.as_str();
		let fqdn = self.fqdn(&record);
		let Some(target) = rrsets
			.into_iter()
			.find(|r| r.name == fqdn && r.kind == kind_str)
		else {
			return Ok(());
		};
		// The TXT matching rule from `src/dns/provider.rs` is the
		// contract: a value-bearing delete drops only the rdata
		// whose value matches (a sibling ACME challenge at the same
		// owner survives), an empty-value delete drops every rdata
		// at the rrset (the DKIM rotator's retire path). Other
		// record kinds fall through to the rrset-delete path, which
		// is the existing whole-set semantics. Google Cloud DNS
		// treats an rrset as the unit of change, so the
		// value-bearing case reads the rrdatas, drops the matching
		// one, and replaces the rrset with the remainder (a
		// wholesale delete only when the rrset is fully gone).
		//
		// The match is on the logical value, so an rdata Cloud DNS
		// lists back with its strings spaced or escaped differently
		// is still found.
		if record.kind == RecordKind::Txt && !record.value.is_empty() {
			let remainder: Vec<String> = target
				.rrdatas
				.iter()
				.filter(|r| !same_txt_value(r, &record.value))
				.cloned()
				.collect();
			if remainder.len() == target.rrdatas.len() {
				// No rdata matched: idempotent, nothing to do.
				return Ok(());
			}
			if remainder.is_empty() {
				return self.post_change(&managed_zone, &[], &[target]).await;
			}
			let target_name = target.name.clone();
			let target_kind = target.kind.clone();
			let target_ttl = target.ttl;
			let replacement = Rrset {
				name: target_name,
				kind: target_kind,
				ttl: target_ttl,
				rrdatas: remainder,
			};
			return self
				.post_change(&managed_zone, &[replacement], &[target])
				.await;
		}
		self.post_change(&managed_zone, &[], &[target]).await
	}

	async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		let managed_zone = self.find_managed_zone(zone).await?;
		let rrsets = self.list_rrsets(&managed_zone).await?;
		let zone_name = self.zone.trim_end_matches('.').to_ascii_lowercase();
		Ok(rrsets
			.into_iter()
			.filter(|r| {
				let n = r.name.trim_end_matches('.').to_ascii_lowercase();
				n == zone_name || n.ends_with(&format!(".{zone_name}"))
			})
			.flat_map(|r| {
				let kind = RecordKind::from_token(&r.kind);
				let name = r.name.trim_end_matches('.').to_string();
				r.rrdatas.into_iter().map(move |value| {
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
	}
}

impl DnsProvider for GcloudProvider {
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

/// Whether `old` already holds what `new` would write, so the upsert can
/// skip the change. TXT compares the logical values in any order, because
/// Cloud DNS may list a record with its strings spaced or escaped
/// differently from how it was written; every other kind compares the
/// rdata verbatim.
fn same_rdatas(record: &DnsRecord, old: &Rrset, new: &Rrset) -> bool {
	if record.kind != RecordKind::Txt {
		return old.rrdatas == new.rrdatas;
	}
	let logical = |rrdatas: &[String]| {
		let mut values: Vec<String> = rrdatas.iter().map(|r| txt_decode(r, TXT_FORM)).collect();
		values.sort();
		values
	};
	logical(&old.rrdatas) == logical(&new.rrdatas)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SignError {
	BadPem,
	BadKey,
	BadClaims,
	SigningFailed,
}

/// Sign `claims` as an RS256 JWT (header `{alg:RS256,typ:JWT}`) using the
/// PKCS#8 PEM private key from a Google service-account credential.
fn sign_rs256(private_key_pem: &str, claims: &Value) -> Result<String, SignError> {
	let pkcs8_der = pem_to_pkcs8(private_key_pem).ok_or(SignError::BadPem)?;
	let key_pair = RsaKeyPair::from_pkcs8(&pkcs8_der).map_err(|_| SignError::BadKey)?;
	let header = json!({"alg": "RS256", "typ": "JWT"});
	let header_b64 = B64URL.encode(serde_json::to_vec(&header).map_err(|_| SignError::BadClaims)?);
	let payload_b64 = B64URL.encode(serde_json::to_vec(claims).map_err(|_| SignError::BadClaims)?);
	let signing_input = format!("{header_b64}.{payload_b64}");
	let rng = SystemRandom::new();
	let mut sig = vec![0u8; key_pair.public().modulus_len()];
	key_pair
		.sign(
			&signature::RSA_PKCS1_SHA256,
			&rng,
			signing_input.as_bytes(),
			&mut sig,
		)
		.map_err(|_| SignError::SigningFailed)?;
	Ok(format!("{signing_input}.{}", B64URL.encode(sig)))
}

/// Decode a PKCS#8 PEM block (with `BEGIN PRIVATE KEY` headers) to DER bytes.
/// Tolerant to blank lines and CRLF endings.
fn pem_to_pkcs8(pem: &str) -> Option<Vec<u8>> {
	let mut in_block = false;
	let mut der = Vec::new();
	for line in pem.lines() {
		let line = line.trim();
		if line.starts_with("-----BEGIN") {
			in_block = true;
			continue;
		}
		if line.starts_with("-----END") {
			break;
		}
		if !in_block || line.is_empty() {
			continue;
		}
		let bytes = B64STD.decode(line).ok()?;
		der.extend(bytes);
	}
	(!der.is_empty()).then_some(der)
}

#[cfg(test)]
#[path = "test_support.rs"]
pub(crate) mod test_support;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
#[cfg(test)]
#[path = "tests_txt.rs"]
mod tests_txt;

#[cfg(test)]
#[path = "tests_txt_forms.rs"]
mod tests_txt_forms;

#[cfg(test)]
#[path = "tests_contract.rs"]
mod tests_contract;
#[cfg(test)]
#[path = "tests_url.rs"]
mod tests_url;
