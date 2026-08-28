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

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret};

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
}

/// A Google Cloud DNS-backed DNS provider for one managed zone.
pub struct GcloudProvider {
	client: reqwest::Client,
	account: ServiceAccount,
	zone: String,
	cached: Arc<Mutex<Option<CachedToken>>>,
	token_base: String,
	dns_base: String,
}

impl GcloudProvider {
	/// Build a provider for `secret.zone()` using the parsed service account.
	/// `secret.token()` is unused: Google authenticates by signature, not
	/// bearer, so the [`ScopedSecret`] is only a zone handle here.
	pub fn new(secret: ScopedSecret, account: ServiceAccount) -> Self {
		GcloudProvider {
			client: reqwest::Client::new(),
			account,
			zone: secret.zone().to_string(),
			cached: Arc::new(Mutex::new(None)),
			token_base: DEFAULT_TOKEN_BASE.to_string(),
			dns_base: DEFAULT_DNS_BASE.to_string(),
		}
	}

	/// Point the OAuth2 token endpoint at an alternate URL (tests).
	pub fn with_token_base(mut self, base: impl Into<String>) -> Self {
		self.token_base = base.into();
		self
	}

	/// Point the Cloud DNS API at an alternate URL (tests).
	pub fn with_dns_base(mut self, base: impl Into<String>) -> Self {
		self.dns_base = base.into();
		self
	}

	/// The Google API type token for a kind we can publish; MX/SRV need
	/// priority/weight handling we do not emit yet.
	fn api_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
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

	/// TXT values travel quoted in `rrdatas`; everything else is verbatim.
	fn rrdatas(&self, record: &DnsRecord) -> Vec<String> {
		if record.kind == RecordKind::Txt {
			vec![format!(
				"\"{}\"",
				record.value.replace('\\', "\\\\").replace('"', "\\\"")
			)]
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

	/// The managed-zone id (`name`) whose `dnsName` matches `zone`.
	async fn find_managed_zone(&self, zone: &str) -> Result<String, ProviderError> {
		let token = self.ensure_token().await?;
		let dns_name = format!("{}.", zone.trim_end_matches('.'));
		let url = format!(
			"{}/dns/v1/projects/{}/managedZones?dnsName={dns_name}",
			self.dns_base, self.account.project_id
		);
		let response = self
			.client
			.get(&url)
			.bearer_auth(&token)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
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

	async fn list_rrsets(&self, managed_zone: &str) -> Result<Vec<Rrset>, ProviderError> {
		let token = self.ensure_token().await?;
		let url = format!(
			"{}/dns/v1/projects/{}/managedZones/{managed_zone}/rrsets",
			self.dns_base, self.account.project_id
		);
		let response = self
			.client
			.get(&url)
			.bearer_auth(&token)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		Self::classify(&response, false)?;
		let text = self.read_body(response).await?;
		let parsed: ListRrsetsResp =
			serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))?;
		Ok(parsed.rrsets)
	}

	async fn post_change(
		&self,
		managed_zone: &str,
		additions: &[Rrset],
		deletions: &[Rrset],
	) -> Result<(), ProviderError> {
		let token = self.ensure_token().await?;
		let url = format!(
			"{}/dns/v1/projects/{}/managedZones/{managed_zone}/changes",
			self.dns_base, self.account.project_id
		);
		let body = serde_json::to_string(&json!({
			"additions": additions,
			"deletions": deletions,
		}))
		.map_err(|e| ProviderError::Remote(e.to_string()))?;
		let response = self
			.client
			.post(&url)
			.bearer_auth(&token)
			.header(reqwest::header::CONTENT_TYPE, "application/json")
			.body(body)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		Self::classify(&response, false)
	}

	async fn read_body(&self, response: reqwest::Response) -> Result<String, ProviderError> {
		response
			.text()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))
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
			.post(format!("{}/token", self.token_base))
			.header(
				reqwest::header::CONTENT_TYPE,
				"application/x-www-form-urlencoded",
			)
			.body(body)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
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
		Self::api_kind(record.kind)?;
		let managed_zone = self.find_managed_zone(zone).await?;
		let rrsets = self.list_rrsets(&managed_zone).await?;
		let kind_str = record.kind.as_str();
		let fqdn = self.fqdn(&record);
		let new_rrset = Rrset {
			name: fqdn.clone(),
			kind: kind_str.to_string(),
			ttl: record.ttl,
			rrdatas: self.rrdatas(&record),
		};
		match rrsets
			.into_iter()
			.find(|r| r.name == fqdn && r.kind == kind_str)
		{
			None => self.post_change(&managed_zone, &[new_rrset], &[]).await,
			Some(old) if old.ttl == new_rrset.ttl && old.rrdatas == new_rrset.rrdatas => Ok(()),
			Some(old) => self.post_change(&managed_zone, &[new_rrset], &[old]).await,
		}
	}

	async fn delete_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		Self::api_kind(record.kind)?;
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
				let kind = parse_kind(&r.kind);
				let name = r.name.trim_end_matches('.').to_string();
				r.rrdatas.into_iter().map(move |value| DnsRecord {
					name: name.clone(),
					kind,
					value: if kind == RecordKind::Txt {
						value.trim_matches('"').to_string()
					} else {
						value
					},
					ttl: r.ttl,
				})
			})
			.collect())
	}
}

impl DnsProvider for GcloudProvider {
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let zone = zone.to_string();
		Box::pin(async move { self.upsert_inner(&zone, record).await })
	}
	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		let zone = zone.to_string();
		Box::pin(async move { self.delete_inner(&zone, record).await })
	}
	fn list(&self, zone: &str) -> ListOp<'_> {
		let zone = zone.to_string();
		Box::pin(async move { self.list_inner(&zone).await })
	}
}

/// Map a Google type token to a [`RecordKind`], defaulting to TXT.
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
#[cfg(test)]
#[path = "gcloud_test_support.rs"]
mod test_support;
#[cfg(test)]
#[path = "gcloud_tests.rs"]
mod tests;
