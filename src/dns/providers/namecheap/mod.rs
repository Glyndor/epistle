//! A Namecheap DNS provider implementing [`DnsProvider`]. Every call carries
//! the global parameters `ApiUser`, `ApiKey`, `UserName`, `ClientIp` and
//! `Command`; getHosts is a GET with them in the query string, setHosts a
//! form POST that replaces the whole host list (no record-id granularity).
//! A/AAAA/TXT/CNAME/MX/CAA are supported; SRV and TLSA are not, because
//! setHosts has no record type for them (DANE/TLSA must be added through an
//! external DNS host, or the operator keeps those records at a provider that
//! supports them).
//!
//! **Race warning.** `setHosts` replaces ALL records at the zone. Upserts and
//! deletes are implemented as read-modify-write: `getHosts` → mutate →
//! `setHosts`. If an operator (or another automation) edits the zone manually
//! between our `getHosts` and `setHosts`, their changes are silently dropped.
//! For zones epistle fully owns, this is fine; for shared zones, pair this with
//! a periodic drift check (`epistle dns-check`).
//!
//! **Authentication** packs `username:api_key` into [`ScopedSecret::token`]; the
//! provider does not modify the secret abstraction. Namecheap also requires
//! the calling IP to be on the account's API whitelist — operators must add
//! the production egress IP at
//! <https://www.namecheap.com/support/api/methods/>. A whitelisting failure
//! surfaces from Namecheap as a 4xx error with an `<Error>` body and is mapped
//! to [`ProviderError::Auth`].

use std::pin::Pin;

use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind, ScopedSecret};
use crate::dns::providers::namecheap::render::{host_from_record, host_label, split_sld_tld};
use crate::dns::providers::namecheap::xml::{Host, extract_hosts, parse_response};
use crate::net::HttpsUrl;

/// Namecheap's production API endpoint; overridable via
/// [`NamecheapProvider::with_api_url`] (tests, sandbox).
const DEFAULT_API_URL: &str = "https://api.namecheap.com/xml.response";

/// Namecheap's sandbox endpoint, for use with
/// [`NamecheapProvider::with_api_url`]. The sandbox requires sandbox
/// credentials, not production ones.
const SANDBOX_API_URL: &str = "https://api.sandbox.namecheap.com/xml.response";

/// Hard cap on response body reads; pairs with `reqwest`'s no-redirect
/// defaults to keep a hostile or compromised Namecheap mirror from streaming
/// unbounded bytes into the process.
const MAX_BODY: usize = 256 * 1024;

// Namecheap API error numbers we treat as auth failures (whitelist / disabled
// key) are defined in `xml` so they travel with the parser that uses them.

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A Namecheap-backed DNS provider for one zone.
pub struct NamecheapProvider {
	client: reqwest::Client,
	secret: ScopedSecret,
	api_user: String,
	api_key: String,
	client_ip: Option<std::net::Ipv4Addr>,
	base: HttpsUrl,
}

impl NamecheapProvider {
	/// Build a provider for the token's zone. The token must be
	/// `"<username>:<api_key>"`; the username doubles as both `ApiUser` and
	/// `UserName`. Returns [`ProviderError::Auth`] when the token is missing
	/// the separator or either side is empty (fail closed).
	pub fn new(secret: ScopedSecret) -> Result<Self, ProviderError> {
		let token = secret.token().to_string();
		let (api_user, api_key) = token.split_once(':').ok_or(ProviderError::Auth)?;
		if api_user.is_empty() || api_key.is_empty() {
			return Err(ProviderError::Auth);
		}
		Ok(NamecheapProvider {
			client: reqwest::Client::new(),
			secret,
			api_user: api_user.to_string(),
			api_key: api_key.to_string(),
			client_ip: None,
			base: HttpsUrl::from_static(DEFAULT_API_URL),
		})
	}

	/// The IPv4 address the API sees the calls come from, sent as the
	/// `ClientIp` global parameter. The API documents it as required on
	/// every call and accepts only IPv4.
	pub fn with_client_ip(mut self, ip: std::net::Ipv4Addr) -> Self {
		self.client_ip = Some(ip);
		self
	}

	/// The Namecheap sandbox URL, for use with [`Self::with_api_url`].
	pub fn sandbox_url() -> HttpsUrl {
		HttpsUrl::from_static(SANDBOX_API_URL)
	}

	/// Point the provider at an alternate API endpoint (tests, the
	/// [`Self::sandbox_url`], or a local mirror).
	pub fn with_api_url(mut self, url: HttpsUrl) -> Self {
		self.base = url;
		self
	}

	/// Whether `kind` can be published through Namecheap. setHosts takes A,
	/// AAAA, ALIAS, CAA, CNAME, MX, MXE, NS, TXT, URL, URL301 and FRAME, so
	/// SRV and TLSA are not.
	fn api_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A
			| RecordKind::Aaaa
			| RecordKind::Txt
			| RecordKind::Cname
			| RecordKind::Mx
			| RecordKind::Caa => Ok(kind.as_str()),
			// setHosts documents no SRV and no TLSA record type.
			RecordKind::Srv | RecordKind::Tlsa => Err(ProviderError::Unsupported),
		}
	}

	/// Reject a record the token is not scoped for, before any network call.
	fn authorize(&self, record: &DnsRecord) -> Result<(), ProviderError> {
		if self.secret.authorizes(&record.name) {
			Ok(())
		} else {
			Err(ProviderError::Auth)
		}
	}

	/// The global parameters every call carries: `ApiUser`, `ApiKey`,
	/// `UserName`, `ClientIp` and `Command`
	/// (<https://www.namecheap.com/support/api/global-parameters/>, read
	/// 2026-10-12). `ClientIp` is left out only when none was configured,
	/// and the API then refuses the call.
	fn global_params(&self, command: &str) -> Vec<(String, String)> {
		let mut params = vec![
			("ApiUser".to_string(), self.api_user.clone()),
			("ApiKey".to_string(), self.api_key.clone()),
			("UserName".to_string(), self.api_user.clone()),
		];
		if let Some(ip) = self.client_ip {
			params.push(("ClientIp".to_string(), ip.to_string()));
		}
		params.push(("Command".to_string(), command.to_string()));
		params
	}

	/// Build a GET request URL with the global parameters plus any
	/// command-specific extras (`SLD`/`TLD`). The URL is an [`HttpsUrl`]:
	/// the key cannot be put on a cleartext request, and every value is
	/// percent-encoded as a query pair.
	fn build_url(&self, command: &str, extra: &[(&str, &str)]) -> HttpsUrl {
		let mut url = self.base.clone();
		for (key, value) in self.global_params(command) {
			url = url.with_query(&key, &value);
		}
		for (key, value) in extra {
			url = url.with_query(key, value);
		}
		url
	}

	/// `getHosts` against Namecheap. Returns the parsed list of [`Host`]s
	/// currently published at the zone (an empty list if the zone has none).
	async fn get_hosts(&self, zone: &str) -> Result<Vec<Host>, ProviderError> {
		let (sld, tld) = split_sld_tld(zone);
		let url = self.build_url(
			"namecheap.domains.dns.getHosts",
			&[("SLD", &sld), ("TLD", &tld)],
		);
		let response = self
			.client
			.get(url.into_url())
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		let api = parse_response(response).await?;
		Ok(extract_hosts(api))
	}

	/// `setHosts` against Namecheap: "All host records that are not
	/// included into the API call will be deleted", so `hosts` is the whole
	/// zone. The hosts go as numbered parameters, and the documentation
	/// recommends a POST past ten of them
	/// (<https://www.namecheap.com/support/api/methods/domains-dns/set-hosts/>,
	/// read 2026-10-12); every call is a form POST, global parameters
	/// included, so the key stays out of the URL.
	async fn set_hosts(&self, zone: &str, hosts: &[Host]) -> Result<(), ProviderError> {
		let (sld, tld) = split_sld_tld(zone);
		let mut params = self.global_params("namecheap.domains.dns.setHosts");
		params.push(("SLD".into(), sld));
		params.push(("TLD".into(), tld));
		params.extend(set_hosts_params(hosts));
		let body = url::form_urlencoded::Serializer::new(String::new())
			.extend_pairs(&params)
			.finish();
		let response = self
			.client
			.post(self.base.clone().into_url())
			.header(
				reqwest::header::CONTENT_TYPE,
				"application/x-www-form-urlencoded",
			)
			.body(body)
			.send()
			.await
			.map_err(|e| ProviderError::Remote(e.to_string()))?;
		let _ = parse_response(response).await?;
		Ok(())
	}

	async fn upsert_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		Self::api_kind(record.kind)?;
		let mut hosts = self.get_hosts(zone).await?;
		let label = host_label(&record.name, zone);
		let kind_str = record.kind.as_str();
		// Drop any existing record at the same (name, kind) — we are replacing it.
		hosts.retain(|h| !(h.name == label && h.kind == kind_str));
		hosts.push(host_from_record(&record, zone)?);
		self.set_hosts(zone, &hosts).await
	}

	async fn delete_inner(&self, zone: &str, record: DnsRecord) -> Result<(), ProviderError> {
		self.authorize(&record)?;
		Self::api_kind(record.kind)?;
		let hosts = self.get_hosts(zone).await?;
		let label = host_label(&record.name, zone);
		let kind_str = record.kind.as_str();
		// The TXT matching rule from `src/dns/provider.rs` is the
		// contract: a value-bearing delete drops only the host whose
		// address matches the value (a sibling ACME challenge at the
		// same owner survives), an empty-value delete drops every host
		// at the label (the DKIM rotator's retire path). Other
		// record kinds fall through to the label-only match, which
		// is the existing whole-set semantics.
		let before = hosts.len();
		let hosts: Vec<Host> = hosts
			.into_iter()
			.filter(|h| {
				if !(h.name == label && h.kind == kind_str) {
					return true;
				}
				if record.kind == RecordKind::Txt && !record.value.is_empty() {
					!crate::dns::txt::same_txt_value(&h.address, &record.value)
				} else {
					false
				}
			})
			.collect();
		if hosts.len() == before {
			// Already absent: idempotent, no need to rewrite the zone.
			return Ok(());
		}
		self.set_hosts(zone, &hosts).await
	}

	async fn list_inner(&self, zone: &str) -> Result<Vec<DnsRecord>, ProviderError> {
		let hosts = self.get_hosts(zone).await?;
		Ok(hosts
			.into_iter()
			.filter_map(|h| crate::dns::providers::namecheap::xml::host_to_record(h, zone))
			.collect())
	}
}

impl DnsProvider for NamecheapProvider {
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

/// The `setHosts` parameters for `hosts`: one numbered `HostName`,
/// `RecordType`, `Address` and `TTL` per host, `MXPref` for an MX host, and
/// `EmailType=MX` when the zone has MX hosts. setHosts lists `EmailType`
/// as required and defines `MX` as "custom MX records of your mail
/// provider"; with no MX host it is left out, which is what other clients
/// of the API do (lego never sends it).
fn set_hosts_params(hosts: &[Host]) -> Vec<(String, String)> {
	let mut params = Vec::with_capacity(hosts.len() * 5 + 1);
	for (n, host) in hosts.iter().enumerate() {
		let n = n + 1;
		params.push((format!("HostName{n}"), host.name.clone()));
		params.push((format!("RecordType{n}"), host.kind.clone()));
		params.push((format!("Address{n}"), host.address.clone()));
		if host.ttl > 0 {
			params.push((format!("TTL{n}"), host.ttl.to_string()));
		}
		if host.kind == "MX" {
			let pref = host.mx_pref.unwrap_or(10);
			params.push((format!("MXPref{n}"), pref.to_string()));
		}
	}
	if hosts.iter().any(|h| h.kind == "MX") {
		params.push(("EmailType".into(), "MX".into()));
	}
	params
}

mod render;
mod xml;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests_basic.rs"]
mod tests_basic;

#[cfg(test)]
#[path = "tests_errors.rs"]
mod tests_errors;

#[cfg(test)]
#[path = "tests_render.rs"]
mod tests_render;

#[cfg(test)]
#[path = "tests_path.rs"]
mod tests_path;

#[cfg(test)]
#[path = "tests_txt_forms.rs"]
mod tests_txt_forms;

#[cfg(test)]
#[path = "tests_wire.rs"]
mod tests_wire;
