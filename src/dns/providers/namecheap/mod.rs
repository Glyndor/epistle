//! A Namecheap DNS provider implementing [`DnsProvider`]. Namecheap's API takes
//! `ApiUser`, `ApiKey`, and `UserName` as query parameters on every call and
//! replaces the whole record set per `setHosts` (no record-id granularity).
//! A/AAAA/TXT/CNAME/MX/SRV are supported via their dedicated fields; TLSA is
//! not — Namecheap's UI/API does not publish TLSA records (DANE/TLSA must be
//! added through an external DNS host, or the operator keeps the DANE-relevant
//! records at a provider that does support them).
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
			base: HttpsUrl::from_static(DEFAULT_API_URL),
		})
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

	/// Whether `kind` can be published through Namecheap. TLSA is not — the
	/// API has no field for the usage/selector/matching/cert tuple.
	fn api_kind(kind: RecordKind) -> Result<&'static str, ProviderError> {
		match kind {
			RecordKind::A
			| RecordKind::Aaaa
			| RecordKind::Txt
			| RecordKind::Cname
			| RecordKind::Mx
			| RecordKind::Srv
			| RecordKind::Caa => Ok(kind.as_str()),
			RecordKind::Tlsa => Err(ProviderError::Unsupported),
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

	/// Build the full request URL with `ApiUser`/`ApiKey`/`UserName`/`Command`
	/// plus any command-specific extras (`SLD`/`TLD`). Namecheap takes its
	/// credentials in the query string, so the URL is an [`HttpsUrl`]: the
	/// key cannot be put on a cleartext request, and every value is
	/// percent-encoded as a query pair.
	fn build_url(&self, command: &str, extra: &[(&str, &str)]) -> HttpsUrl {
		let mut url = self
			.base
			.with_query("ApiUser", &self.api_user)
			.with_query("ApiKey", &self.api_key)
			.with_query("UserName", &self.api_user)
			.with_query("Command", command);
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

	/// `setHosts` against Namecheap. Replaces ALL records at the zone with the
	/// supplied list (empty list → no records).
	async fn set_hosts(&self, zone: &str, hosts: &[Host]) -> Result<(), ProviderError> {
		let (sld, tld) = split_sld_tld(zone);
		let url = self.build_url(
			"namecheap.domains.dns.setHosts",
			&[("SLD", &sld), ("TLD", &tld)],
		);
		let body = build_set_hosts_body(hosts);
		let response = self
			.client
			.post(url.into_url())
			.header(reqwest::header::CONTENT_TYPE, "application/xml")
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

/// Construct the XML body for `setHosts`: a `<request>` wrapper around the
/// rendered host elements.
fn build_set_hosts_body(hosts: &[Host]) -> String {
	let inner: String = hosts.iter().map(render_host).collect();
	format!(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><request>{inner}</request>"#)
}

/// Render a [`Host`] as the `<host …/>` XML element Namecheap's setHosts
/// accepts. Only the attributes meaningful for the kind are emitted.
fn render_host(host: &Host) -> String {
	let name = xml_attr_escape(&host.name);
	let kind = &host.kind;
	let address = xml_attr_escape(&host.address);
	let ttl = host.ttl;
	let base = format!(r#"Name="{name}" Type="{kind}" Address="{address}" TTL="{ttl}""#);
	match kind.as_str() {
		"MX" => match host.mx_pref {
			Some(p) => {
				format!(r#"Name="{name}" Type="MX" Address="{address}" MXPref="{p}" TTL="{ttl}""#)
			}
			None => base,
		},
		"SRV" => {
			let priority = host.priority.unwrap_or(0);
			let weight = host.weight.unwrap_or(0);
			let port = host.port.unwrap_or(0);
			format!(
				r#"Name="{name}" Type="SRV" Address="{address}" Priority="{priority}" Weight="{weight}" Port="{port}" TTL="{ttl}""#
			)
		}
		_ => base,
	}
}

/// Escape XML attribute special characters.
fn xml_attr_escape(value: &str) -> String {
	let mut out = String::with_capacity(value.len());
	for ch in value.chars() {
		match ch {
			'&' => out.push_str("&amp;"),
			'<' => out.push_str("&lt;"),
			'>' => out.push_str("&gt;"),
			'"' => out.push_str("&quot;"),
			'\'' => out.push_str("&apos;"),
			_ => out.push(ch),
		}
	}
	out
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
