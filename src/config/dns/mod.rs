//! DNS provider configuration for record automation (e.g. publishing the TLSA
//! record when the certificate rotates).

use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;

mod providers;
pub use providers::DnsProviders;

use crate::dns::provider::{DnsProvider, ScopedSecret};
use crate::dns::providers::bunny::BunnyProvider;
use crate::dns::providers::cloudflare::CloudflareProvider;
use crate::dns::providers::desec::DesecProvider;
use crate::dns::providers::digitalocean::DigitaloceanProvider;
use crate::dns::providers::dnsimple::DnsimpleProvider;
use crate::dns::providers::gcloud::{GcloudProvider, ServiceAccount};
use crate::dns::providers::godaddy::GodaddyProvider;
use crate::dns::providers::namecheap::NamecheapProvider;
use crate::dns::providers::ovh::OvhProvider;
use crate::dns::providers::porkbun::PorkbunProvider;
use crate::dns::providers::rfc2136::Rfc2136Provider;
use crate::dns::providers::route53::Route53Provider;
use crate::dns::providers::spaceship::SpaceshipProvider;

/// DNS provider settings. When present with usable credentials, record
/// automation is enabled; otherwise epistle stays in manual mode (operator
/// publishes records by hand).
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
	/// Provider id: `cloudflare`, `desec`, `digitalocean`, `gcloud`, `namecheap`,
	/// `porkbun`, `route53`, `rfc2136`, `spaceship`, or `manual`.
	pub provider: String,
	/// The DNS zone the token is scoped to (least privilege).
	pub zone: String,
	/// API token inline — discouraged; prefer `token_file` or `token_env`.
	#[serde(default)]
	pub token: Option<String>,
	/// Path to a `0600` file holding the API token.
	#[serde(default)]
	pub token_file: Option<PathBuf>,
	/// Environment variable holding the API token.
	#[serde(default)]
	pub token_env: Option<String>,
	/// Route 53: AWS access key id.
	#[serde(default)]
	pub access_key: Option<String>,
	/// Route 53: AWS secret access key (prefer `secret_key_env`).
	#[serde(default)]
	pub secret_key: Option<String>,
	/// Route 53: environment variable holding the AWS secret access key.
	#[serde(default)]
	pub secret_key_env: Option<String>,
	/// Route 53: the hosted zone id.
	#[serde(default)]
	pub hosted_zone_id: Option<String>,
	/// Provider-specific account identifier. DNSimple needs one alongside the
	/// token; it is not a secret and may sit in the config file.
	#[serde(default)]
	pub account_id: Option<String>,
	/// Provider endpoint or region selector. OVH has `ovh-eu`, `ovh-ca` and
	/// `ovh-us` APIs with separate credentials; RFC 2136 uses this for the
	/// nameserver `host:port` that accepts UPDATE messages.
	#[serde(default)]
	pub endpoint: Option<String>,
	/// Third credential part for providers whose API needs one beyond
	/// `access_key` and `secret_key`. OVH calls it the consumer key.
	#[serde(default)]
	pub consumer_key: Option<String>,
	/// Environment variable holding `consumer_key`, so it stays out of the
	/// config file.
	#[serde(default)]
	pub consumer_key_env: Option<String>,
	/// TSIG key name for RFC 2136. The key material itself travels through
	/// `token` / `token_env` / `token_file` as base64.
	#[serde(default)]
	pub key_name: Option<String>,
	/// TSIG algorithm for RFC 2136 (`hmac-sha256` by default when absent).
	#[serde(default)]
	pub algorithm: Option<String>,
	/// Path to a credentials file for providers that authenticate with one,
	/// such as a Google Cloud service-account JSON.
	#[serde(default)]
	pub credentials_file: Option<PathBuf>,
	/// Namecheap: the IPv4 address the API sees epistle's calls come from,
	/// sent as the `ClientIp` parameter the API requires on every call. It
	/// is the address on the account's API whitelist.
	#[serde(default)]
	pub client_ip: Option<String>,
}

/// Every provider name `Dns::build` recognises, in display order. Kept next
/// to `Dns::build` so the validation paths (the TOML loader in
/// `Config::validate` and the `epistle init` answers validator in
/// `answers_validate`) consult the same list the `match` consults; a name
/// in the list that does not build, or a name outside the list that does,
/// fails the `provider_list_matches_build` test that pins them together.
pub(crate) const SUPPORTED_PROVIDERS: &[&str] = &[
	"bunny",
	"cloudflare",
	"desec",
	"digitalocean",
	"dnsimple",
	"gcloud",
	"godaddy",
	"namecheap",
	"ovh",
	"porkbun",
	"route53",
	"rfc2136",
	"spaceship",
	"manual",
];

/// Whether `name` is in [`SUPPORTED_PROVIDERS`], matched case-insensitively.
/// `Dns::build` lowercases its own value; the loader and the answers
/// validator route through here so the comparison lives in one place.
pub(crate) fn is_supported_provider(name: &str) -> bool {
	SUPPORTED_PROVIDERS
		.iter()
		.any(|p| p.eq_ignore_ascii_case(name))
}

/// Every `match` arm in [`Dns::build`], in the same order. Used by
/// the build-invariant test: a name the build accepts (a recognised
/// arm) must also be in [`SUPPORTED_PROVIDERS`], so an operator
/// who configures `provider = "<name>"` reaches the same path
/// through the loader, the answers validator, and the build. The
/// two lists are kept together; a new arm without a corresponding
/// entry in `SUPPORTED_PROVIDERS` (and a new fixture in the build
/// test) fails the invariant.
#[cfg(test)]
pub(crate) const BUILD_ARM_NAMES: &[&str] = &[
	"cloudflare",
	"dnsimple",
	"bunny",
	"spaceship",
	"desec",
	"gcloud",
	"godaddy",
	"namecheap",
	"ovh",
	"route53",
	"porkbun",
	"digitalocean",
	"rfc2136",
	"manual",
];

/// Treat a `Some("")` or `Some("   ")` as absent. Inline credential
/// fields in `Dns` are `Option<String>`, so `Some("")` is the
/// TOML-level placeholder operators reach for while authoring; the
/// build must not turn that into a working provider that would then
/// send an empty `sso-key` header to GoDaddy, an empty bearer token
/// to DigitalOcean, and so on. The other providers (Cloudflare,
/// DNSimple) are already covered because they go through
/// [`Dns::secret`], which trims via this helper too.
fn non_empty(s: Option<String>) -> Option<String> {
	s.filter(|v| !v.trim().is_empty())
}

impl Dns {
	/// Build the configured provider, or `None` in manual mode / when
	/// credentials are missing (fail closed: no automation rather than a broken
	/// provider).
	pub fn build(&self) -> Option<Arc<dyn DnsProvider>> {
		self.build_inner(None)
	}

	/// Like [`Dns::build`], for a server named `hostname`: providers that can
	/// label records with their origin (Cloudflare tags) use it.
	pub fn build_for_host(&self, hostname: &str) -> Option<Arc<dyn DnsProvider>> {
		self.build_inner(Some(hostname))
	}

	fn build_inner(&self, hostname: Option<&str>) -> Option<Arc<dyn DnsProvider>> {
		match self.provider.to_ascii_lowercase().as_str() {
			"cloudflare" => {
				let provider = CloudflareProvider::new(self.secret()?);
				Some(Arc::new(match hostname {
					Some(host) => provider.with_hostname(host),
					None => provider,
				}))
			}
			"dnsimple" => {
				let account_id = self.account_id.clone()?;
				Some(Arc::new(DnsimpleProvider::new(self.secret()?, account_id)))
			}
			"bunny" => Some(Arc::new(BunnyProvider::new(self.secret()?))),
			"spaceship" => {
				let api_key = non_empty(self.access_key.clone())?;
				let api_secret = self.aws_secret()?;
				Some(Arc::new(SpaceshipProvider::new(
					api_key,
					api_secret,
					self.zone.clone(),
				)))
			}
			"desec" => Some(Arc::new(DesecProvider::new(self.secret()?))),
			"gcloud" => {
				let account = load_gcloud_account(self.credentials_file.as_deref()?)?;
				// An empty `private_key` would pass `serde_json` but
				// fail at JWT signing time, on the first operation
				// against the live API. The other providers reject
				// empty or whitespace-only credentials at build time
				// (see `non_empty` and `secret`); the gcloud arm
				// mirrors that by refusing to build a provider when
				// the parsed service account has no key material.
				// epistle stays in manual mode (the next call
				// returns `None`) instead of constructing a
				// provider that would later error on the first
				// write.
				if account.private_key.trim().is_empty() {
					None
				} else {
					Some(Arc::new(GcloudProvider::new(self.secret()?, account)))
				}
			}
			"namecheap" => {
				// The API refuses every call without `ClientIp`, so a
				// missing or non-IPv4 address builds no provider.
				let client_ip = self.client_ip.as_deref()?.trim().parse().ok()?;
				Some(Arc::new(
					NamecheapProvider::new(self.secret()?)
						.ok()?
						.with_client_ip(client_ip),
				))
			}
			"ovh" => {
				let application_key = non_empty(self.access_key.clone())?;
				let application_secret = self.aws_secret()?;
				let consumer_key = self.consumer_key()?;
				let secret = ScopedSecret::new(&self.zone, consumer_key);
				// A non-https endpoint fails closed like missing credentials:
				// no provider rather than one that would send its keys in clear.
				let base =
					crate::dns::providers::ovh::resolve_base(self.endpoint.as_deref()).ok()?;
				Some(Arc::new(
					OvhProvider::new(application_key, application_secret, secret).with_base(base),
				))
			}
			"route53" => {
				let access_key = non_empty(self.access_key.clone())?;
				let secret_key = self.aws_secret()?;
				let hosted_zone_id = non_empty(self.hosted_zone_id.clone())?;
				Some(Arc::new(Route53Provider::new(
					access_key,
					secret_key,
					hosted_zone_id,
				)))
			}
			"porkbun" => {
				let api_key = non_empty(self.access_key.clone())?;
				let secret = self.aws_secret()?;
				Some(Arc::new(PorkbunProvider::new(
					ScopedSecret::new(&self.zone, secret),
					api_key,
				)))
			}
			"digitalocean" => Some(Arc::new(DigitaloceanProvider::new(self.secret()?))),
			"rfc2136" => {
				let secret = self.secret()?;
				let key_name = non_empty(self.key_name.clone())?;
				let endpoint = non_empty(self.endpoint.clone())?;
				Some(Arc::new(
					Rfc2136Provider::new(secret, &key_name, self.algorithm.as_deref(), &endpoint)
						.ok()?,
				))
			}
			"godaddy" => {
				let api_key = non_empty(self.access_key.clone())?;
				let api_secret = self.aws_secret()?;
				Some(Arc::new(GodaddyProvider::new(
					api_key,
					api_secret,
					self.zone.clone(),
				)))
			}
			_ => None,
		}
	}

	/// The AWS secret access key from `secret_key_env` (preferred) or inline.
	/// Empty or whitespace-only values are treated as absent so a TOML
	/// placeholder (`secret_key = ""`) does not build a provider that
	/// then sends `sso-key :`.
	fn aws_secret(&self) -> Option<String> {
		if let Some(var) = &self.secret_key_env {
			return std::env::var(var).ok().filter(|s| !s.trim().is_empty());
		}
		non_empty(self.secret_key.clone())
	}

	/// The OVH consumer key from `consumer_key_env` (preferred) or inline.
	/// Same empty-string handling as [`Self::aws_secret`].
	fn consumer_key(&self) -> Option<String> {
		if let Some(var) = &self.consumer_key_env {
			return std::env::var(var).ok().filter(|s| !s.trim().is_empty());
		}
		non_empty(self.consumer_key.clone())
	}

	/// Resolve the scoped token from inline / env / file, in that precedence.
	/// The inline path trims and rejects empty values; the env / file
	/// paths already do (see [`ScopedSecret::from_env`] and
	/// [`ScopedSecret::from_file`]).
	fn secret(&self) -> Option<ScopedSecret> {
		if let Some(token) = non_empty(self.token.clone()) {
			return Some(ScopedSecret::new(&self.zone, token));
		}
		if let Some(var) = &self.token_env {
			return ScopedSecret::from_env(&self.zone, var);
		}
		if let Some(path) = &self.token_file {
			return ScopedSecret::from_file(&self.zone, path).ok();
		}
		None
	}
}

/// Load and parse a Google service-account JSON file.
fn load_gcloud_account(path: &std::path::Path) -> Option<ServiceAccount> {
	let bytes = std::fs::read(path).ok()?;
	serde_json::from_slice(&bytes).ok()
}

impl std::fmt::Debug for Dns {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Dns")
			.field("provider", &self.provider)
			.field("zone", &self.zone)
			.field("token", &self.token.as_ref().map(|_| "***"))
			.field("token_file", &self.token_file)
			.field("token_env", &self.token_env)
			// `access_key` carries the API key for GoDaddy, Porkbun,
			// OVH, Route 53 and Spaceship, redact it the same way
			// `token` and `secret_key` are redacted, so formatting or
			// logging a `Dns` never leaks credentials into operator
			// logs.
			.field("access_key", &self.access_key.as_ref().map(|_| "***"))
			.field("secret_key", &self.secret_key.as_ref().map(|_| "***"))
			.field("secret_key_env", &self.secret_key_env)
			.field("hosted_zone_id", &self.hosted_zone_id)
			.field("client_ip", &self.client_ip)
			.finish()
	}
}

#[cfg(test)]
mod tests;
