//! DNS provider configuration for record automation (e.g. publishing the TLSA
//! record when the certificate rotates).

use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;

use crate::dns::cloudflare::CloudflareProvider;
use crate::dns::provider::{DnsProvider, ScopedSecret};

/// DNS provider settings. When present with a usable token, record automation
/// is enabled; otherwise epistle stays in manual mode (operator publishes
/// records by hand).
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
	/// Provider id: `cloudflare` (more to come) or `manual`.
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
}

impl Dns {
	/// Build the configured provider, or `None` in manual mode / when no token
	/// is available (fail closed: no automation rather than a broken provider).
	pub fn build(&self) -> Option<Arc<dyn DnsProvider>> {
		match self.provider.to_ascii_lowercase().as_str() {
			"cloudflare" => Some(Arc::new(CloudflareProvider::new(self.secret()?))),
			_ => None,
		}
	}

	/// Resolve the scoped token from inline / env / file, in that precedence.
	fn secret(&self) -> Option<ScopedSecret> {
		if let Some(token) = &self.token {
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

impl std::fmt::Debug for Dns {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Dns")
			.field("provider", &self.provider)
			.field("zone", &self.zone)
			.field("token", &self.token.as_ref().map(|_| "***"))
			.field("token_file", &self.token_file)
			.field("token_env", &self.token_env)
			.finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn cfg(extra: &str) -> Dns {
		toml::from_str(&format!(
			"provider = \"cloudflare\"\nzone = \"example.org\"\n{extra}"
		))
		.expect("parse")
	}

	#[test]
	fn manual_provider_builds_nothing() {
		let dns: Dns = toml::from_str("provider = \"manual\"\nzone = \"example.org\"").unwrap();
		assert!(dns.build().is_none());
	}

	#[test]
	fn cloudflare_with_inline_token_builds() {
		let dns = cfg("token = \"abc\"");
		assert!(dns.build().is_some());
	}

	#[test]
	fn cloudflare_without_token_builds_nothing() {
		let dns = cfg("");
		assert!(dns.build().is_none());
	}

	#[test]
	fn debug_redacts_the_token() {
		let dns = cfg("token = \"super-secret\"");
		let rendered = format!("{dns:?}");
		assert!(!rendered.contains("super-secret"), "{rendered}");
		assert!(rendered.contains("***"), "{rendered}");
	}

	#[test]
	fn env_token_takes_effect() {
		unsafe { std::env::set_var("EPISTLE_TEST_DNS_PROVIDER_TOKEN", "tok") };
		let dns = cfg("token_env = \"EPISTLE_TEST_DNS_PROVIDER_TOKEN\"");
		assert!(dns.build().is_some());
	}
}
