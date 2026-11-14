//! Provider state, construction, zone authorization, and trait dispatch.

use std::pin::Pin;

use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError};
use crate::net::HttpsUrl;

use super::lock;

/// GoDaddy's API base; overridable for tests.
const DEFAULT_BASE: &str = "https://api.godaddy.com/v1";

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// A GoDaddy-backed DNS provider for one zone.
pub struct GodaddyProvider {
	pub(super) client: reqwest::Client,
	/// The (non-secret) API key paired with the secret.
	pub(super) api_key: String,
	/// The secret half of the API key pair. The provider never logs it; the
	/// only place it leaves the struct is the `sso-key` header.
	pub(super) api_secret: String,
	/// The zone every record is scoped to.
	pub(super) zone: String,
	pub(super) base: HttpsUrl,
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

	/// Reject a record outside the configured zone before any network call.
	pub(super) fn authorize(&self, record: &DnsRecord) -> Result<(), ProviderError> {
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
}

impl DnsProvider for GodaddyProvider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(crate::dns::providers::within(async move {
			let _turn = lock::hold(&self.api_key, &self.zone).await;
			self.upsert_inner(record).await
		}))
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(crate::dns::providers::within(async move {
			let _turn = lock::hold(&self.api_key, &self.zone).await;
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
