//! Answering ACME challenges (RFC 8555 §8).
//!
//! One [`ChallengeResponder`] per challenge type makes a domain's challenge
//! answerable before the CA is told to validate it, and withdraws it once
//! validation is over. The order flow in [`super::client`] withdraws every
//! challenge it published whether validation succeeded or not, so a TXT record
//! or a challenge certificate never outlives the order that needed it.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::client::AcmeError;
use super::http01::ChallengeStore;
use super::jws::AccountKey;
use super::tlsalpn::AlpnChallengeStore;
use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind};

type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Publishes and withdraws the answer to one type of ACME challenge.
pub trait ChallengeResponder: Send + Sync {
	/// The challenge type the CA names (`http-01`, `tls-alpn-01`, `dns-01`).
	fn kind(&self) -> &'static str;
	/// Make the challenge for `domain` answerable. Returns once the CA can
	/// see the answer, or an error when it never became visible.
	fn publish<'a>(
		&'a self,
		domain: &'a str,
		token: &'a str,
		key: &'a AccountKey,
	) -> Fut<'a, Result<(), AcmeError>>;
	/// Withdraw what [`ChallengeResponder::publish`] put in place. Best
	/// effort: a failure is logged, never returned, so it cannot mask the
	/// outcome of the order.
	fn withdraw<'a>(&'a self, domain: &'a str, token: &'a str, key: &'a AccountKey) -> Fut<'a, ()>;
}

impl ChallengeResponder for ChallengeStore {
	fn kind(&self) -> &'static str {
		"http-01"
	}

	fn publish<'a>(
		&'a self,
		_domain: &'a str,
		token: &'a str,
		key: &'a AccountKey,
	) -> Fut<'a, Result<(), AcmeError>> {
		self.set(token, &key.key_authorization(token));
		Box::pin(async { Ok(()) })
	}

	fn withdraw<'a>(
		&'a self,
		_domain: &'a str,
		token: &'a str,
		_key: &'a AccountKey,
	) -> Fut<'a, ()> {
		self.remove(token);
		Box::pin(async {})
	}
}

impl ChallengeResponder for Arc<AlpnChallengeStore> {
	fn kind(&self) -> &'static str {
		"tls-alpn-01"
	}

	fn publish<'a>(
		&'a self,
		domain: &'a str,
		token: &'a str,
		key: &'a AccountKey,
	) -> Fut<'a, Result<(), AcmeError>> {
		let result = self
			.set(domain, &key.key_authorization(token))
			.map_err(|error| AcmeError::Protocol(error.to_string()));
		Box::pin(async move { result })
	}

	fn withdraw<'a>(
		&'a self,
		domain: &'a str,
		_token: &'a str,
		_key: &'a AccountKey,
	) -> Fut<'a, ()> {
		self.remove(domain);
		Box::pin(async {})
	}
}

/// Whether a TXT value is served by every authoritative server of its zone.
pub trait TxtVisibility: Send + Sync {
	/// `true` once every authoritative server answers `name` with `value`.
	fn visible<'a>(&'a self, name: &'a str, value: &'a str) -> Fut<'a, bool>;
}

/// DNS-01: a `_acme-challenge.<domain>` TXT record published through the
/// configured `[dns]` provider.
pub struct Dns01 {
	provider: Arc<dyn DnsProvider>,
	visibility: Arc<dyn TxtVisibility>,
	timeout: Duration,
	interval: Duration,
}

/// How long a published record may take to reach every authoritative server
/// before the order is abandoned. Most providers propagate in seconds; a
/// few batch their zone pushes for a minute or two.
pub const DNS01_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(300);
const DNS01_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Short TTL so a stale challenge value expires quickly from caches.
const DNS01_TTL: u32 = 60;

impl Dns01 {
	/// Publish through `provider` and wait on `visibility`, with the
	/// production propagation bounds.
	pub fn new(provider: Arc<dyn DnsProvider>, visibility: Arc<dyn TxtVisibility>) -> Self {
		Dns01 {
			provider,
			visibility,
			timeout: DNS01_PROPAGATION_TIMEOUT,
			interval: DNS01_POLL_INTERVAL,
		}
	}

	/// Override the propagation bounds (tests use zero to fail at once).
	pub fn with_bounds(mut self, timeout: Duration, interval: Duration) -> Self {
		self.timeout = timeout;
		self.interval = interval;
		self
	}

	fn record(domain: &str, token: &str, key: &AccountKey) -> DnsRecord {
		DnsRecord {
			name: format!("_acme-challenge.{domain}"),
			kind: RecordKind::Txt,
			value: key.dns01_value(token),
			ttl: DNS01_TTL,
			proxied: None,
		}
	}

	/// Poll until the record is visible or `timeout` passes.
	async fn wait_visible(&self, record: &DnsRecord) -> Result<(), AcmeError> {
		let deadline = tokio::time::Instant::now() + self.timeout;
		loop {
			if self.visibility.visible(&record.name, &record.value).await {
				return Ok(());
			}
			if tokio::time::Instant::now() >= deadline {
				return Err(AcmeError::Protocol(format!(
					"dns-01: {} TXT not visible on the authoritative servers after {}s",
					record.name,
					self.timeout.as_secs()
				)));
			}
			tokio::time::sleep(self.interval).await;
		}
	}
}

impl ChallengeResponder for Dns01 {
	fn kind(&self) -> &'static str {
		"dns-01"
	}

	fn publish<'a>(
		&'a self,
		domain: &'a str,
		token: &'a str,
		key: &'a AccountKey,
	) -> Fut<'a, Result<(), AcmeError>> {
		Box::pin(async move {
			let record = Self::record(domain, token, key);
			self.provider
				.upsert(domain, record.clone())
				.await
				.map_err(|error| AcmeError::Protocol(format!("dns-01: publish: {error}")))?;
			self.wait_visible(&record).await
		})
	}

	fn withdraw<'a>(&'a self, domain: &'a str, token: &'a str, key: &'a AccountKey) -> Fut<'a, ()> {
		Box::pin(async move {
			let record = Self::record(domain, token, key);
			if let Err(error) = self.provider.delete(domain, record).await {
				tracing::warn!(%error, %domain, "dns-01: challenge record not removed");
			}
		})
	}
}
