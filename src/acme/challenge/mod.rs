//! Answering ACME challenges (RFC 8555 §8).
//!
//! One [`ChallengeResponder`] per challenge type makes a domain's challenge
//! answerable before the CA is told to validate it, and withdraws it once
//! validation is over. The order flow in [`super::client`] withdraws every
//! challenge it published whether validation succeeded or not, so a TXT record
//! or a challenge certificate never outlives the order that needed it.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
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
	/// The zone every published challenge was published in, keyed by the
	/// challenge it belongs to. The withdrawal removes the record from the
	/// zone that holds it and asks the provider nothing: a lookup that
	/// fails at that moment must not send the removal to another zone and
	/// leave the record behind.
	published: Mutex<HashMap<(String, String), String>>,
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
			published: Mutex::new(HashMap::new()),
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

	/// The published zones, recovered when a thread that held the lock
	/// panicked. The map is a record of what was published, and a panic
	/// elsewhere must not take the withdrawal down with it.
	fn published_zones(&self) -> MutexGuard<'_, HashMap<(String, String), String>> {
		self.published
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// Keep the zone a challenge was published in, so the withdrawal
	/// removes the record from the same zone.
	fn remember(&self, domain: &str, token: &str, zone: &str) {
		self.published_zones()
			.insert((domain.to_string(), token.to_string()), zone.to_string());
	}

	/// The zone a challenge was published in, taken out of the record so a
	/// second withdrawal does not try to remove it again.
	fn forget(&self, domain: &str, token: &str) -> Option<String> {
		self.published_zones()
			.remove(&(domain.to_string(), token.to_string()))
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
			// The zone that holds the challenge name: a provider that
			// names its zones looks a zone up by its exact name, and the
			// ACME identifier is a name below the zone the credential
			// covers.
			let zone = crate::dns::zone::resolve(self.provider.as_ref(), domain)
				.await
				.map_err(|error| AcmeError::Protocol(format!("dns-01: publish: {error}")))?;
			// The zone is kept with the challenge before the write, so a
			// write that half-succeeded is withdrawn from the zone it
			// landed in.
			self.remember(domain, token, &zone);
			self.provider
				.upsert(&zone, record.clone())
				.await
				.map_err(|error| AcmeError::Protocol(format!("dns-01: publish: {error}")))?;
			self.wait_visible(&record).await
		})
	}

	fn withdraw<'a>(&'a self, domain: &'a str, token: &'a str, key: &'a AccountKey) -> Fut<'a, ()> {
		Box::pin(async move {
			let record = Self::record(domain, token, key);
			// The zone the challenge was published in. It is the one the
			// publish used, and the provider is not asked again: a
			// lookup that fails now would send the removal to a zone
			// that does not hold the record, and the record would stay.
			let Some(zone) = self.forget(domain, token) else {
				// The zone is not known: the challenge was never
				// published, or it was published by another run. The
				// record is left where it is rather than removed from a
				// zone nobody named.
				tracing::warn!(
					%domain,
					"dns-01: the zone the challenge was published in is not known; no record was removed"
				);
				return;
			};
			if let Err(error) = self.provider.delete(&zone, record).await {
				tracing::warn!(%error, %domain, "dns-01: challenge record not removed");
			}
		})
	}
}

#[cfg(test)]
mod tests;
