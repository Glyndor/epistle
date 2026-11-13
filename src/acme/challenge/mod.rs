//! Answering ACME challenges (RFC 8555 §8).
//!
//! One [`ChallengeResponder`] per challenge type makes a domain's challenge
//! answerable before the CA is told to validate it, and withdraws it once
//! validation is over. The order flow in [`super::client`] withdraws every
//! challenge it published whether validation succeeded or not, so a TXT record
//! or a challenge certificate never outlives the order that needed it.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::client::AcmeError;
use super::http01::ChallengeStore;
use super::jws::AccountKey;
use super::tlsalpn::AlpnChallengeStore;
use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind};
use crate::dns::publish::write::{Unguarded, replace_set};
use crate::dns::txt::same_txt_value;

mod pending;
pub use pending::{PENDING_FILE, journal_path};
use pending::{Pending, PendingTxt};

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
	/// Withdraw everything this responder still has published, including
	/// what an earlier run of the server left behind. Run at startup and
	/// when the renewal loop stops. A responder whose answers live only in
	/// this process has nothing to do: they end with it.
	fn withdraw_pending(&self) -> Fut<'_, ()> {
		Box::pin(async {})
	}
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
	/// Every record published and not yet removed, with the zone it was
	/// published in. The withdrawal removes the record from the zone that
	/// holds it and asks the provider nothing: a lookup that fails at that
	/// moment must not send the removal to another zone and leave the
	/// record behind.
	published: Pending,
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
			published: Pending::in_memory(),
		}
	}

	/// Keep the published records in a journal at `path` as well, and take
	/// over the records an earlier run left in it, so a server that stopped
	/// before its withdrawal removes them at its next start (see
	/// [`ChallengeResponder::withdraw_pending`]).
	pub fn with_journal(mut self, path: PathBuf) -> Self {
		self.published = Pending::with_journal(path);
		self
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

	/// Remove one published record from the zone that holds it. It is
	/// forgotten only once the provider removed it: a withdrawal cancelled
	/// before the delete returned, or a delete that failed, is run again by
	/// the next withdrawal, at shutdown or at the next start.
	async fn remove(&self, entry: PendingTxt) {
		let record = entry.record.clone();
		let outcome = write_txt(
			self.provider.as_ref(),
			&entry.zone,
			&record,
			|held| {
				held.iter()
					.filter(|r| !same_txt_value(&r.value, &record.value))
					.cloned()
					.collect()
			},
			Unguarded::Remove(entry.record.clone()),
		)
		.await;
		match outcome {
			Ok(()) => self.published.remove(&entry.domain, &entry.token),
			Err(error) => {
				tracing::warn!(%error, domain = %entry.domain, "dns-01: challenge record not removed");
			}
		}
	}
}

/// Write the TXT set at the name of `record` in `zone` as `plan` makes it,
/// under the guarded contract, holding the lock of the zone the reconcile
/// loop takes too. A provider that checks no precondition gets `unguarded`,
/// the ordinary write.
async fn write_txt(
	provider: &dyn DnsProvider,
	zone: &str,
	record: &DnsRecord,
	plan: impl FnOnce(&[DnsRecord]) -> Vec<DnsRecord>,
	unguarded: Unguarded,
) -> Result<(), crate::dns::publish::write::WriteError> {
	let _lock = crate::dns::zone_lock::lock(zone).await;
	replace_set(
		provider,
		zone,
		&record.name,
		&RecordKind::Txt,
		plan,
		unguarded,
		format!("epistle-acme-{}", uuid::Uuid::now_v7()),
	)
	.await
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
			// The record and its zone are kept before the write, so a write
			// that half-succeeded is withdrawn from the zone it landed in,
			// by this run or, through the journal, by the next one.
			self.published
				.insert(PendingTxt {
					domain: domain.to_string(),
					token: token.to_string(),
					zone: zone.clone(),
					record: record.clone(),
				})
				.map_err(|error| {
					AcmeError::Protocol(format!("dns-01: publish: journal: {error}"))
				})?;
			write_txt(
				self.provider.as_ref(),
				&zone,
				&record,
				|held| {
					held.iter()
						.filter(|r| !same_txt_value(&r.value, &record.value))
						.cloned()
						.chain([record.clone()])
						.collect()
				},
				Unguarded::Upsert(record.clone()),
			)
			.await
			.map_err(|error| AcmeError::Protocol(format!("dns-01: publish: {error}")))?;
			self.wait_visible(&record).await
		})
	}

	fn withdraw<'a>(
		&'a self,
		domain: &'a str,
		token: &'a str,
		_key: &'a AccountKey,
	) -> Fut<'a, ()> {
		Box::pin(async move {
			// The zone the challenge was published in. It is the one the
			// publish used, and the provider is not asked again: a
			// lookup that fails now would send the removal to a zone
			// that does not hold the record, and the record would stay.
			let Some(entry) = self.published.get(domain, token) else {
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
			self.remove(entry).await;
		})
	}

	fn withdraw_pending(&self) -> Fut<'_, ()> {
		Box::pin(async move {
			let pending = self.published.all();
			if !pending.is_empty() {
				let domains: Vec<&str> =
					pending.iter().map(|entry| entry.domain.as_str()).collect();
				tracing::info!(
					?domains,
					"dns-01: withdrawing challenge records still published"
				);
			}
			for entry in pending {
				self.remove(entry).await;
			}
		})
	}
}

#[cfg(test)]
pub(crate) mod fake_zone;
#[cfg(test)]
mod tests;
