//! Where a domain's rotation writes its key records.
//!
//! The rotation asks DNS for two things only: put a DKIM key record at a
//! name, and take the one at a name away. [`KeyPublisher`] is that and no
//! more, so the rotation does not depend on how the records reach the zone.
//! [`ProviderPublisher`] writes through the configured `[dns]` providers,
//! one write at a time across every domain that shares it.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind};

/// The answer of a publisher: `Err` carries why the write did not happen.
pub type PublishOp<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// Writes the DKIM key records of one rotation.
///
/// Both operations are repeated by a rotation that resumes after a crash, so
/// both must be idempotent: publishing the same value twice leaves one
/// record, and withdrawing a name that holds nothing succeeds.
pub trait KeyPublisher: Send + Sync {
	/// Make the TXT at `name` (`<selector>._domainkey.<domain>`) hold the key
	/// record `value`, replacing the DKIM record at that name.
	fn publish<'a>(&'a self, name: &'a str, value: &'a str) -> PublishOp<'a>;
	/// Remove the DKIM key record at `name`. A rotation names only selectors
	/// it made itself, so nothing else is expected at the name.
	fn withdraw<'a>(&'a self, name: &'a str) -> PublishOp<'a>;
}

/// A [`KeyPublisher`] over the `[dns]` providers.
///
/// A name goes to the longest of `zones` that contains it. A name inside
/// none of them is refused rather than written to some other zone. Every
/// write holds `writes`, which the server shares between the rotations of
/// all domains, so two domains never write to one provider at once: a
/// provider that rewrites a whole record set or zone could lose one of two
/// concurrent changes. Every write also holds the lock of the zone it goes
/// to, which the reconcile loop takes too (see
/// [`crate::dns::zone_lock`]).
pub struct ProviderPublisher {
	provider: Arc<dyn DnsProvider>,
	zones: Vec<String>,
	writes: Arc<tokio::sync::Mutex<()>>,
}

impl ProviderPublisher {
	/// Publish through `provider` in `zones`, with a write lock of its own.
	pub fn new(provider: Arc<dyn DnsProvider>, zones: Vec<String>) -> Self {
		ProviderPublisher {
			provider,
			zones,
			writes: Arc::new(tokio::sync::Mutex::new(())),
		}
	}

	/// Take `writes` as the lock every write holds, shared with other
	/// publishers.
	pub fn sharing_writes(mut self, writes: Arc<tokio::sync::Mutex<()>>) -> Self {
		self.writes = writes;
		self
	}

	/// The longest zone that contains `name`, or why there is none.
	fn zone_for(&self, name: &str) -> Result<&str, String> {
		self.zones
			.iter()
			.filter(|zone| crate::dkim::Rotator::is_in_zone(name, zone))
			.max_by_key(|zone| zone.len())
			.map(String::as_str)
			.ok_or_else(|| format!("{name} is in none of the [dns] zones"))
	}
}

fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 300,
		proxied: None,
	}
}

impl KeyPublisher for ProviderPublisher {
	fn publish<'a>(&'a self, name: &'a str, value: &'a str) -> PublishOp<'a> {
		Box::pin(async move {
			let zone = self.zone_for(name)?;
			let _write = self.writes.lock().await;
			// The lock of the zone: the reconcile loop publishes in the
			// same zone, and the two must not write it at the same time.
			let _zone = crate::dns::zone_lock::lock(zone).await;
			self.provider
				.upsert(zone, txt(name, value))
				.await
				.map_err(|error| format!("publish {name}: {error}"))
		})
	}

	fn withdraw<'a>(&'a self, name: &'a str) -> PublishOp<'a> {
		Box::pin(async move {
			let zone = self.zone_for(name)?;
			let _write = self.writes.lock().await;
			// The lock of the zone: the reconcile loop publishes in the
			// same zone, and the two must not write it at the same time.
			let _zone = crate::dns::zone_lock::lock(zone).await;
			// An empty value removes the TXT set at the name, the way the
			// `[dkim]` rotation retires a selector it made.
			self.provider
				.delete(zone, txt(name, ""))
				.await
				.map_err(|error| format!("withdraw {name}: {error}"))
		})
	}
}
