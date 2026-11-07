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
/// concurrent changes.
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
			// An empty value removes the TXT set at the name, the way the
			// `[dkim]` rotation retires a selector it made.
			self.provider
				.delete(zone, txt(name, ""))
				.await
				.map_err(|error| format!("withdraw {name}: {error}"))
		})
	}
}

/// A [`KeyPublisher`] that asks the certificates container to do the
/// writing.
///
/// With the certificates container on, this process holds no DNS
/// credential: the record is written by the container that holds it, and
/// this one learns whether the write happened. The write goes through the
/// same hand-off the `[dkim]` key's rotation uses.
pub struct HandoffPublisher {
	/// The asking side of the hand-off.
	writer: crate::dns::handoff::Writer,
	/// The lock every write holds, shared with the other domains.
	writes: Arc<tokio::sync::Mutex<()>>,
}

impl HandoffPublisher {
	/// The publisher that writes through `writer`.
	pub fn new(writer: crate::dns::handoff::Writer) -> Self {
		HandoffPublisher {
			writer,
			writes: Arc::new(tokio::sync::Mutex::new(())),
		}
	}

	/// Take `writes` as the lock every write holds, shared with other
	/// publishers.
	pub fn sharing_writes(mut self, writes: Arc<tokio::sync::Mutex<()>>) -> Self {
		self.writes = writes;
		self
	}
}

impl KeyPublisher for HandoffPublisher {
	fn publish<'a>(&'a self, name: &'a str, value: &'a str) -> PublishOp<'a> {
		Box::pin(async move {
			let _write = self.writes.lock().await;
			self.writer
				.perform(crate::dns::handoff::Write::dkim(name, value))
				.await
		})
	}

	fn withdraw<'a>(&'a self, name: &'a str) -> PublishOp<'a> {
		Box::pin(async move {
			let _write = self.writes.lock().await;
			self.writer
				.perform(crate::dns::handoff::Write::withdraw(name))
				.await
		})
	}
}
