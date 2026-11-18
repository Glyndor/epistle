//! Where a domain's rotation writes its key records.
//!
//! The rotation asks DNS for two things only: put a DKIM key record at a
//! name, and take the one at a name away. [`KeyPublisher`] is that and no
//! more, so the rotation does not depend on how the records reach the zone.
//! [`ProviderPublisher`] writes through the configured `[dns]` providers,
//! one write at a time across every domain that shares it, with the guarded
//! writer of [`crate::dns::publish::write`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::dns::provider::live::LiveProvider;
use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind, same_txt_purpose, txt_purpose};
use crate::dns::publish::write::{Unguarded, WriteError, replace_set};

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
	/// Called at the start of every cycle of the rotation: a publisher that
	/// holds a credential builds its provider again here. The default does
	/// nothing.
	fn refresh(&self) {}
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
	/// The provider again, when it is built once per cycle.
	live: Option<Arc<LiveProvider>>,
	zones: Vec<String>,
	writes: Arc<tokio::sync::Mutex<()>>,
}

impl ProviderPublisher {
	/// Publish through `provider` in `zones`, with a write lock of its own.
	pub fn new(provider: Arc<dyn DnsProvider>, zones: Vec<String>) -> Self {
		ProviderPublisher {
			provider,
			live: None,
			zones,
			writes: Arc::new(tokio::sync::Mutex::new(())),
		}
	}

	/// Publish through `live`, which is built again at the start of every
	/// cycle (see [`KeyPublisher::refresh`]).
	pub fn live(live: Arc<LiveProvider>, zones: Vec<String>) -> Self {
		let mut publisher = Self::new(Arc::clone(&live) as Arc<dyn DnsProvider>, zones);
		publisher.live = Some(live);
		publisher
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

/// Make `record` the DKIM key record at its name in `zone`: the DKIM record
/// there is replaced and nothing else is touched, under the precondition
/// that the set is still the one read (see [`crate::dns::publish::write`]).
/// A provider without a precondition gets the `upsert`, which replaces the
/// TXT of the same purpose. The caller holds the lock of the zone.
pub(crate) async fn publish_key(
	provider: &dyn DnsProvider,
	zone: &str,
	record: DnsRecord,
) -> Result<(), WriteError> {
	let name = record.name.clone();
	replace_set(
		provider,
		zone,
		&name,
		&RecordKind::Txt,
		|held| {
			held.iter()
				.filter(|r| !same_txt_purpose(&r.value, &record.value))
				.cloned()
				.chain([record.clone()])
				.collect()
		},
		Unguarded::Upsert(record.clone()),
		operation(),
	)
	.await
}

/// Take the DKIM key records at `name` in `zone` away, under the
/// precondition that the set is still the one read; a TXT of another purpose
/// at the name stays. A provider without a precondition gets the delete with
/// an empty value, which removes the TXT set at the name, the way the
/// `[dkim]` rotation retires a selector. The caller holds the lock of the
/// zone.
pub(crate) async fn withdraw_key(
	provider: &dyn DnsProvider,
	zone: &str,
	name: &str,
) -> Result<(), WriteError> {
	replace_set(
		provider,
		zone,
		name,
		&RecordKind::Txt,
		|held| {
			held.iter()
				.filter(|r| txt_purpose(&r.value) != Some("v=DKIM1"))
				.cloned()
				.collect()
		},
		Unguarded::Delete(txt(name, "")),
		operation(),
	)
	.await
}

/// The name of one write, so a lost answer can be resolved.
fn operation() -> String {
	format!("epistle-dkim-{}", uuid::Uuid::now_v7())
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
	fn refresh(&self) {
		if let Some(live) = &self.live {
			live.refresh_or_keep("per-domain DKIM rotation");
		}
	}

	fn publish<'a>(&'a self, name: &'a str, value: &'a str) -> PublishOp<'a> {
		Box::pin(async move {
			let zone = self.zone_for(name)?;
			let _write = self.writes.lock().await;
			// The lock of the zone: the reconcile loop publishes in the
			// same zone, and the two must not write it at the same time.
			let _zone = crate::dns::zone_lock::lock(zone).await;
			publish_key(self.provider.as_ref(), zone, txt(name, value))
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
			withdraw_key(self.provider.as_ref(), zone, name)
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
