//! A DNS provider for tests of the dns-01 withdrawal: it records every
//! write with its zone, name and value, and can be told to fail or stall.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{Dns01, TxtVisibility};
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError};

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// Records `upsert ZONE NAME VALUE` and `delete ZONE NAME VALUE`.
pub(crate) struct FakeZone {
	calls: Mutex<Vec<String>>,
	zones: Vec<String>,
	/// The zone lookup fails instead of answering.
	pub(crate) lookup_fails: AtomicBool,
	/// A delete is recorded and then answers an error.
	pub(crate) delete_fails: AtomicBool,
	/// A delete is recorded and then never returns.
	pub(crate) delete_stalls: AtomicBool,
}

impl FakeZone {
	/// A provider that holds `zones`.
	pub(crate) fn new(zones: &[&str]) -> Arc<Self> {
		Arc::new(FakeZone {
			calls: Mutex::new(Vec::new()),
			zones: zones.iter().map(|zone| zone.to_string()).collect(),
			lookup_fails: AtomicBool::new(false),
			delete_fails: AtomicBool::new(false),
			delete_stalls: AtomicBool::new(false),
		})
	}

	/// Every write so far, in order.
	pub(crate) fn calls(&self) -> Vec<String> {
		self.calls.lock().expect("calls").clone()
	}

	/// The writes that were deletes.
	pub(crate) fn deletes(&self) -> Vec<String> {
		self.calls()
			.into_iter()
			.filter(|call| call.starts_with("delete "))
			.collect()
	}

	/// Wait up to five seconds for `count` deletes.
	pub(crate) async fn wait_for_deletes(&self, count: usize) -> Vec<String> {
		let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
		loop {
			let deletes = self.deletes();
			if deletes.len() >= count || tokio::time::Instant::now() >= deadline {
				return deletes;
			}
			tokio::time::sleep(Duration::from_millis(10)).await;
		}
	}

	fn push(&self, verb: &str, zone: &str, record: &DnsRecord) {
		self.calls
			.lock()
			.expect("calls")
			.push(format!("{verb} {zone} {} {}", record.name, record.value));
	}
}

impl DnsProvider for FakeZone {
	fn upsert(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		self.push("upsert", zone, &record);
		Box::pin(async { Ok(()) })
	}

	fn delete(&self, zone: &str, record: DnsRecord) -> Op<'_> {
		self.push("delete", zone, &record);
		if self.delete_stalls.load(Ordering::Relaxed) {
			return Box::pin(std::future::pending());
		}
		if self.delete_fails.load(Ordering::Relaxed) {
			return Box::pin(async { Err(ProviderError::Remote("the delete failed".into())) });
		}
		Box::pin(async { Ok(()) })
	}

	/// The zone lookup, which `lookup_fails` breaks. Reading a zone that
	/// was found goes on working: the lookup is what must not be asked
	/// again.
	fn has_zone<'a>(&'a self, zone: &'a str) -> crate::dns::provider::ZoneOp<'a> {
		let fails = self.lookup_fails.load(Ordering::Relaxed);
		let held = self.zones.iter().any(|held| held == zone);
		Box::pin(async move {
			if fails {
				Err(ProviderError::Remote("the lookup failed".into()))
			} else {
				Ok(held)
			}
		})
	}

	fn list(&self, zone: &str) -> ListOp<'_> {
		let held = self.zones.iter().any(|held| held == zone);
		let zone = zone.to_string();
		Box::pin(async move {
			if held {
				Ok(Vec::new())
			} else {
				Err(ProviderError::ZoneNotFound(zone))
			}
		})
	}
}

/// Answers that every record is visible, so a publish does not wait.
pub(crate) struct Visible;

impl TxtVisibility for Visible {
	fn visible<'a>(
		&'a self,
		_name: &'a str,
		_value: &'a str,
	) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
		Box::pin(async { true })
	}
}

/// A dns-01 responder over `provider` that does not wait for propagation.
pub(crate) fn dns01(provider: &Arc<FakeZone>) -> Dns01 {
	Dns01::new(provider.clone(), Arc::new(Visible)).with_bounds(Duration::ZERO, Duration::ZERO)
}
