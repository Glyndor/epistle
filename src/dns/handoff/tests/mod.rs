//! Tests for the DNS hand-off between the two containers of a split stack.
//!
//! The pieces the tests share: an in-memory zone that stands for the DNS
//! provider the certificates container holds, and a resolver that reads that
//! zone, so a rotation can confirm what was published.

use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::dns::handoff::{Operation, Outcome, Request, Server, requests_dir, results_dir};
use crate::dns::provider::{DnsProvider, DnsRecord, ProviderError};

pub(super) mod format;
pub(super) mod hostile;
pub(super) mod requests;
pub(super) mod rotation;
pub(super) mod selectors;
pub(super) mod server;
pub(super) mod writer;

/// The types of the provider trait are private aliases; the underlying type
/// is spelled out here so the test module can implement `DnsProvider`.
type Op<'a> = std::pin::Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> =
	std::pin::Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

/// An in-memory zone: what the fake provider holds and what the fake
/// resolver reads.
#[derive(Debug, Default)]
pub(super) struct FakeZone {
	records: Mutex<Vec<(String, String)>>,
	failing: AtomicBool,
}

impl FakeZone {
	/// A zone with nothing in it.
	pub(super) fn new() -> Arc<Self> {
		Arc::new(FakeZone::default())
	}

	/// Every record the zone holds, as `(name, value)`.
	pub(super) fn records(&self) -> Vec<(String, String)> {
		self.records.lock().expect("zone lock").clone()
	}

	/// The values at `name`.
	pub(super) fn values(&self, name: &str) -> Vec<String> {
		self.records
			.lock()
			.expect("zone lock")
			.iter()
			.filter(|(held, _)| held.eq_ignore_ascii_case(name))
			.map(|(_, value)| value.clone())
			.collect()
	}

	/// Put a record in the zone, as a provider that already holds it.
	pub(super) fn seed(&self, name: &str, value: &str) {
		self.records
			.lock()
			.expect("zone lock")
			.push((name.to_string(), value.to_string()));
	}

	/// Make every write fail, the way a provider whose credential expired
	/// fails.
	pub(super) fn fail(&self) {
		self.failing.store(true, Ordering::SeqCst);
	}
}

impl DnsProvider for FakeZone {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		let name = record.name.clone();
		let value = record.value.clone();
		Box::pin(async move {
			if self.failing.load(Ordering::SeqCst) {
				return Err(ProviderError::Remote(
					"the zone refused the write".to_string(),
				));
			}
			let mut records = self.records.lock().expect("zone lock");
			records.retain(|(held, _)| !held.eq_ignore_ascii_case(&name));
			records.push((name, value));
			Ok(())
		})
	}

	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		let name = record.name.clone();
		Box::pin(async move {
			if self.failing.load(Ordering::SeqCst) {
				return Err(ProviderError::Remote(
					"the zone refused the write".to_string(),
				));
			}
			let mut records = self.records.lock().expect("zone lock");
			records.retain(|(held, _)| !held.eq_ignore_ascii_case(&name));
			Ok(())
		})
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// A resolver that reads the fake zone, so a rotation can confirm the
/// record it published.
pub(super) struct FakeResolver {
	zone: Arc<FakeZone>,
}

impl FakeResolver {
	/// The resolver over `zone`.
	pub(super) fn new(zone: Arc<FakeZone>) -> Self {
		FakeResolver { zone }
	}
}

/// The type the resolver trait returns; the alias behind it is private to
/// the SPF module, so the test module spells it out.
type Lookup<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

impl crate::spf::DnsLookup for FakeResolver {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let values = self.zone.values(name);
		Box::pin(async move { Ok(values) })
	}

	fn addresses(&self, _name: &str) -> Lookup<'_, Vec<IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(&self, _name: &str) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// The zones and domains the tests configure.
pub(super) const ZONE: &str = "example.org";
pub(super) const DOMAIN: &str = "example.org";

/// The zones a test install publishes.
pub(super) fn zones() -> Vec<String> {
	vec![ZONE.to_string()]
}

/// The domains a test install serves.
pub(super) fn domains() -> Vec<String> {
	vec![DOMAIN.to_string()]
}

/// The selectors the operator configured: the ones in `[dkim]` and in a
/// `[[dkim.domain]]` entry. A rotation publishes and retires them, so the
/// serving side has to accept them.
pub(super) fn configured() -> Vec<String> {
	vec!["mail".to_string(), "custom".to_string()]
}

/// Write a request the way the asking side writes it.
pub(super) fn request(dir: &Path, id: &str, request: &Request) {
	let root = dir.join("dns-handoff");
	std::fs::create_dir_all(requests_dir(&root)).expect("requests dir");
	let bytes = serde_json::to_vec(request).expect("encode");
	crate::storage::write_secret(&requests_dir(&root).join(id), &bytes).expect("write");
}

/// The answer to the request `id`.
pub(super) fn answer(dir: &Path, id: &str) -> Outcome {
	let bytes = std::fs::read(results_dir(&dir.join("dns-handoff")).join(id)).expect("the answer");
	serde_json::from_slice(&bytes).expect("decode")
}

/// A request the serving side would accept, to change one thing at a time.
pub(super) fn accepted(id: &str) -> Request {
	Request {
		id: id.to_string(),
		operation: Operation::Publish,
		name: "ed1._domainkey.example.org".to_string(),
		kind: "TXT".to_string(),
		value: "v=DKIM1; k=ed25519; p=abc".to_string(),
		ttl: 300,
		created_at: crate::dns::handoff::writer::now(),
	}
}

/// Serve the request in `dir` and answer with what the zone holds and what
/// the answer says.
pub(super) async fn served(dir: &Path, id: &str) -> (Vec<(String, String)>, Outcome) {
	let zone = FakeZone::new();
	let server = Server::new(
		dir.join("dns-handoff"),
		zone.clone(),
		zones(),
		domains(),
		configured(),
	);
	server.serve_once().await;
	(zone.records(), answer(dir, id))
}
