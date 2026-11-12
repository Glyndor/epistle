//! Signing while the DKIM key rotates: a selector is never used before its
//! key is published, and mail signed on either side of the switch verifies.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use epistle::dkim::rotate::RotationState;
use epistle::dkim::{DkimOutcome, ReloadableSigner, Rotator, Signer, generate_key, verify_message};
use epistle::dns::provider::{DnsProvider, DnsRecord, ProviderError};
use epistle::spf::{DnsFailure, DnsLookup};
use tokio::sync::Semaphore;

use super::support::*;

const DAY: u64 = 86_400;
const RAW: &[u8] = b"From: alice@example.org\r\nSubject: rotation\r\n\r\nHello\r\n";

type Lookup<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

/// A zone whose first publication of a new selector waits for the test, and
/// says when it got there.
struct GatedZone {
	records: Mutex<HashMap<String, Vec<String>>>,
	reached: Semaphore,
	gate: Semaphore,
}

impl GatedZone {
	fn published(&self, selector: &str) -> bool {
		let name = format!("{selector}._domainkey.example.org");
		self.records.lock().unwrap().contains_key(&name)
	}
}

impl DnsProvider for GatedZone {
	fn upsert(
		&self,
		_zone: &str,
		record: DnsRecord,
	) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + '_>> {
		Box::pin(async move {
			self.reached.add_permits(1);
			self.gate.acquire().await.expect("gate open").forget();
			self.records
				.lock()
				.unwrap()
				.insert(record.name, vec![record.value]);
			Ok(())
		})
	}

	fn delete(
		&self,
		_zone: &str,
		record: DnsRecord,
	) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + '_>> {
		Box::pin(async move {
			self.records.lock().unwrap().remove(&record.name);
			Ok(())
		})
	}

	fn list(
		&self,
		_zone: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

struct Resolver(HashMap<String, Vec<String>>);

impl DnsLookup for Resolver {
	fn txt(&self, name: &str) -> Lookup<'_, Vec<String>> {
		let found = self.0.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(found) })
	}

	fn addresses(&self, _name: &str) -> Lookup<'_, Vec<IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(&self, _name: &str) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

fn selector_of(signature: &str) -> String {
	signature
		.split(';')
		.find_map(|field| field.trim().strip_prefix("s="))
		.expect("s= tag")
		.to_string()
}

/// One signature, and whether its selector was published once it existed.
struct Sample {
	selector: String,
	published: bool,
	header: String,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signing_never_uses_a_selector_before_it_is_published() {
	seed("dkim rotation");
	let root = tempfile::tempdir().expect("data dir");
	let (pem, record) = generate_key().expect("ed25519 key");
	let key_file = root.path().join("ed0.key");
	std::fs::write(&key_file, pem).expect("write key");
	let zone = Arc::new(GatedZone {
		records: Mutex::new(HashMap::from([(
			"ed0._domainkey.example.org".to_string(),
			vec![record],
		)])),
		reached: Semaphore::new(0),
		gate: Semaphore::new(0),
	});
	let state = RotationState {
		selector: "ed0".into(),
		key_file: key_file.clone(),
		rotated_at: 0,
		previous: None,
		pending: None,
		rsa: None,
	};
	std::fs::write(
		root.path().join("dkim-rotation.json"),
		serde_json::to_vec(&state).expect("state JSON"),
	)
	.expect("write state");
	let signer = ReloadableSigner::new(Arc::new(Signer::load("ed0", &key_file).expect("signer")));
	let rotator = Rotator::new(
		root.path().to_path_buf(),
		signer.clone(),
		zone.clone(),
		"example.org".into(),
		vec!["example.org".into()],
		30 * DAY,
		DAY,
	);

	let stop = Arc::new(AtomicBool::new(false));
	let signed = Arc::new(AtomicUsize::new(0));
	let samples = Arc::new(Mutex::new(Vec::<Sample>::new()));
	let mut workers = tokio::task::JoinSet::new();
	for _ in 0..4 {
		let (signer, zone, stop, signed, samples) = (
			signer.clone(),
			zone.clone(),
			stop.clone(),
			signed.clone(),
			samples.clone(),
		);
		workers.spawn(async move {
			while !stop.load(Ordering::Acquire) {
				let header = signer.current().sign("example.org", RAW).expect("sign");
				let selector = selector_of(&header);
				// Publications only grow here, so a selector missing now was
				// missing when the signature was made.
				let published = zone.published(&selector);
				samples.lock().unwrap().push(Sample {
					selector,
					published,
					header,
				});
				signed.fetch_add(1, Ordering::AcqRel);
				tokio::task::yield_now().await;
			}
		});
	}

	let rotation = tokio::spawn(async move { rotator.tick(31 * DAY).await });
	// The rotator is inside the publication of the new selector.
	tokio::time::timeout(DEADLINE, zone.reached.acquire())
		.await
		.expect("publication deadline")
		.expect("reached")
		.forget();
	let before = signed.load(Ordering::Acquire);
	tokio::time::timeout(DEADLINE, async {
		while signed.load(Ordering::Acquire) < before + 64 {
			tokio::task::yield_now().await;
		}
	})
	.await
	.expect("signing continues while publication is held");
	assert!(
		samples.lock().unwrap().iter().all(|s| s.selector == "ed0"),
		"seed={SEED:#x} the signer switched before the new key was published"
	);

	zone.gate.add_permits(1);
	rotation
		.await
		.expect("rotation task")
		.expect("rotation completes");
	let after = signed.load(Ordering::Acquire);
	tokio::time::timeout(DEADLINE, async {
		while signed.load(Ordering::Acquire) < after + 64 {
			tokio::task::yield_now().await;
		}
	})
	.await
	.expect("signing continues after the switch");
	stop.store(true, Ordering::Release);
	while let Some(worker) = workers.join_next().await {
		worker.expect("signing worker");
	}

	let samples = std::mem::take(&mut *samples.lock().unwrap());
	let new = format!("ed{}", 31);
	assert!(
		samples.iter().any(|s| s.selector == new),
		"seed={SEED:#x} nothing signed with the rotated key"
	);
	let unpublished: Vec<_> = samples.iter().filter(|s| !s.published).collect();
	assert!(
		unpublished.is_empty(),
		"seed={SEED:#x} {} signatures used a selector nobody could verify",
		unpublished.len()
	);
	// Signatures from both sides of the switch verify, so the previous
	// selector stays published through the overlap.
	let resolver = Resolver(zone.records.lock().unwrap().clone());
	for selector in ["ed0", new.as_str()] {
		let sample = samples
			.iter()
			.find(|s| s.selector == selector)
			.unwrap_or_else(|| panic!("seed={SEED:#x} no signature under {selector}"));
		let message = [sample.header.as_bytes(), RAW].concat();
		let results = verify_message(&resolver, &message).await;
		assert_eq!(results.len(), 1);
		assert_eq!(
			results[0].outcome,
			DkimOutcome::Pass,
			"seed={SEED:#x} {selector} signature must verify"
		);
	}
}
