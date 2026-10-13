//! Multi-domain DKIM rotation: TXT publication must cover every in-zone
//! signing domain the relay signs for, not just the single domain the
//! rotator was originally configured with.

use super::*;
use std::pin::Pin;
use std::sync::Mutex;

use crate::dkim::test_support::KeyDns;
use crate::dns::provider::ProviderError;

const DAY: u64 = 86_400;
const RAW: &[u8] = b"From: alice@example.org\r\nSubject: rotation\r\n\r\nHello\r\n";

#[derive(Default)]
struct RecordingDns {
	records: Mutex<std::collections::HashMap<String, Vec<String>>>,
	upserts: Mutex<Vec<(String, String)>>,
	deletes: Mutex<Vec<String>>,
}

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

impl DnsProvider for RecordingDns {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		let entry = (record.name.clone(), record.value.clone());
		Box::pin(async move {
			self.upserts.lock().unwrap().push(entry);
			self.records
				.lock()
				.unwrap()
				.insert(record.name, vec![record.value]);
			Ok(())
		})
	}

	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		let name = record.name.clone();
		Box::pin(async move {
			self.deletes.lock().unwrap().push(name.clone());
			self.records.lock().unwrap().remove(&name);
			Ok(())
		})
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

#[derive(Default)]
struct FailSecondDomain {
	upserts: Mutex<Vec<String>>,
	deletes: Mutex<Vec<String>>,
}

impl DnsProvider for FailSecondDomain {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		let name = record.name.clone();
		Box::pin(async move {
			self.upserts.lock().unwrap().push(name.clone());
			if name.contains("mail.example.org") {
				Err(ProviderError::Remote("simulated outage".into()))
			} else {
				Ok(())
			}
		})
	}

	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		self.deletes.lock().unwrap().push(record.name);
		Box::pin(async { Ok(()) })
	}

	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

struct Fixture {
	_dir: tempfile::TempDir,
	signer: ReloadableSigner,
	rotator: Rotator,
	dns: Arc<RecordingDns>,
}

fn fixture(zone: &str, signing_domains: &[&str]) -> Fixture {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let root = dir.path().canonicalize().expect("absolute data dir");
	let (pem, record) = super::super::generate_key().expect("ed25519 key");
	let key_file = root.join("ed0.key");
	std::fs::write(&key_file, pem).expect("write ed25519 key");
	let signer = Signer::load("ed0", &key_file).expect("load ed25519");
	let dns = Arc::new(RecordingDns::default());
	for domain in signing_domains {
		dns.records
			.lock()
			.unwrap()
			.insert(format!("ed0._domainkey.{domain}"), vec![record.clone()]);
	}
	let signer = ReloadableSigner::new(Arc::new(signer));
	let rotator = Rotator::new(
		root.clone(),
		signer.clone(),
		dns.clone(),
		zone.to_string(),
		signing_domains.iter().map(|s| s.to_string()).collect(),
		30 * DAY,
		DAY,
	);
	let state = RotationState {
		selector: "ed0".into(),
		key_file,
		rotated_at: 0,
		previous: None,
		pending: None,
	};
	std::fs::write(
		root.join("dkim-rotation.json"),
		serde_json::to_vec(&state).expect("state JSON"),
	)
	.expect("write state");
	Fixture {
		_dir: dir,
		signer,
		rotator,
		dns,
	}
}

#[tokio::test]
async fn rotation_publishes_for_every_in_zone_domain() {
	let f = fixture("example.org", &["example.org", "mail.example.org"]);
	assert_eq!(
		f.rotator.tick(31 * DAY).await.expect("rotate"),
		Decision::Rotate
	);
	let names: Vec<String> = f
		.dns
		.upserts
		.lock()
		.unwrap()
		.iter()
		.map(|(name, _)| name.clone())
		.collect();
	assert!(
		names.iter().any(|n| n == "ed31._domainkey.example.org"),
		"missing apex upsert in {names:?}"
	);
	assert!(
		names
			.iter()
			.any(|n| n == "ed31._domainkey.mail.example.org"),
		"missing subdomain upsert in {names:?}"
	);
	let signed = f
		.signer
		.current()
		.sign("mail.example.org", RAW)
		.expect("sign mail.example.org");
	let mut bytes = signed.into_bytes();
	bytes.extend_from_slice(RAW);
	let dns = KeyDns(f.dns.records.lock().unwrap().clone());
	let results = crate::dkim::verify_message(&dns, &bytes).await;
	assert_eq!(
		results.len(),
		1,
		"signature for mail.example.org must verify against the rotator's published records"
	);
	assert_eq!(
		results[0].outcome,
		crate::dkim::DkimOutcome::Pass,
		"rotator must publish a v=DKIM1 record under mail.example.org for the subdomain signature to verify"
	);
}

#[tokio::test]
async fn rotation_retires_for_every_in_zone_domain() {
	let f = fixture("example.org", &["example.org", "mail.example.org"]);
	assert_eq!(
		f.rotator.tick(31 * DAY).await.expect("rotate"),
		Decision::Rotate
	);
	let now = 31 * DAY + ROTATE_OVERLAP_DAYS * DAY + 1;
	assert_eq!(
		f.rotator.tick(now).await.expect("retire"),
		Decision::Retire("ed0".into())
	);
	let deletes = f.dns.deletes.lock().unwrap().clone();
	assert!(
		deletes.iter().any(|n| n == "ed0._domainkey.example.org"),
		"missing apex delete in {deletes:?}"
	);
	assert!(
		deletes
			.iter()
			.any(|n| n == "ed0._domainkey.mail.example.org"),
		"missing subdomain delete in {deletes:?}"
	);
}

#[tokio::test]
async fn rotate_keeps_old_selector_when_one_upsert_fails() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let root = dir.path().canonicalize().expect("absolute data dir");
	let (pem, _) = super::super::generate_key().expect("ed25519 key");
	let key_file = root.join("ed0.key");
	std::fs::write(&key_file, pem).expect("write ed25519 key");
	let signer = Signer::load("ed0", &key_file).expect("load");
	let signer = ReloadableSigner::new(Arc::new(signer));
	let failing = Arc::new(FailSecondDomain::default());
	let dns: Arc<dyn DnsProvider> = failing.clone();
	let rotator = Rotator::new(
		root.clone(),
		signer.clone(),
		dns,
		"example.org".into(),
		vec!["example.org".into(), "mail.example.org".into()],
		30 * DAY,
		DAY,
	);
	let initial_selector = signer.current().dns_record_value();
	let state = RotationState {
		selector: "ed0".into(),
		key_file: key_file.clone(),
		rotated_at: 0,
		previous: None,
		pending: None,
	};
	std::fs::write(
		root.join("dkim-rotation.json"),
		serde_json::to_vec(&state).expect("state JSON"),
	)
	.expect("write state");
	let err = rotator
		.tick(31 * DAY)
		.await
		.expect_err("rotation must fail when an upsert fails");
	assert!(
		err.to_string().contains("mail.example.org"),
		"failure must name the failing domain, got {err}"
	);
	assert_eq!(
		signer.current().dns_record_value(),
		initial_selector,
		"active signer must not switch when an upsert fails"
	);
	let saved: RotationState = serde_json::from_slice(
		&std::fs::read(root.join("dkim-rotation.json")).expect("read state"),
	)
	.expect("state JSON");
	assert_eq!(
		saved.selector, "ed0",
		"persisted selector must remain the pre-rotation one"
	);
	let published = failing.upserts.lock().unwrap().clone();
	let withdrawn = failing.deletes.lock().unwrap().clone();
	let orphan = published
		.iter()
		.filter(|name| name.ends_with("._domainkey.example.org"))
		.find(|name| !withdrawn.contains(name));
	assert!(
		orphan.is_none(),
		"a record published before the failure must be withdrawn: {orphan:?}"
	);
}

#[tokio::test]
async fn rotate_skips_when_signing_domains_list_is_empty() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let root = dir.path().canonicalize().expect("absolute data dir");
	let (pem, _) = super::super::generate_key().expect("ed25519 key");
	let key_file = root.join("ed0.key");
	std::fs::write(&key_file, pem).expect("write key");
	let signer = Signer::load("ed0", &key_file).expect("load");
	let signer = ReloadableSigner::new(Arc::new(signer));
	let dns = Arc::new(RecordingDns::default());
	let rotator = Rotator::new(
		root.clone(),
		signer.clone(),
		dns.clone(),
		"example.org".into(),
		Vec::new(),
		30 * DAY,
		DAY,
	);
	let state = RotationState {
		selector: "ed0".into(),
		key_file,
		rotated_at: 0,
		previous: None,
		pending: None,
	};
	std::fs::write(
		root.join("dkim-rotation.json"),
		serde_json::to_vec(&state).expect("state JSON"),
	)
	.expect("write state");
	// With no in-zone domains the rotator has nothing to publish; the
	// signer must still rotate so the configured key material is no longer
	// signed with after the interval elapses, leaving the operator's
	// startup warning to explain why no TXT was actually written.
	assert_eq!(
		rotator.tick(31 * DAY).await.expect("rotate"),
		Decision::Rotate,
		"rotation runs even with no in-zone domains"
	);
	assert!(
		dns.upserts.lock().unwrap().is_empty(),
		"no upserts must be issued when there are no in-zone domains"
	);
}
