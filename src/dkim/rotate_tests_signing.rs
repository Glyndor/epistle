//! Real signing and verification across automatic rotation.

use super::*;
use std::pin::Pin;
use std::sync::Mutex;

use crate::dkim::test_support::{KeyDns, signature_fields, signature_headers};
use crate::dns::provider::ProviderError;

const DAY: u64 = 86_400;
const RAW: &[u8] = b"From: alice@example.org\r\nSubject: rotation\r\n\r\nHello\r\n";

#[derive(Default)]
struct RecordingDns {
	records: Mutex<std::collections::HashMap<String, Vec<String>>>,
}

type Op<'a> = Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
type ListOp<'a> = Pin<Box<dyn Future<Output = Result<Vec<DnsRecord>, ProviderError>> + Send + 'a>>;

impl DnsProvider for RecordingDns {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			self.records
				.lock()
				.unwrap()
				.insert(record.name, vec![record.value]);
			Ok(())
		})
	}

	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			self.records.lock().unwrap().remove(&record.name);
			Ok(())
		})
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

fn fixture() -> Fixture {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let root = dir.path().canonicalize().expect("absolute data dir");
	let (pem, record) = super::super::generate_key().expect("ed25519 key");
	let key_file = root.join("ed0.key");
	std::fs::write(&key_file, pem).expect("write ed25519 key");
	let rsa_file = root.join("rsa.key");
	std::fs::write(&rsa_file, include_str!("test_rsa_key.pem")).expect("write RSA key");
	let signer = Signer::load("ed0", &key_file)
		.expect("load ed25519")
		.with_rsa("rsa-configured", &rsa_file)
		.expect("load RSA");
	let dns = Arc::new(RecordingDns::default());
	dns.records.lock().unwrap().extend([
		("ed0._domainkey.example.org".into(), vec![record]),
		(
			"rsa-configured._domainkey.example.org".into(),
			vec![signer.rsa_dns_record_value().expect("RSA record")],
		),
	]);
	// Rotation must retain the loaded RSA key rather than reload its file.
	std::fs::remove_file(rsa_file).expect("remove RSA file after loading");
	let signer = ReloadableSigner::new(Arc::new(signer));
	let rotator = Rotator::new(
		root.clone(),
		signer.clone(),
		dns.clone(),
		"example.org".into(),
		vec!["example.org".into()],
		30 * DAY,
		DAY,
	);
	let state = RotationState {
		selector: "ed0".into(),
		key_file,
		rotated_at: 0,
		previous: None,
		pending: None,
		rsa: None,
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

async fn verify(signer: &ReloadableSigner, dns: &RecordingDns) {
	let header = signer.current().sign("example.org", RAW).expect("sign");
	let lines = signature_headers(header.as_bytes());
	assert_eq!(
		lines.len(),
		2,
		"dual signing emits two verifiable signatures"
	);
	let signed = [lines[0].as_bytes(), RAW].concat();
	let dns = KeyDns(dns.records.lock().unwrap().clone());
	let results = crate::dkim::verify_message(&dns, &signed).await;
	assert_eq!(
		results.len(),
		1,
		"ed25519 signature is independently verifiable"
	);
	assert_eq!(
		results[0].outcome,
		crate::dkim::DkimOutcome::Pass,
		"ed25519 signature must verify with the published public key"
	);
	let rsa_selector = &signature_fields(header.as_bytes())[1].0;
	verify_rsa(
		&lines[1],
		&dns.0[&format!("{rsa_selector}._domainkey.example.org")][0],
	);
}

fn verify_rsa(line: &str, record: &str) {
	assert!(
		crate::dkim::test_support::rsa_verifies(line, record, RAW),
		"RSA signature must verify with the published public key"
	);
}

#[tokio::test]
async fn rotation_replaces_the_configured_rsa_key_too() {
	let f = fixture();
	verify(&f.signer, &f.dns).await;
	assert_eq!(
		f.rotator.tick(31 * DAY).await.expect("rotate"),
		Decision::Rotate
	);
	let header = f.signer.current().sign("example.org", RAW).expect("sign");
	assert_eq!(
		signature_fields(header.as_bytes()),
		vec![
			("ed31".into(), "example.org".into(), "ed25519-sha256".into()),
			("rsa31".into(), "example.org".into(), "rsa-sha256".into()),
		],
		"a dual-signing rotation puts a new RSA key in service with the new ed25519 one"
	);
	verify(&f.signer, &f.dns).await;
}
