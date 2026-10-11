//! Real signing and verification across automatic rotation.

use super::*;
use std::pin::Pin;
use std::sync::Mutex;

use crate::dkim::test_support::{KeyDns, signature_fields};
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
	let lines: Vec<_> = header.lines().collect();
	assert_eq!(
		lines.len(),
		2,
		"dual signing emits two verifiable signatures"
	);
	let ed_header = format!("{}\r\n", lines[0]);
	let signed = [ed_header.as_bytes(), RAW].concat();
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
	verify_rsa(lines[1], &dns.0["rsa-configured._domainkey.example.org"][0]);
}

fn verify_rsa(line: &str, record: &str) {
	use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo};

	let value = line.strip_prefix("DKIM-Signature:").expect("RSA header");
	let signature = super::super::signature::parse(value).expect("parse RSA signature");
	let spki = super::super::parse_key(record).expect("decode RSA public key");
	let (_, public) = SubjectPublicKeyInfo::from_der(&spki).expect("RSA SPKI");
	let raw = std::str::from_utf8(RAW).expect("UTF-8 message");
	let (headers, body) = raw.split_once("\r\n\r\n").expect("message sections");
	let body = super::super::canon::body(signature.body_canon, body.as_bytes());
	assert!(
		signature.body_hash == ring::digest::digest(&ring::digest::SHA256, &body).as_ref(),
		"RSA body hash must cover the message body"
	);
	let mut input = String::new();
	for name in signature.signed_headers {
		let (name, value) = headers
			.lines()
			.filter_map(|line| line.split_once(':'))
			.find(|(field, _)| field.eq_ignore_ascii_case(&name))
			.expect("signed header");
		input.push_str(&super::super::canon::header(
			signature.header_canon,
			name,
			value,
		));
	}
	let unsigned = format!("{}b=", value.rsplit_once("b=").expect("signature value").0);
	let canonical =
		super::super::canon::header(signature.header_canon, "DKIM-Signature", &unsigned);
	input.push_str(canonical.strip_suffix("\r\n").expect("canonical CRLF"));
	let key = ring::signature::UnparsedPublicKey::new(
		&ring::signature::RSA_PKCS1_2048_8192_SHA256,
		public.subject_public_key.data.as_ref(),
	);
	assert!(
		key.verify(input.as_bytes(), &signature.signature).is_ok(),
		"RSA signature must verify with the configured public key"
	);
}

#[tokio::test]
async fn rotation_preserves_configured_rsa_signature() {
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
			(
				"rsa-configured".into(),
				"example.org".into(),
				"rsa-sha256".into()
			),
		],
		"rotation must keep the configured RSA signature alongside the new ed25519 selector"
	);
	verify(&f.signer, &f.dns).await;
}
