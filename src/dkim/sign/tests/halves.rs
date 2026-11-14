//! Signing in two halves: the message is read into a header block, and only
//! the block reaches the key holder.

use super::*;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::dkim::test_support::{GOLDEN, KeyDns, PLAIN, ed25519_pem, fixed_signer};

#[test]
fn the_signature_is_the_same_bytes_as_before_the_split() {
	let dir = tempfile::tempdir().expect("tempdir");
	let signer = fixed_signer(dir.path());
	for (raw, expected) in GOLDEN {
		let signature = signer.sign("example.org", raw.as_bytes()).expect("signs");
		assert_eq!(signature, expected, "for {raw:?}");
	}
}

/// A key holder that keeps every block it is handed and signs nothing.
#[derive(Default)]
struct Recorder(Mutex<Vec<(String, HeaderBlock)>>);

impl KeyHolder for Recorder {
	fn sign_block(&self, domain: &str, block: &HeaderBlock) -> Result<String, Refusal> {
		self.0
			.lock()
			.expect("recorder")
			.push((domain.to_string(), block.clone()));
		Ok(String::new())
	}
}

#[test]
fn the_holder_gets_the_header_block_and_never_the_body() {
	let raw = b"From: alice@example.org\r\nSubject: hi\r\nX-Unsigned: field-marker\r\n\r\nbody-marker line\r\n";
	let recorder = Recorder::default();
	holder::sign_message(&recorder, "example.org", raw).expect("handed over");
	let seen = recorder.0.into_inner().expect("recorder");
	assert_eq!(seen.len(), 1);
	let (domain, block) = &seen[0];
	assert_eq!(domain, "example.org");
	assert_eq!(block.canonical, "subject:hi\r\nfrom:alice@example.org\r\n");
	assert!(block.names.starts_with("subject:from:"), "{}", block.names);
	for text in [&block.names, &block.canonical] {
		assert!(!text.contains("marker"), "{text:?}");
	}
	let body = canon::body(Canon::Relaxed, b"body-marker line\r\n");
	let hash = ring::digest::digest(&ring::digest::SHA256, &body);
	assert_eq!(&block.body_hash[..], hash.as_ref());
}

#[test]
fn a_message_the_reader_refuses_never_reaches_the_holder() {
	let recorder = Recorder::default();
	let two_froms = b"From: a@example.org\r\nFrom: b@example.org\r\n\r\nbody\r\n";
	assert!(holder::sign_message(&recorder, "example.org", two_froms).is_none());
	assert!(recorder.0.into_inner().expect("recorder").is_empty());
}

#[tokio::test]
async fn a_per_domain_holder_signs_with_the_override_and_verifies() {
	let dir = tempfile::tempdir().expect("tempdir");
	let default_key = dir.path().join("default.pem");
	std::fs::write(&default_key, ed25519_pem([1; 32])).expect("write key");
	let own_key = dir.path().join("own.pem");
	std::fs::write(&own_key, ed25519_pem([2; 32])).expect("write key");
	let default = Signer::load("def", &default_key).expect("load");
	let own = Signer::load("own", &own_key).expect("load");
	let record = own.dns_record_value();
	let holder = crate::dkim::PerDomainSigner::new(
		crate::dkim::ReloadableSigner::new(Arc::new(default)),
		vec![crate::dkim::DomainSigner {
			domain: "example.org".to_string(),
			signer: crate::dkim::ReloadableSigner::new(Arc::new(own)),
		}],
	);
	let block = HeaderBlock::from_message(PLAIN.as_bytes()).expect("block");
	let signature = holder.sign_block("example.org", &block).expect("signs");
	assert!(signature.contains("s=own;"), "{signature}");
	let mut signed = signature.into_bytes();
	signed.extend_from_slice(PLAIN.as_bytes());
	let dns = KeyDns(HashMap::from([(
		"own._domainkey.example.org".to_string(),
		vec![record],
	)]));
	let results = crate::dkim::verify_message(&dns, &signed).await;
	assert_eq!(results.len(), 1, "{results:?}");
	assert_eq!(results[0].outcome, crate::dkim::DkimOutcome::Pass);
}

#[test]
fn the_holder_refuses_each_malformed_block_and_signs_the_valid_one() {
	let dir = tempfile::tempdir().expect("tempdir");
	let signer = fixed_signer(dir.path());
	let valid = HeaderBlock::from_message(PLAIN.as_bytes()).expect("block");
	assert_eq!(valid.check(), Ok(()));
	assert!(signer.sign_block("example.org", &valid).is_ok());
	let edit = |change: &dyn Fn(&mut HeaderBlock)| {
		let mut block = valid.clone();
		change(&mut block);
		block
	};
	let cases: [(&str, HeaderBlock, Malformed); 9] = [
		(
			"an uppercase name",
			edit(&|b| b.names = b.names.replacen("from", "From", 1)),
			Malformed::Name,
		),
		(
			"a name with a semicolon",
			edit(&|b| b.names.push_str(":x;y")),
			Malformed::Name,
		),
		(
			"an empty name",
			edit(&|b| b.names.push(':')),
			Malformed::Name,
		),
		(
			"a line without its CRLF",
			edit(&|b| {
				let end = b.canonical.len() - 2;
				b.canonical.truncate(end);
			}),
			Malformed::Line,
		),
		(
			"a line feed inside a value",
			edit(&|b| b.canonical = b.canonical.replacen("hello", "hel\nlo", 1)),
			Malformed::Line,
		),
		(
			"a line with no colon",
			edit(&|b| b.canonical.insert_str(0, "nocolon\r\n")),
			Malformed::Line,
		),
		(
			"lines out of the order of h=",
			edit(&|b| {
				let mut lines: Vec<&str> = b.canonical.split_inclusive("\r\n").collect();
				lines.swap(0, 1);
				b.canonical = lines.concat();
			}),
			Malformed::Order,
		),
		(
			"no From line",
			edit(&|b| {
				b.names = b.names.replacen("from:", "", 1);
				b.canonical = b
					.canonical
					.split_inclusive("\r\n")
					.filter(|line| !line.starts_with("from:"))
					.collect();
			}),
			Malformed::From,
		),
		(
			"two From lines",
			edit(&|b| {
				b.names.insert_str(0, "from:");
				b.canonical.insert_str(0, "from:mallory@example.net\r\n");
			}),
			Malformed::From,
		),
	];
	for (case, block, expected) in cases {
		assert_eq!(block.check(), Err(expected), "{case}");
		assert_eq!(
			signer.sign_block("example.org", &block),
			Err(Refusal::Malformed(expected)),
			"{case}"
		);
	}
}
