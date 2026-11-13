//! Signing in two halves: the message is read into a header block, and only
//! the block reaches the key holder.

use super::*;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::dkim::test_support::KeyDns;

/// The PKCS#8 v2 envelope of an ed25519 key, around the seed and the public
/// key, the way `Ed25519KeyPair::generate_pkcs8` writes it.
fn ed25519_pem(seed: [u8; 32]) -> String {
	let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("seed");
	let mut der = vec![
		0x30, 0x53, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
		0x20,
	];
	der.extend_from_slice(&seed);
	der.extend_from_slice(&[0xa1, 0x23, 0x03, 0x21, 0x00]);
	der.extend_from_slice(pair.public_key().as_ref());
	pem_encode(&der)
}

/// A signer whose keys never change: an ed25519 key from a fixed seed and
/// the committed RSA test key.
fn fixed_signer(dir: &std::path::Path) -> Signer {
	let ed = dir.join("ed.pem");
	std::fs::write(&ed, ed25519_pem([7; 32])).expect("write ed25519 key");
	let rsa = dir.join("rsa.pem");
	std::fs::write(&rsa, include_str!("../../test_rsa_key.pem")).expect("write RSA key");
	Signer::load("sel", &ed)
		.expect("load ed25519")
		.with_rsa("rsasel", &rsa)
		.expect("load RSA")
}

const PLAIN: &str = "From: Alice <alice@example.org>\r\nTo: bob@example.net\r\nSubject: hello\r\nDate: Fri, 13 Nov 2026 10:00:00 +0000\r\nMessage-ID: <1@example.org>\r\nX-Other: kept out\r\n\r\nBody line\r\n\r\n\r\n";

const FOLDED: &str = "Resent-From: relay@example.org\r\nResent-Bad;Name: x\r\nSubject: a\r\n folded \t value\r\nFrom: alice@example.org\r\nCC: Carol\r\n <carol@example.net>\r\n\r\nbody\nwith bare line feeds\n";

/// What the signer wrote for [`PLAIN`] and [`FOLDED`] before it was split
/// into halves, captured from `develop` at 30a2235f. Both algorithms are deterministic, so a change here is a
/// change of what receivers verify.
const GOLDEN_PLAIN: &str = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org;\r\n\ts=sel; h=message-id:date:subject:to:from:from:to:cc:subject:reply-to:date:\r\n\tmessage-id:list-unsubscribe:list-unsubscribe-post:content-type:\r\n\tdisposition-notification-to:return-receipt-to:auto-submitted;\r\n\tbh=WgzUh9Cj9ZxoxfDX0KmEumMyCUUcs6RcTjwCBcKBIOc=; b=\r\n\tY0FHfygsQZI4RmiaoK4BcGUfJ98ZUuCgqseoPw1+QVkPr03kzoTGSjAhh9vk/Sm7\r\n\tHpE5ozu53cVIMvyq+P23BA==\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=rsasel;\r\n\th=message-id:date:subject:to:from:from:to:cc:subject:reply-to:date:\r\n\tmessage-id:list-unsubscribe:list-unsubscribe-post:content-type:\r\n\tdisposition-notification-to:return-receipt-to:auto-submitted;\r\n\tbh=WgzUh9Cj9ZxoxfDX0KmEumMyCUUcs6RcTjwCBcKBIOc=; b=\r\n\tgX1dGmN/pmFOUP5mHd63HTjzh9/9lteSGydzgYag0BedNqpGQfRRy1UwWk4Ee9g5\r\n\tnB3R/tvh+1wzkIyKBTsdge+erbwVrni42HCHhcYn+nNQXZXqja9Ct2JCnoduVk08\r\n\tTpf7z2KFRrkGWLBwKteM1H3uL33wd7mK+I81gmcj9hc8ecMMR3FwYtKGR5hmmew1\r\n\twqFAcmZ6/fKHrZrGjL7nbbJsfNZahFXXNi/HsqWMXOBZHFhsjevQhVlrQhQfzJVi\r\n\t84MJYpaqQtvuc3vU3uYtArITg3mBAtOOOMHhk1EhPNWEKA464um521pIcpyIM0JI\r\n\tggpoqNB9bmwkZ334b6TWKA==\r\n";

const GOLDEN_FOLDED: &str = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org;\r\n\ts=sel; h=cc:from:subject:resent-from:from:to:cc:subject:reply-to:date:\r\n\tmessage-id:list-unsubscribe:list-unsubscribe-post:content-type:\r\n\tdisposition-notification-to:return-receipt-to:auto-submitted;\r\n\tbh=dZvyjtyXOyRe6QCP62Q/S7Omps/slg7C1smbbvjKeKk=; b=\r\n\tbjamRigR54ORH3+1fDHb7J2ZD3h442KUh02LhxQ+YL3qAOGo66GmzPeFDcEL7Tfq\r\n\tqkkwiVLBDbjH0RPHqd0VDw==\r\nDKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; s=rsasel;\r\n\th=cc:from:subject:resent-from:from:to:cc:subject:reply-to:date:message-id:\r\n\tlist-unsubscribe:list-unsubscribe-post:content-type:\r\n\tdisposition-notification-to:return-receipt-to:auto-submitted;\r\n\tbh=dZvyjtyXOyRe6QCP62Q/S7Omps/slg7C1smbbvjKeKk=; b=\r\n\thqi1ltugwiwaymuTIWCbg57OivpjAVMnzRbnlmOCuwsuU2LI3zkI4ZcB3+CNyKRJ\r\n\tfF4z3dzYk4TNrQFe0rsGoxK8wcwq/TlbitKrT0YwyYNPyrLpDJgxOsQ6Hvxqqf+t\r\n\tfQglD+X4ydcyUHGhtR2c8KCUYCQfjmuIqwKmU3FFMW5U72OKg0DE/Nkp/oiHtl5Q\r\n\tYeBiCCTc3mZMzy4ngVhcGtUfZqsjkNNqhCUTwNOtpZkvNs12mpyfmHI4KCVX17Of\r\n\txwuENPKAxB3ZLRe5+fbpW7n/G5khyricyosdnLfr1lv5aNpZKEaRrBm5Hxm4rwwD\r\n\tnumomxeS+0cSrD2LxBLORQ==\r\n";

const GOLDEN: [(&str, &str); 2] = [(PLAIN, GOLDEN_PLAIN), (FOLDED, GOLDEN_FOLDED)];

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
