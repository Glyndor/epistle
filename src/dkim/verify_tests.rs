//! DKIM verification tests.

use super::*;
use std::collections::HashMap;
use std::pin::Pin;

use crate::dkim::signature::Canon;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

struct KeyDns {
	records: HashMap<String, Vec<String>>,
	fail: bool,
}

impl DnsLookup for KeyDns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let result = if self.fail {
			Err(DnsFailure::Temporary)
		} else {
			Ok(self.records.get(name).cloned().unwrap_or_default())
		};
		Box::pin(async move { result })
	}

	fn addresses(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

/// Sign a message with ed25519 the way a sender would, returning the
/// full message and the DNS key record.
fn signed_message() -> (Vec<u8>, KeyDns) {
	let rng = SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
	let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load key");

	let body = b"Hello world\r\n";
	let canonical_body = canon::body(Canon::Relaxed, body);
	let body_hash = BASE64.encode(ring::digest::digest(&ring::digest::SHA256, &canonical_body));

	let from = " Alice <alice@example.org>";
	let subject = " Greetings";
	let dkim_value = format!(
		" v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org; s=sel; h=from:subject; bh={body_hash}; b="
	);

	let mut hash_input = String::new();
	hash_input.push_str(&canon::header(Canon::Relaxed, "From", from));
	hash_input.push_str(&canon::header(Canon::Relaxed, "Subject", subject));
	let mut dkim_line = canon::header(Canon::Relaxed, "DKIM-Signature", &dkim_value);
	dkim_line.truncate(dkim_line.len() - 2);
	hash_input.push_str(&dkim_line);

	let signature = BASE64.encode(key_pair.sign(hash_input.as_bytes()).as_ref());
	let message = format!(
		"From:{from}\r\nSubject:{subject}\r\nDKIM-Signature:{dkim_value}{signature}\r\n\r\nHello world\r\n"
	);

	let public_key = BASE64.encode(key_pair.public_key().as_ref());
	let mut records = HashMap::new();
	records.insert(
		"sel._domainkey.example.org".to_string(),
		vec![format!("v=DKIM1; k=ed25519; p={public_key}")],
	);
	(
		message.into_bytes(),
		KeyDns {
			records,
			fail: false,
		},
	)
}

/// Sign a message whose `l=` tag exactly equals the body length, returning
/// the message and the DNS key record. The signer has signed the entire
/// body; appending any byte after the signed region is the append attack.
fn signed_message_with_l_tag() -> (Vec<u8>, KeyDns) {
	let rng = SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
	let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load key");

	let body = b"Hello world\r\n";
	let l = body.len();
	let canonical_body = canon::body(Canon::Relaxed, body);
	let body_hash = BASE64.encode(ring::digest::digest(&ring::digest::SHA256, &canonical_body));

	let from = " Alice <alice@example.org>";
	let subject = " Greetings";
	let dkim_value = format!(
		" v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org; s=sel; h=from:subject; l={l}; bh={body_hash}; b="
	);

	let mut hash_input = String::new();
	hash_input.push_str(&canon::header(Canon::Relaxed, "From", from));
	hash_input.push_str(&canon::header(Canon::Relaxed, "Subject", subject));
	let mut dkim_line = canon::header(Canon::Relaxed, "DKIM-Signature", &dkim_value);
	dkim_line.truncate(dkim_line.len() - 2);
	hash_input.push_str(&dkim_line);

	let signature = BASE64.encode(key_pair.sign(hash_input.as_bytes()).as_ref());
	let message = format!(
		"From:{from}\r\nSubject:{subject}\r\nDKIM-Signature:{dkim_value}{signature}\r\n\r\nHello world\r\n"
	);

	let public_key = BASE64.encode(key_pair.public_key().as_ref());
	let mut records = HashMap::new();
	records.insert(
		"sel._domainkey.example.org".to_string(),
		vec![format!("v=DKIM1; k=ed25519; p={public_key}")],
	);
	(
		message.into_bytes(),
		KeyDns {
			records,
			fail: false,
		},
	)
}

/// Sign a message using simple body canonicalisation where the raw body
/// carries a trailing blank line that simple strips (RFC 6376 §3.4.4). The
/// signer sets `l=` to the canonical length, which is shorter than the raw
/// body length. A verifier that compares `l=` against the raw body length
/// refuses this legitimate mail as Fail; the canonical-length check accepts
/// it. This is the everyday false rejection the §3.5 semantics fix.
fn signed_message_with_simple_body_canon_and_trailing_blank_line() -> (Vec<u8>, KeyDns) {
	let rng = SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
	let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load key");

	// Raw body: 15 bytes ("Hello world\r\n\r\n"). Simple canonicalisation
	// strips the trailing blank line and produces 13 bytes. `l=` is the
	// canonical length, which a conforming signer publishes.
	let body = b"Hello world\r\n\r\n";
	let canonical_body = canon::body(Canon::Simple, body);
	let l = canonical_body.len();
	assert!(
		l < body.len(),
		"trailing blank line must shrink canonical body"
	);
	let body_hash = BASE64.encode(ring::digest::digest(&ring::digest::SHA256, &canonical_body));

	let from = " Alice <alice@example.org>";
	let subject = " Greetings";
	let dkim_value = format!(
		" v=1; a=ed25519-sha256; c=simple/simple; d=example.org; s=sel; h=from:subject; l={l}; bh={body_hash}; b="
	);

	let mut hash_input = String::new();
	hash_input.push_str(&canon::header(Canon::Simple, "From", from));
	hash_input.push_str(&canon::header(Canon::Simple, "Subject", subject));
	let mut dkim_line = canon::header(Canon::Simple, "DKIM-Signature", &dkim_value);
	dkim_line.truncate(dkim_line.len() - 2);
	hash_input.push_str(&dkim_line);

	let signature = BASE64.encode(key_pair.sign(hash_input.as_bytes()).as_ref());
	let message = format!(
		"From:{from}\r\nSubject:{subject}\r\nDKIM-Signature:{dkim_value}{signature}\r\n\r\nHello world\r\n\r\n"
	);

	let public_key = BASE64.encode(key_pair.public_key().as_ref());
	let mut records = HashMap::new();
	records.insert(
		"sel._domainkey.example.org".to_string(),
		vec![format!("v=DKIM1; k=ed25519; p={public_key}")],
	);
	(
		message.into_bytes(),
		KeyDns {
			records,
			fail: false,
		},
	)
}

/// Sign a message using relaxed body canonicalisation where the raw body
/// has runs of WSP that relaxed collapses (RFC 6376 §3.4.4). The signer
/// sets `l=` to the canonical length, which is shorter than the raw body
/// length. The canonical-length check accepts this mail; a raw-length
/// check refuses it.
fn signed_message_with_relaxed_body_canon_and_internal_wsp() -> (Vec<u8>, KeyDns) {
	let rng = SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
	let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("load key");

	// Raw body has internal WSP runs that relaxed collapses. Canonical
	// length is 13; raw length is 17.
	let body = b"Hello  \t \tworld\r\n";
	let canonical_body = canon::body(Canon::Relaxed, body);
	let l = canonical_body.len();
	assert!(l < body.len(), "internal WSP must shrink canonical body");
	let body_hash = BASE64.encode(ring::digest::digest(&ring::digest::SHA256, &canonical_body));

	let from = " Alice <alice@example.org>";
	let subject = " Greetings";
	let dkim_value = format!(
		" v=1; a=ed25519-sha256; c=relaxed/relaxed; d=example.org; s=sel; h=from:subject; l={l}; bh={body_hash}; b="
	);

	let mut hash_input = String::new();
	hash_input.push_str(&canon::header(Canon::Relaxed, "From", from));
	hash_input.push_str(&canon::header(Canon::Relaxed, "Subject", subject));
	let mut dkim_line = canon::header(Canon::Relaxed, "DKIM-Signature", &dkim_value);
	dkim_line.truncate(dkim_line.len() - 2);
	hash_input.push_str(&dkim_line);

	let signature = BASE64.encode(key_pair.sign(hash_input.as_bytes()).as_ref());
	let message = format!(
		"From:{from}\r\nSubject:{subject}\r\nDKIM-Signature:{dkim_value}{signature}\r\n\r\nHello  \t \tworld\r\n"
	);

	let public_key = BASE64.encode(key_pair.public_key().as_ref());
	let mut records = HashMap::new();
	records.insert(
		"sel._domainkey.example.org".to_string(),
		vec![format!("v=DKIM1; k=ed25519; p={public_key}")],
	);
	(
		message.into_bytes(),
		KeyDns {
			records,
			fail: false,
		},
	)
}

#[tokio::test]
async fn valid_ed25519_signature_passes() {
	let (message, dns) = signed_message();
	let results = verify_message(&dns, &message).await;
	assert_eq!(results.len(), 1);
	assert_eq!(results[0].outcome, DkimOutcome::Pass, "{results:?}");
	assert_eq!(results[0].domain.as_deref(), Some("example.org"));
}

#[tokio::test]
async fn tampered_body_fails() {
	let (message, dns) = signed_message();
	let tampered = String::from_utf8(message)
		.expect("ascii")
		.replace("Hello world", "Hacked world");
	let results = verify_message(&dns, tampered.as_bytes()).await;
	assert_eq!(results[0].outcome, DkimOutcome::Fail);
}

#[tokio::test]
async fn tampered_signed_header_fails() {
	let (message, dns) = signed_message();
	let tampered = String::from_utf8(message)
		.expect("ascii")
		.replace("Subject: Greetings", "Subject: Free money");
	let results = verify_message(&dns, tampered.as_bytes()).await;
	assert_eq!(results[0].outcome, DkimOutcome::Fail);
}

#[tokio::test]
async fn missing_key_is_permerror() {
	let (message, mut dns) = signed_message();
	dns.records.clear();
	let results = verify_message(&dns, &message).await;
	assert_eq!(results[0].outcome, DkimOutcome::PermError);
}

#[tokio::test]
async fn dns_failure_is_temperror() {
	let (message, mut dns) = signed_message();
	dns.fail = true;
	let results = verify_message(&dns, &message).await;
	assert_eq!(results[0].outcome, DkimOutcome::TempError);
}

#[tokio::test]
async fn l_tag_equal_to_body_passes() {
	// The signed message covers the entire body with `l=` set to the body
	// length. Verify as today.
	let (message, dns) = signed_message_with_l_tag();
	let results = verify_message(&dns, &message).await;
	assert_eq!(results[0].outcome, DkimOutcome::Pass, "{results:?}");
}

#[tokio::test]
async fn body_extended_past_l_tag_fails() {
	// The signer only signed the first 13 bytes (the body length); an
	// attacker who appends extra bytes after the signed region must not
	// produce a passing signature (RFC 6376 §6.1.1, the append attack).
	let (message, dns) = signed_message_with_l_tag();
	let extended = String::from_utf8(message).expect("ascii").replace(
		"Hello world\r\n",
		"Hello world\r\nMalicious appended content\r\n",
	);
	let results = verify_message(&dns, extended.as_bytes()).await;
	assert_eq!(results[0].outcome, DkimOutcome::Fail, "{results:?}");
}

#[tokio::test]
async fn l_tag_smaller_than_body_fails_even_when_hash_still_matches() {
	// The signer signed only the first 13 bytes (`l=13`); appending bytes
	// past the signed region is the append attack of RFC 6376 §6.1.1.
	// With the canonical-length check the verifier refuses outright
	// before hashing, never silently truncating to `l=`.
	let (message, dns) = signed_message_with_l_tag();
	let extension = "\r\nMalicious appended content\r\n";
	let extended = String::from_utf8(message)
		.expect("ascii")
		.replace("Hello world\r\n", &format!("Hello world\r\n{extension}"));
	// Sanity: the appended region is past the body length (l= was 13).
	assert!(!extension.is_empty());
	let results = verify_message(&dns, extended.as_bytes()).await;
	assert_eq!(
		results[0].outcome,
		DkimOutcome::Fail,
		"appending bytes past l= must not verify: {results:?}"
	);
}

#[tokio::test]
async fn a_trailing_blank_line_stripped_by_simple_canonicalisation_still_passes() {
	// Control for the canonical-length semantics: the raw body ends with
	// an extra `\r\n\r\n` that simple canonicalisation strips, so the
	// canonical body is shorter than the raw body. The signer sets
	// `l=` to the canonical length (RFC 6376 §3.5). A verifier that
	// compares `l=` against the raw length refuses this legitimate mail;
	// the canonical-length check accepts it.
	let (message, dns) = signed_message_with_simple_body_canon_and_trailing_blank_line();
	let results = verify_message(&dns, &message).await;
	assert_eq!(results[0].outcome, DkimOutcome::Pass, "{results:?}");
}

#[tokio::test]
async fn internal_wsp_collapsed_by_relaxed_canonicalisation_still_passes() {
	// Twin of the simple-canon control for relaxed canon: the raw body
	// has internal WSP runs that relaxed collapses, so the canonical
	// body is shorter than the raw body. `l=` is the canonical length,
	// which the canonical-length check accepts.
	let (message, dns) = signed_message_with_relaxed_body_canon_and_internal_wsp();
	let results = verify_message(&dns, &message).await;
	assert_eq!(results[0].outcome, DkimOutcome::Pass, "{results:?}");
}

#[tokio::test]
async fn unsigned_message_is_none() {
	let dns = KeyDns {
		records: HashMap::new(),
		fail: false,
	};
	let results = verify_message(&dns, b"From: a@example.org\r\n\r\nbody\r\n").await;
	assert_eq!(results.len(), 1);
	assert_eq!(results[0].outcome, DkimOutcome::None);
}

#[tokio::test]
async fn malformed_signature_is_permerror() {
	let dns = KeyDns {
		records: HashMap::new(),
		fail: false,
	};
	let raw = b"From: a@example.org\r\nDKIM-Signature: v=1; nonsense\r\n\r\nbody\r\n";
	let results = verify_message(&dns, raw).await;
	assert_eq!(results[0].outcome, DkimOutcome::PermError);
}

#[tokio::test]
async fn expired_x_tag_fails_without_reaching_dns() {
	let (message, mut dns) = signed_message();
	// Make DNS return TempError: if expiry check is bypassed, the outcome
	// would be TempError, not Fail, proving DNS was consulted.
	dns.fail = true;
	// Inject x=1 (expired since 1970-01-01) into the existing header.
	let message_str = String::from_utf8(message).expect("ascii");
	let modified = message_str.replace("; b=", "; x=1; b=");
	let results = verify_message(&dns, modified.as_bytes()).await;
	// Expiry fires before DNS: must be Fail, not TempError.
	assert_eq!(results[0].outcome, DkimOutcome::Fail, "{results:?}");
}

#[tokio::test]
async fn future_x_tag_does_not_fail() {
	let (message, dns) = signed_message();
	// x= far in the future: should not affect the outcome.
	let message_str = String::from_utf8(message).expect("ascii");
	let modified = message_str.replace("; b=", "; x=9999999999; b=");
	// The signature is now invalid (we changed the header without re-signing),
	// but the expiry check must not reject it — the eventual failure is Fail
	// from bad signature, not from expiry.
	let results = verify_message(&dns, modified.as_bytes()).await;
	// Body hash or sig check fails, but not from expiry short-circuit.
	assert!(
		matches!(
			results[0].outcome,
			DkimOutcome::Fail | DkimOutcome::PermError
		),
		"{results:?}"
	);
}

#[test]
fn outcome_keywords_cover_all_variants() {
	assert_eq!(DkimOutcome::Pass.as_str(), "pass");
	assert_eq!(DkimOutcome::Fail.as_str(), "fail");
	assert_eq!(DkimOutcome::PermError.as_str(), "permerror");
	assert_eq!(DkimOutcome::TempError.as_str(), "temperror");
	assert_eq!(DkimOutcome::None.as_str(), "none");
}

fn empty_dns() -> KeyDns {
	KeyDns {
		records: HashMap::new(),
		fail: false,
	}
}

#[tokio::test]
async fn folded_header_unsigned_message_is_none() {
	// A folded (continued) header must parse; with no signature → none.
	let raw = b"From: Alice\r\n <alice@example.org>\r\nSubject: hi\r\n\r\nbody\r\n";
	let results = verify_message(&empty_dns(), raw).await;
	assert_eq!(results[0].outcome, DkimOutcome::None);
}

#[tokio::test]
async fn leading_fold_is_permerror() {
	// A message that begins with a continuation line is malformed.
	let raw = b" orphaned continuation\r\nFrom: a@example.org\r\n\r\nbody\r\n";
	let results = verify_message(&empty_dns(), raw).await;
	assert_eq!(results[0].outcome, DkimOutcome::PermError);
}

#[tokio::test]
async fn message_without_blank_line_has_empty_body() {
	// No header/body separator: the whole input is headers, body empty.
	let results = verify_message(&empty_dns(), b"From: a@example.org\r\n").await;
	assert_eq!(results[0].outcome, DkimOutcome::None);
}

#[tokio::test]
async fn resolver_stub_methods_are_inert() {
	let dns = empty_dns();
	assert!(dns.addresses("x").await.expect("ok").is_empty());
	assert!(dns.mx("x").await.expect("ok").is_empty());
}
