//! ARC sealing of forwarded mail, and the Sieve redirect fixtures it uses.

use super::base::{directory, message};
use super::*;
use std::fs;

/// A throwaway ARC sealer signing under `domain`.
pub(super) fn arc_sealer(domain: &str) -> std::sync::Arc<crate::arc::sealer::ArcSealer> {
	use ring::signature::Ed25519KeyPair;
	let rng = ring::rand::SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate");
	let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
	std::sync::Arc::new(crate::arc::sealer::ArcSealer::new(key, domain, "sel"))
}

/// Configure a Sieve redirect for alice and return the (account-rooted) sink.
pub(super) fn redirect_sink(dir: &std::path::Path) -> SplitDelivery {
	let account_dir = dir.join("accounts").join("alice");
	fs::create_dir_all(&account_dir).expect("mkdir");
	fs::write(
		account_dir.join("filter.sieve"),
		"redirect \"forward@example.com\";",
	)
	.expect("filter");
	SplitDelivery::new(dir, directory()).expect("sink")
}

/// AMS refuses to sign without a From header, so forwarded test mail carries one.
pub(super) const FORWARD_BODY: &[u8] = b"From: bob@example.net\r\nSubject: hi\r\n\r\nbody\r\n";

#[test]
fn forwarded_mail_gains_an_arc_seal() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = redirect_sink(dir.path()).with_arc_sealer(arc_sealer("relay.example"));
	let mut msg = message(&["alice@example.org"]);
	msg.data = FORWARD_BODY.to_vec();
	sink.deliver(msg).expect("deliver");

	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	let entry = spool.load(ids[0]).expect("load");
	let data = String::from_utf8_lossy(&entry.data);
	// A fresh chain: a complete first instance under our domain.
	assert!(data.contains("ARC-Seal:"), "{data}");
	assert!(data.contains("ARC-Message-Signature:"), "{data}");
	assert!(data.contains("ARC-Authentication-Results:"), "{data}");
	assert!(data.contains("d=relay.example"), "{data}");
	assert!(data.contains("cv=none"), "{data}");
}

#[test]
fn no_sealer_leaves_the_forwarded_copy_unchanged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sink = redirect_sink(dir.path());
	let mut msg = message(&["alice@example.org"]);
	msg.data = FORWARD_BODY.to_vec();
	sink.deliver(msg).expect("deliver");

	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	let entry = spool.load(ids[0]).expect("load");
	// Without a sealer the copy is forwarded byte-for-byte, under the
	// Delivered-To of the address that forwarded it.
	assert_eq!(
		entry.data,
		[
			b"Delivered-To: alice@example.org\r\n".as_slice(),
			FORWARD_BODY
		]
		.concat()
	);
}

#[test]
fn a_chain_we_already_sealed_is_not_resealed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let sealer = arc_sealer("relay.example");
	// Pre-seal the message as if we sealed it at inbound accept (i=1, our domain).
	let prepend = sealer
		.seal(
			FORWARD_BODY,
			"none",
			&[],
			crate::arc::chain::ChainValidation::None,
		)
		.expect("seal");
	let mut sealed = prepend.into_bytes();
	sealed.extend_from_slice(FORWARD_BODY);

	let sink = redirect_sink(dir.path()).with_arc_sealer(std::sync::Arc::clone(&sealer));
	let mut msg = message(&["alice@example.org"]);
	msg.data = sealed.clone();
	sink.deliver(msg).expect("deliver");

	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	let entry = spool.load(ids[0]).expect("load");
	// No second set: the forwarded copy is the already-sealed input under
	// its Delivered-To.
	let expected = [b"Delivered-To: alice@example.org\r\n".as_slice(), &sealed].concat();
	assert_eq!(entry.data, expected, "our domain must not double-seal");
	// Exactly one instance is present (i=1, no i=2).
	let chain = crate::arc::chain::extract(&entry.data)
		.expect("extract")
		.expect("chain");
	assert_eq!(chain.len(), 1, "expected a single ARC instance");
}
