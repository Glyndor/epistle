//! Forwarded mail and the ARC chain it already carries: the sealing done
//! while forwarding has no DNS, so it only starts a chain, never extends one.

use super::base::{FORWARD_BODY, arc_sealer, message, redirect_sink};
use super::*;
use crate::arc::chain::{ChainValidation, extract};
use crate::storage::FsSpool;

#[test]
fn a_chain_made_by_another_domain_is_forwarded_without_a_new_instance() {
	let dir = tempfile::tempdir().expect("tempdir");
	// The first instance comes from a different hop.
	let first = arc_sealer("origin.example")
		.seal(FORWARD_BODY, "spf=pass", &[], ChainValidation::None)
		.expect("seal");
	let incoming = [first.as_bytes(), FORWARD_BODY].concat();

	let sink = redirect_sink(dir.path()).with_arc_sealer(arc_sealer("relay.example"));
	let mut msg = message(&["alice@example.org"]);
	msg.data = incoming.clone();
	sink.deliver(msg).expect("deliver");

	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	let entry = spool.load(ids[0]).expect("load");
	let chain = extract(&entry.data).expect("extract").expect("chain");
	assert_eq!(chain.len(), 1, "no instance 2 without a validated chain");
	let expected = [b"Delivered-To: alice@example.org\r\n".as_slice(), &incoming].concat();
	assert_eq!(entry.data, expected);
}

#[test]
fn arc_headers_that_do_not_form_a_chain_are_not_sealed_over() {
	let dir = tempfile::tempdir().expect("tempdir");
	// A lone seal, with no message signature or results beside it.
	let mut incoming =
		b"ARC-Seal: i=1; a=ed25519-sha256; d=o.example; s=s; cv=none; b=AAAA\r\n".to_vec();
	incoming.extend_from_slice(FORWARD_BODY);

	let sink = redirect_sink(dir.path()).with_arc_sealer(arc_sealer("relay.example"));
	let mut msg = message(&["alice@example.org"]);
	msg.data = incoming.clone();
	sink.deliver(msg).expect("deliver");

	let spool = FsSpool::open(dir.path()).expect("spool");
	let ids = spool.list().expect("list");
	let entry = spool.load(ids[0]).expect("load");
	let text = String::from_utf8_lossy(&entry.data);
	assert!(!text.contains("d=relay.example"), "{text}");
}
