//! The upsert contract for the TXT path against the RFC 2136 wire
//! mock: a TXT upsert emits a delete for every cached value of the
//! same purpose (the same `class NONE` shape `tests_b::txt_delete_keeps_the_sibling_challenge`
//! exercises) and one `class IN` add. Two records of the same purpose
//! at the same name (a real-world DNS configuration error: SPF returns
//! `permerror`, RFC 7208 §4.5) must end as exactly one TXT carrying
//! the new value. The cache is seeded with both duplicates so the
//! wire shape carries two deletes; a stale cache would leave one
//! duplicate published, the limitation the module doc names.

use std::collections::HashMap;

use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::DNSClass;

use super::tests::{
	ZONE, make_signing_pair, provider_with_endpoint_and_cache, spawn_server, txt, wait_for_wire,
	ServerReply,
};
use crate::dns::provider::DnsProvider;

const OLD_SPF_1: &str = "v=spf1 mx -all";
const OLD_SPF_2: &str = "v=spf1 include:_spf.google.com -all";
const NEW_SPF: &str = "v=spf1 -all";
const UNRELATED: &str = "google-site-verification=abc123";

#[tokio::test]
async fn txt_upsert_collapses_duplicates_of_the_same_purpose() {
	let signer = make_signing_pair();
	let signer_clone = signer.clone();
	let (endpoint, captured) = spawn_server(move |bytes| {
		signer_clone
			.verify_message_byte(bytes, None, true)
			.expect("verify");
		ServerReply::NoError {
			verify_signer: make_signing_pair(),
		}
	})
	.await;
	// Seed the cache with every value the apex currently holds:
	// two duplicate SPFs and one site verification TXT. The TXT
	// upsert must remove every same-purpose value (both old SPFs)
	// and leave the unrelated TXT alone. The cache is the
	// authoritative view for this provider (RFC 2136 has no
	// query path).
	let mut seed = HashMap::new();
	seed.insert(
		ZONE.to_string(),
		vec![
			OLD_SPF_1.to_string(),
			OLD_SPF_2.to_string(),
			UNRELATED.to_string(),
		],
	);
	let provider = provider_with_endpoint_and_cache(endpoint, seed);
	provider
		.upsert(ZONE, txt(ZONE, NEW_SPF))
		.await
		.expect("apex SPF upsert with duplicates");
	let wire = wait_for_wire(&captured).await;
	let msg = Message::from_vec(&wire).expect("parse UPDATE");
	let updates = &msg.authorities;
	// Wire: 2 class-NONE deletes (both old SPFs) + 1 add (new SPF).
	// The unrelated TXT is not in the cache for the SPF upsert.
	assert_eq!(
		updates.len(),
		3,
		"class-NONE delete for each old SPF plus the add for the new one, got {updates:?}"
	);
	let deletes: Vec<String> = updates
		.iter()
		.filter(|u| u.dns_class == DNSClass::NONE)
		.filter_map(|u| match &u.data {
			hickory_resolver::proto::rr::RData::TXT(t) => {
				let s: String = t
					.txt_data
					.iter()
					.map(|s| std::str::from_utf8(s).unwrap_or(""))
					.collect();
				Some(s)
			}
			_ => None,
		})
		.collect();
	let mut want = vec![OLD_SPF_1.to_string(), OLD_SPF_2.to_string()];
	want.sort();
	let mut got = deletes.clone();
	got.sort();
	assert_eq!(got, want, "both old SPFs are class-NONE deleted");
	let adds: Vec<&hickory_resolver::proto::rr::Record> = updates
		.iter()
		.filter(|u| u.dns_class == DNSClass::IN)
		.collect();
	assert_eq!(adds.len(), 1, "exactly one add, got {adds:?}");
	if let hickory_resolver::proto::rr::RData::TXT(t) = &adds[0].data {
		let got: String = t
			.txt_data
			.iter()
			.map(|s| std::str::from_utf8(s).unwrap_or(""))
			.collect();
		assert_eq!(got, NEW_SPF, "the add carries the new SPF");
	} else {
		panic!("add record is not TXT: {:?}", adds[0].data);
	}
}