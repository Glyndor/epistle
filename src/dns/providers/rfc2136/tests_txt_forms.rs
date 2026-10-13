//! TXT encoding on the RFC 2136 wire: the character-strings each fixture
//! becomes, and the publish, read and compare round trip. RFC 2136 has no
//! list, so the read side is the provider's cache of what it wrote.

use super::tests::{
	ServerReply, ZONE, make_signing_pair, provider_with_endpoint, spawn_server, txt, wait_for_wire,
};
use super::*;
use crate::dns::txt::fixtures::{
	CALLER_QUOTED, CALLER_QUOTED_LOGICAL, SHORT, SPECIAL, all, dkim_rsa2048,
};
use crate::dns::txt::same_txt_value;
use hickory_resolver::proto::op::Message;

const NAME: &str = "sel._domainkey.example.org";

async fn server() -> (String, super::tests::CapturedVec) {
	spawn_server(|_| ServerReply::NoError {
		verify_signer: make_signing_pair(),
	})
	.await
}

/// The character-strings of every TXT update in the last message, with
/// its class.
async fn last_updates(captured: &super::tests::CapturedVec) -> Vec<(DNSClass, Vec<Vec<u8>>)> {
	let wire = wait_for_wire(captured).await;
	let msg = Message::from_vec(&wire).expect("parse UPDATE");
	msg.authorities
		.iter()
		.map(|r| match &r.data {
			RData::TXT(t) => (r.dns_class, t.txt_data.iter().map(|s| s.to_vec()).collect()),
			other => panic!("not a TXT update: {other:?}"),
		})
		.collect()
}

async fn added_strings(value: &str) -> Vec<Vec<u8>> {
	let (endpoint, captured) = server().await;
	provider_with_endpoint(endpoint)
		.upsert(ZONE, txt(NAME, value))
		.await
		.expect("upsert");
	let updates = last_updates(&captured).await;
	assert_eq!(updates.len(), 1, "a fresh cache sends only the add");
	updates[0].1.clone()
}

#[tokio::test]
async fn txt_short_value_is_one_character_string() {
	assert_eq!(added_strings(SHORT).await, vec![SHORT.as_bytes().to_vec()]);
}

#[tokio::test]
async fn txt_dkim_rsa2048_is_two_character_strings() {
	let value = dkim_rsa2048();
	assert_eq!(
		added_strings(&value).await,
		vec![
			value.as_bytes()[..255].to_vec(),
			value.as_bytes()[255..].to_vec()
		]
	);
}

/// The wire format is length-prefixed, so `"` and `\` travel as
/// themselves, with no escaping.
#[tokio::test]
async fn txt_quote_and_backslash_travel_unescaped() {
	assert_eq!(
		added_strings(SPECIAL).await,
		vec![SPECIAL.as_bytes().to_vec()]
	);
}

#[tokio::test]
async fn txt_caller_quoted_value_is_not_quoted_twice() {
	assert_eq!(
		added_strings(CALLER_QUOTED).await,
		vec![CALLER_QUOTED_LOGICAL.as_bytes().to_vec()]
	);
}

/// Publishing a value and then the same logical value again removes
/// exactly the RDATA the first write added and adds it back, so the zone
/// ends where it started; and a delete by the logical value forgets it.
#[tokio::test]
async fn txt_publish_read_compare_round_trip_reports_no_change() {
	for (value, logical) in all() {
		let (endpoint, captured) = server().await;
		let provider = provider_with_endpoint(endpoint);
		provider
			.upsert(ZONE, txt(NAME, &value))
			.await
			.expect("upsert");
		let first = last_updates(&captured).await;
		let cached = provider.txt_cache.lock().unwrap()[NAME].clone();
		assert_eq!(cached, vec![logical.clone()], "cached form of {value}");
		assert!(same_txt_value(&cached[0], &value), "{value}");
		provider
			.upsert(ZONE, txt(NAME, &logical))
			.await
			.expect("again");
		let second = last_updates(&captured).await;
		assert_eq!(second.len(), 2, "{value}");
		assert_eq!(second[0].0, DNSClass::NONE);
		assert_eq!(second[0].1, first[0].1, "removes what it added: {value}");
		assert_eq!(second[1].1, first[0].1, "adds the same RDATA: {value}");
		provider
			.delete(ZONE, txt(NAME, &logical))
			.await
			.expect("delete");
		assert!(
			provider.txt_cache.lock().unwrap()[NAME].is_empty(),
			"delete by the logical value forgets {value}"
		);
	}
}
