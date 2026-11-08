use super::*;

/// An RSA-2048 DKIM `p=` value is roughly 410 bytes; hickory rejects
/// character-strings past 255 octets, so the provider has to split long
/// TXT values into 255-octet chunks before sending. The wire format
/// keeps the order of the strings and the resolver concatenates them
/// back into one logical record. A failure here means the message
/// never reaches the nameserver, so a 410-byte DKIM cannot be
/// published at all.
#[tokio::test]
async fn long_txt_value_is_split_into_255_octet_character_strings() {
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
	let provider = provider_with_endpoint(endpoint);
	// 410 bytes of base64-shaped ASCII, the size of an RSA-2048 DKIM
	// public key. The value is intentionally a single line of `A`s so
	// the only bytes are 0x41; the split is purely a length split.
	let value: String = "A".repeat(410);
	assert_eq!(value.len(), 410, "fixture is exactly 410 bytes");
	provider
		.upsert(ZONE, txt("ed._domainkey.example.org", &value))
		.await
		.expect("upsert");

	let wire = wait_for_wire(&captured).await;
	let msg = Message::from_vec(&wire).expect("parse UPDATE");
	let add = msg
		.authorities
		.iter()
		.find(|r| r.dns_class == DNSClass::IN)
		.expect("add record");
	if let hickory_resolver::proto::rr::RData::TXT(t) = &add.data {
		// Resolvers concatenate the character-strings in order, so
		// the joined value must equal the original input byte-for-byte.
		let joined: String = t
			.txt_data
			.iter()
			.map(|s| std::str::from_utf8(s).unwrap_or(""))
			.collect();
		assert_eq!(joined.len(), 410, "concatenated length is the original");
		assert_eq!(joined, value, "concatenated bytes match the input");
		// No character-string past 255 octets, otherwise hickory
		// would have refused to encode the message in the first place.
		for (i, s) in t.txt_data.iter().enumerate() {
			assert!(
				s.len() <= 255,
				"character-string {i} is {len} bytes (must be at most 255)",
				len = s.len()
			);
		}
		// 410 bytes split on 255-byte boundaries: the first 255 go
		// in one string and the remaining 155 in a second.
		assert_eq!(t.txt_data.len(), 2, "410 bytes split into 2 strings");
		assert_eq!(t.txt_data[0].len(), 255);
		assert_eq!(t.txt_data[1].len(), 155);
	} else {
		panic!("add record is not TXT: {:?}", add.data);
	}
}

/// The two halves of the UPDATE message carry different classes
/// under the contract:
///
/// - The TXT upsert's class-NONE delete (seeded cache has the
///   same-purpose SPF) carries class NONE, because the contract
///   removes only the same-purpose value and the wire must echo the
///   RDATA so the server does not strip a sibling TXT at the same
///   owner.
/// - The TXT delete with an empty value carries class ANY, the
///   RRset delete the DKIM rotator uses to retire a selector.
///
/// A future regression that picked the wrong class for either
/// path (the apex SPF would land alongside the new one, or a
/// retired DKIM key would stay published) fails here.
#[tokio::test]
async fn txt_upsert_uses_class_none_and_empty_value_delete_uses_class_any() {
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
	// Seed the cache with the same SPF the first upsert is about to
	// publish. The second upsert then exercises the class-NONE
	// delete path.
	let mut seed = std::collections::HashMap::new();
	seed.insert(ZONE.to_string(), vec!["v=spf1 -all".to_string()]);
	let provider = provider_with_endpoint_and_cache(endpoint, seed);
	provider
		.upsert(ZONE, txt(ZONE, "v=spf1 mx -all"))
		.await
		.expect("upsert");
	// Empty-value delete uses class ANY (RRset delete). The DKIM
	// rotator retires a selector this way; with anything other than
	// class ANY the retired key would stay published.
	provider
		.delete(
			ZONE,
			DnsRecord::new(
				"_dkim._domainkey.example.org",
				RecordKind::Txt,
				String::new(),
				3600,
			),
		)
		.await
		.expect("delete");

	let wires = wait_for_n_wires(&captured, 2).await;
	// Wire 0: upsert. First update record is the class-NONE delete
	// for the same-purpose SPF.
	let upsert_msg = Message::from_vec(&wires[0]).expect("parse UPDATE");
	let upsert_delete = upsert_msg
		.authorities
		.first()
		.expect("upsert has the class-NONE delete");
	assert_eq!(
		upsert_delete.dns_class,
		DNSClass::NONE,
		"TXT upsert removes a same-purpose value with class NONE; \
		 class ANY would strip every TXT at the owner"
	);
	// Wire 1: empty-value TXT delete. The single update record is
	// the class-ANY RRset delete.
	let delete_msg = Message::from_vec(&wires[1]).expect("parse UPDATE");
	assert_eq!(delete_msg.authorities.len(), 1);
	let delete_rr = &delete_msg.authorities[0];
	assert_eq!(
		delete_rr.dns_class,
		DNSClass::ANY,
		"TXT delete with an empty value is the RRset delete (class ANY); \
		 class NONE would only match a record whose RDATA is empty"
	);
}
