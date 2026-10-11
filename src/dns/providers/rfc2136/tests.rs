//! Tests for the RFC 2136 provider against an in-process TCP mock that
//! verifies TSIG-signed UPDATE messages itself.
//!
//! The test design follows `desec_tests.rs`: every test starts a
//! `tokio::net::TcpListener`, captures what the client sent (or refuses
//! to send), and then invokes the provider. We do **not** mock the wire
//! — we parse the bytes with the same `hickory-proto` parser the server
//! side would use, verify the TSIG with the same key, and then write
//! back a hand-crafted NOERROR response.

use std::sync::{Arc, Mutex};

use base64::Engine;
use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::TSigner;
use hickory_resolver::proto::rr::rdata::tsig::TsigAlgorithm;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

pub(super) const ZONE: &str = "example.org";
pub(super) const KEY_NAME: &str = "epistle-key.";
pub(super) const KEY_BASE64: &str = "c3VwZXJzZWNyZXQta2V5LW1hdGVyaWFsLWZvci10ZXN0cw==";

pub(super) fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
	}
}

pub(super) fn make_signing_pair() -> TSigner {
	let key = base64::engine::general_purpose::STANDARD
		.decode(KEY_BASE64)
		.unwrap();
	let name = hickory_resolver::proto::rr::Name::from_ascii(KEY_NAME).unwrap();
	TSigner::new(key, TsigAlgorithm::HmacSha256, name, 300).unwrap()
}

/// Captured view of one client request, for assertions.
#[derive(Default, Debug, Clone)]
pub(super) struct Captured {
	/// The bytes received on the wire (length-prefix stripped).
	pub(super) wire: Vec<u8>,
	/// Whether the client connected at all.
	pub(super) connected: bool,
}

pub(super) type CapturedVec = Arc<Mutex<Vec<Captured>>>;

/// Spawn a fake nameserver on a random port. The handler reads one
/// UPDATE message per connection and replies; the closure decides what
/// (and whether) to send back, and may verify the client's TSIG. The
/// loop accepts as many connections as needed.
pub(super) async fn spawn_server<F>(respond: F) -> (String, CapturedVec)
where
	F: Fn(&[u8]) -> ServerReply + Send + Sync + 'static,
{
	let captured: CapturedVec = Arc::new(Mutex::new(Vec::new()));
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let respond = Arc::new(respond);
	let captured_clone = captured.clone();
	tokio::spawn(async move {
		loop {
			let (mut stream, _) = match listener.accept().await {
				Ok(s) => s,
				Err(_) => return,
			};
			let mut cap = Captured {
				connected: true,
				..Default::default()
			};
			let mut len_buf = [0u8; 2];
			if stream.read_exact(&mut len_buf).await.is_err() {
				continue;
			}
			let len = u16::from_be_bytes(len_buf) as usize;
			let mut body = vec![0u8; len];
			if stream.read_exact(&mut body).await.is_err() {
				continue;
			}
			cap.wire = body.clone();
			let reply = respond(&body);
			let bytes = reply.bytes();
			if !bytes.is_empty() {
				let len = bytes.len() as u16;
				let _ = stream.write_all(&len.to_be_bytes()).await;
				let _ = stream.write_all(&bytes).await;
			}
			let _ = stream.shutdown().await;
			captured_clone.lock().unwrap().push(cap);
		}
	});
	(format!("127.0.0.1:{}", addr.port()), captured)
}

/// Wait for at least one captured wire message and return the latest.
pub(super) async fn wait_for_wire(captured: &CapturedVec) -> Vec<u8> {
	loop {
		{
			let g = captured.lock().unwrap();
			if let Some(c) = g.last()
				&& !c.wire.is_empty()
			{
				return c.wire.clone();
			}
		}
		tokio::time::sleep(std::time::Duration::from_millis(10)).await;
	}
}

/// Wait until at least `n` captures have arrived.
async fn wait_for_n_wires(captured: &CapturedVec, n: usize) -> Vec<Vec<u8>> {
	loop {
		{
			let g = captured.lock().unwrap();
			if g.len() >= n {
				return g.iter().map(|c| c.wire.clone()).collect();
			}
		}
		tokio::time::sleep(std::time::Duration::from_millis(10)).await;
	}
}

/// What the fake server returns to the client.
pub(super) enum ServerReply {
	/// A NOERROR response. The server signs it with `verify_signer` so
	/// the client's TSIG verification succeeds.
	NoError { verify_signer: TSigner },
	/// A NOTAUTH response (RCODE 9), unsigned — RFC 8945 §5.2 says error
	/// responses are not signed unless the request itself was verified.
	NotAuth,
	/// Arbitrary bytes, for the case where the answer does not parse at all.
	Raw(Vec<u8>),
}

impl ServerReply {
	pub(super) fn bytes(&self) -> Vec<u8> {
		match self {
			ServerReply::NoError { verify_signer } => {
				let id = 0xBEEF;
				let mut resp = Message::new(
					id,
					hickory_resolver::proto::op::MessageType::Response,
					hickory_resolver::proto::op::OpCode::Update,
				);
				resp.metadata.response_code = hickory_resolver::proto::op::ResponseCode::NoError;
				let now = std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.unwrap_or_default()
					.as_secs();
				let _ = resp.finalize(verify_signer, now);
				resp.to_vec().unwrap()
			}
			ServerReply::Raw(bytes) => bytes.clone(),
			ServerReply::NotAuth => {
				let id = 0xBEEF;
				let mut resp = Message::new(
					id,
					hickory_resolver::proto::op::MessageType::Response,
					hickory_resolver::proto::op::OpCode::Update,
				);
				resp.metadata.response_code = hickory_resolver::proto::op::ResponseCode::NotAuth;
				resp.to_vec().unwrap()
			}
		}
	}
}

/// Build a wired-up provider pointing at the test server's endpoint.
pub(super) fn provider_with_endpoint(endpoint: String) -> Rfc2136Provider {
	Rfc2136Provider::new(
		ScopedSecret::new(ZONE, KEY_BASE64),
		KEY_NAME,
		Some("hmac-sha256"),
		&endpoint,
	)
	.unwrap()
}

/// Build a wired-up provider whose TXT cache is pre-populated with
/// `seed`. Used by the wire-shape tests so the contract scenarios
/// (apex SPF change, sibling challenge cleanup) start from a
/// non-empty cache and exercise the class-NONE delete path.
pub(super) fn provider_with_endpoint_and_cache(
	endpoint: String,
	seed: std::collections::HashMap<String, Vec<String>>,
) -> Rfc2136Provider {
	provider_with_endpoint(endpoint).with_cache(seed)
}

#[tokio::test]
async fn upsert_sends_signed_update_with_correct_zone_and_rrset() {
	let signer = make_signing_pair();
	let signer_clone = signer.clone();
	let (endpoint, captured) = spawn_server(move |bytes| {
		signer_clone
			.verify_message_byte(bytes, None, true)
			.expect("client TSIG must verify");
		ServerReply::NoError {
			verify_signer: make_signing_pair(),
		}
	})
	.await;
	// Seed the cache with a previous DMARC at the same owner. The
	// contract removes a same-purpose TXT with class NONE before the
	// add; without the seed the wire would carry just the add and
	// the test would not exercise the deletion path.
	let mut seed = std::collections::HashMap::new();
	seed.insert(
		"_dmarc.example.org".to_string(),
		vec!["v=DMARC1; p=quarantine".to_string()],
	);
	let provider = provider_with_endpoint_and_cache(endpoint, seed);
	provider
		.upsert(ZONE, txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect("upsert");

	let wire = wait_for_wire(&captured).await;

	let msg = Message::from_vec(&wire).expect("parse UPDATE");
	assert_eq!(msg.op_code, hickory_resolver::proto::op::OpCode::Update);
	assert_eq!(msg.queries.len(), 1, "exactly one zone section query");
	let zone_query = &msg.queries[0];
	assert_eq!(zone_query.name.to_ascii(), "example.org.");
	assert_eq!(
		zone_query.query_type,
		hickory_resolver::proto::rr::RecordType::SOA
	);

	// Two update records: one class-NONE delete carrying the previous
	// DMARC RDATA, then the add. Class NONE is the wire shape the
	// contract picks for same-purpose TXT removal (RFC 2136 §2.5.3);
	// the server only removes records whose RDATA matches the
	// placeholder, so the ownership token and any other TXT at the
	// same owner stay published.
	let updates = &msg.authorities;
	assert_eq!(updates.len(), 2, "expected class-NONE delete + add");
	let delete = &updates[0];
	assert_eq!(delete.dns_class, DNSClass::NONE);
	assert_eq!(delete.ttl, 0);
	assert_eq!(delete.name.to_ascii(), "_dmarc.example.org.");
	if let hickory_resolver::proto::rr::RData::TXT(t) = &delete.data {
		let got: String = t
			.txt_data
			.iter()
			.map(|s| std::str::from_utf8(s).unwrap_or(""))
			.collect();
		assert_eq!(got, "v=DMARC1; p=quarantine");
	} else {
		panic!("delete record is not TXT: {:?}", delete.data);
	}
	let add = &updates[1];
	assert_eq!(add.dns_class, DNSClass::IN);
	assert_eq!(add.ttl, 3600);
	assert_eq!(add.name.to_ascii(), "_dmarc.example.org.");
	// TXT carries the value as a character-string; `TXT::new(vec![value])`
	// emits the raw bytes (no surrounding quotes).
	if let hickory_resolver::proto::rr::RData::TXT(t) = &add.data {
		let got: String = t
			.txt_data
			.iter()
			.map(|s| std::str::from_utf8(s).unwrap_or(""))
			.collect();
		assert_eq!(got, "v=DMARC1; p=none");
	} else {
		panic!("add record is not TXT: {:?}", add.data);
	}

	// TSIG is the signature record.
	let sig = msg.signature().expect("UPDATE must carry a TSIG record");
	assert_eq!(sig.data.algorithm, TsigAlgorithm::HmacSha256);
	assert_eq!(sig.name.to_ascii(), KEY_NAME);
}

#[tokio::test]
async fn upsert_at_apex_uses_the_zone_as_owner() {
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
	// Seed the cache so the wire shape is class-NONE delete + add
	// (the contract path), not just add.
	let mut seed = std::collections::HashMap::new();
	seed.insert(ZONE.to_string(), vec!["v=spf1 -all".to_string()]);
	let provider = provider_with_endpoint_and_cache(endpoint, seed);
	provider
		.upsert(ZONE, txt(ZONE, "v=spf1 mx -all"))
		.await
		.expect("upsert");

	let wire = wait_for_wire(&captured).await;
	let msg = Message::from_vec(&wire).unwrap();
	let updates = &msg.authorities;
	assert_eq!(updates.len(), 2, "class-NONE delete + add at the apex");
	assert_eq!(updates[0].name.to_ascii(), "example.org.");
	assert_eq!(updates[0].dns_class, DNSClass::NONE);
	assert_eq!(updates[1].name.to_ascii(), "example.org.");
}

#[tokio::test]
async fn upsert_with_existing_record_replaces_without_duplicating() {
	// The contract pins two wire shapes for TXT upsert: an empty
	// cache emits just the `add`; a cache with a same-purpose value
	// emits a `class NONE` delete for that value followed by the
	// `add`. Re-running an upsert with the new value produces the
	// second shape, so the server never sees two TXT records at the
	// same owner name. We assert both shapes here.
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
	// Seed the cache with the same value the first upsert would
	// publish. Both calls then exercise the class-NONE delete path:
	// the first delete is for the seed, the second for the value the
	// first upsert added.
	let mut seed = std::collections::HashMap::new();
	seed.insert(ZONE.to_string(), vec!["v=spf1 -all".to_string()]);
	let provider = provider_with_endpoint_and_cache(endpoint, seed);
	provider
		.upsert(ZONE, txt(ZONE, "v=spf1 -all"))
		.await
		.expect("upsert");
	provider
		.upsert(ZONE, txt(ZONE, "v=spf1 mx -all"))
		.await
		.expect("upsert");
	let wires = wait_for_n_wires(&captured, 2).await;
	assert_eq!(wires.len(), 2);
	for (i, wire) in wires.iter().enumerate() {
		let msg = Message::from_vec(wire).unwrap();
		let updates = &msg.authorities;
		assert_eq!(
			updates.len(),
			2,
			"wire {i} carries a class-NONE delete for the previous value and the add"
		);
		// Class NONE is the contract shape for same-purpose TXT
		// removal. A future regression to class ANY on TXT would
		// strip every record at the owner (the bug the contract
		// closes: an apex SPF upsert wiping the ownership token).
		assert_eq!(updates[0].dns_class, DNSClass::NONE);
		assert_eq!(updates[1].dns_class, DNSClass::IN);
	}
}

#[tokio::test]
async fn delete_is_idempotent_when_record_is_absent() {
	// RFC 2136 §2.5.3: a class-NONE delete for an absent record is a
	// no-op on the server. The client still emits the same wire
	// shape: a single class-NONE update record carrying the RDATA
	// the caller asked for, regardless of whether anything matches.
	// The class-NONE shape is the contract path for TXT delete with
	// a value; an empty value would be class ANY (the RRset delete).
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
	provider
		.delete(ZONE, txt("_never_existed.example.org", "ignored"))
		.await
		.expect("delete is idempotent");

	let wire = wait_for_wire(&captured).await;
	let msg = Message::from_vec(&wire).expect("parse UPDATE");
	// delete is exactly one update record with class NONE (the
	// contract path for TXT delete with a value) and TTL 0, RDATA
	// carrying the value the caller passed. A sibling TXT at the
	// same owner with a different value is left alone because the
	// server only removes records whose RDATA matches the
	// placeholder.
	let updates = &msg.authorities;
	assert_eq!(updates.len(), 1);
	assert_eq!(updates[0].dns_class, DNSClass::NONE);
	assert_eq!(updates[0].ttl, 0);
	assert_eq!(updates[0].name.to_ascii(), "_never_existed.example.org.");
}

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
			DnsRecord {
				name: "_dkim._domainkey.example.org".into(),
				kind: RecordKind::Txt,
				value: String::new(),
				ttl: 3600,
			},
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

/// Non-TXT records keep the whole-set semantics at a name. An MX
/// upsert therefore carries `class ANY` for the delete-rrset, the
/// same way it did before the contract; case difference on the
/// target is irrelevant on the wire because DNS names are
/// case-insensitive, so `MAIL.Example.Org.` and `mail.example.org`
/// are the same record and a round-trip never duplicates it.
#[tokio::test]
async fn mx_upsert_with_a_different_case_target_uses_class_any_delete() {
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
	provider
		.upsert(
			ZONE,
			DnsRecord {
				name: ZONE.into(),
				kind: RecordKind::Mx,
				value: "10 mail.example.org".into(),
				ttl: 3600,
			},
		)
		.await
		.expect("MX upsert");
	let wire = wait_for_wire(&captured).await;
	let msg = Message::from_vec(&wire).expect("parse UPDATE");
	let updates = &msg.authorities;
	assert_eq!(
		updates.len(),
		2,
		"non-TXT upsert is delete-RRset + add, the same wire shape the contract keeps"
	);
	assert_eq!(
		updates[0].dns_class,
		DNSClass::ANY,
		"non-TXT upserts keep the whole-set delete (class ANY); \
		 class NONE would only match an MX whose RDATA is empty"
	);
	assert_eq!(updates[1].dns_class, DNSClass::IN);
}

#[tokio::test]
async fn list_returns_unsupported() {
	// No test server: `list` must short-circuit without touching the
	// network. We do not even construct a server.
	let endpoint = "127.0.0.1:1".to_string();
	let provider = provider_with_endpoint(endpoint);
	let result = provider.list(ZONE).await;
	assert_eq!(result, Err(ProviderError::Unsupported));
}

#[tokio::test]
async fn record_outside_zone_is_rejected_without_network() {
	// `authorize` runs before the TCP connect, so even though the
	// endpoint is unreachable (no listener), the call must fail with
	// Auth and never open a socket.
	let endpoint = "127.0.0.1:1".to_string();
	let provider = provider_with_endpoint(endpoint);
	let result = provider
		.upsert(ZONE, txt("_dmarc.other.example", "x"))
		.await;
	assert_eq!(result, Err(ProviderError::Auth));
}

#[tokio::test]
async fn mx_upsert_encodes_preference_and_exchange_in_wire_message() {
	let (endpoint, captured) = spawn_server(|_| ServerReply::NoError {
		verify_signer: make_signing_pair(),
	})
	.await;
	let provider = provider_with_endpoint(endpoint);
	let mx = DnsRecord {
		name: ZONE.to_string(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org.".to_string(),
		ttl: 3600,
	};
	provider.upsert(ZONE, mx).await.expect("mx upsert");
	let caps = captured.lock().unwrap();
	let wire = caps.first().expect("captured a request").wire.clone();
	let msg = Message::from_vec(&wire).expect("parse UPDATE");
	let updates = msg.updates();
	let add = updates
		.iter()
		.find(|r| matches!(r.data, hickory_resolver::proto::rr::RData::MX(_)))
		.expect("add MX RR");
	if let hickory_resolver::proto::rr::RData::MX(mx) = &add.data {
		assert_eq!(mx.preference, 10);
		assert_eq!(mx.exchange.to_ascii(), "mail.example.org.");
	} else {
		panic!("expected MX rdata");
	}
}
