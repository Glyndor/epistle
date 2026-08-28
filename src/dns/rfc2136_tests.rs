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

const ZONE: &str = "example.org";
const KEY_NAME: &str = "epistle-key.";
const KEY_BASE64: &str = "c3VwZXJzZWNyZXQta2V5LW1hdGVyaWFsLWZvci10ZXN0cw==";

fn txt(name: &str, value: &str) -> DnsRecord {
	DnsRecord {
		name: name.to_string(),
		kind: RecordKind::Txt,
		value: value.to_string(),
		ttl: 3600,
	}
}

fn make_signing_pair() -> TSigner {
	let key = base64::engine::general_purpose::STANDARD
		.decode(KEY_BASE64)
		.unwrap();
	let name = hickory_resolver::proto::rr::Name::from_ascii(KEY_NAME).unwrap();
	TSigner::new(key, TsigAlgorithm::HmacSha256, name, 300).unwrap()
}

/// Captured view of one client request, for assertions.
#[derive(Default, Debug, Clone)]
struct Captured {
	/// The bytes received on the wire (length-prefix stripped).
	wire: Vec<u8>,
	/// Whether the client connected at all.
	connected: bool,
}

type CapturedVec = Arc<Mutex<Vec<Captured>>>;

/// Spawn a fake nameserver on a random port. The handler reads one
/// UPDATE message per connection and replies; the closure decides what
/// (and whether) to send back, and may verify the client's TSIG. The
/// loop accepts as many connections as needed.
async fn spawn_server<F>(respond: F) -> (String, CapturedVec)
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
async fn wait_for_wire(captured: &CapturedVec) -> Vec<u8> {
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
enum ServerReply {
	/// A NOERROR response. The server signs it with `verify_signer` so
	/// the client's TSIG verification succeeds.
	NoError { verify_signer: TSigner },
	/// A NOTAUTH response (RCODE 9), unsigned — RFC 8945 §5.2 says error
	/// responses are not signed unless the request itself was verified.
	NotAuth,
}

impl ServerReply {
	fn bytes(&self) -> Vec<u8> {
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
fn provider_with_endpoint(endpoint: String) -> Rfc2136Provider {
	Rfc2136Provider::new(
		ScopedSecret::new(ZONE, KEY_BASE64),
		KEY_NAME,
		Some("hmac-sha256"),
		&endpoint,
	)
	.unwrap()
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
	let provider = provider_with_endpoint(endpoint);
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

	// Two update records: one delete RRset (class NONE, TTL 0), one add.
	let updates = &msg.authorities;
	assert_eq!(updates.len(), 2, "expected delete + add");
	let delete = &updates[0];
	assert_eq!(delete.dns_class, DNSClass::NONE);
	assert_eq!(delete.ttl, 0);
	assert_eq!(delete.name.to_ascii(), "_dmarc.example.org.");
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
	let provider = provider_with_endpoint(endpoint);
	provider
		.upsert(ZONE, txt(ZONE, "v=spf1 -all"))
		.await
		.expect("upsert");

	let wire = wait_for_wire(&captured).await;
	let msg = Message::from_vec(&wire).unwrap();
	let updates = &msg.authorities;
	assert_eq!(updates.len(), 2);
	assert_eq!(updates[0].name.to_ascii(), "example.org.");
	assert_eq!(updates[1].name.to_ascii(), "example.org.");
}

#[tokio::test]
async fn upsert_with_existing_record_replaces_without_duplicating() {
	// The contract is encoded in the wire shape: every upsert issues a
	// `delete RRset (name, type)` followed by an `add`. Re-running an
	// upsert produces the same wire shape, so the server never sees two
	// TXT records at the same owner name. We assert the shape here; the
	// authoritative check is "the wire contains a delete-rrset before the
	// add", which is exactly what RFC 2136 §2.5 specifies for replacement.
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
	// Run twice — the wire must look the same both times, never two adds
	// without an intervening delete-rrset.
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
	for wire in wires {
		let msg = Message::from_vec(&wire).unwrap();
		let updates = &msg.authorities;
		assert_eq!(
			updates.len(),
			2,
			"always delete-rrset + add, never just add"
		);
		assert_eq!(updates[0].dns_class, DNSClass::NONE);
		assert_eq!(updates[1].dns_class, DNSClass::IN);
	}
}

#[tokio::test]
async fn delete_is_idempotent_when_record_is_absent() {
	// RFC 2136 §2.5.3: a delete-rrset for an absent RRset is a no-op.
	// The server does not need to know whether the RRset exists; both
	// responses are NOERROR. The client emits the same wire either way.
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
	let msg = Message::from_vec(&wire).unwrap();
	// delete is exactly one update record (the delete-rrset), with class
	// NONE and TTL 0. No `add` follows.
	let updates = &msg.authorities;
	assert_eq!(updates.len(), 1);
	assert_eq!(updates[0].dns_class, DNSClass::NONE);
	assert_eq!(updates[0].ttl, 0);
	assert_eq!(updates[0].name.to_ascii(), "_never_existed.example.org.");
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
async fn unsupported_kind_is_rejected() {
	let endpoint = "127.0.0.1:1".to_string();
	let provider = provider_with_endpoint(endpoint);
	let mx = DnsRecord {
		name: ZONE.to_string(),
		kind: RecordKind::Mx,
		value: "10 mail.example.org".to_string(),
		ttl: 3600,
	};
	assert_eq!(
		provider.upsert(ZONE, mx).await,
		Err(ProviderError::Unsupported)
	);
}

#[tokio::test]
async fn server_returning_notauth_is_mapped_to_auth_error() {
	// The server rejects the request without verifying TSIG (e.g. the
	// key is unknown). RFC 2136 says it answers NOTAUTH.
	let (endpoint, captured) = spawn_server(move |_bytes| ServerReply::NotAuth).await;
	let provider = provider_with_endpoint(endpoint);
	let result = provider.upsert(ZONE, txt(ZONE, "x")).await;
	assert_eq!(result, Err(ProviderError::Auth));
	let g = captured.lock().unwrap();
	assert!(
		!g.is_empty() && g[0].connected,
		"client did not connect to the server"
	);
}

#[tokio::test]
async fn auth_header_tsig_uses_exact_key_and_algorithm() {
	// The TSIG RR carries the algorithm name and the key name. A
	// different algorithm or key name would invalidate the MAC. We
	// verify the literal bytes the client emitted carry the right
	// values.
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
		.upsert(ZONE, txt("_dmarc.example.org", "v=DMARC1"))
		.await
		.expect("upsert");

	let wire = wait_for_wire(&captured).await;
	let wire_str = String::from_utf8_lossy(&wire);
	assert!(
		wire_str.contains("hmac-sha256"),
		"TSIG algorithm name missing from wire bytes: {wire_str}"
	);
	let msg = Message::from_vec(&wire).unwrap();
	let sig = msg.signature().expect("TSIG present");
	assert_eq!(sig.data.algorithm, TsigAlgorithm::HmacSha256);
	assert_eq!(sig.name.to_ascii(), KEY_NAME);
	assert_eq!(sig.data.mac.len(), 32, "HMAC-SHA256 produces a 32-byte MAC");
}

#[tokio::test]
async fn bad_tsig_is_mapped_to_auth_error() {
	// The client signs with KEY_BASE64, but the server's verifier uses
	// a different key. RFC 8945 §5.2 says the server MUST answer
	// BADSIG; we surface that as ProviderError::Auth. The server here
	// answers an unsigned NOTAUTH (the simplest path) — the client
	// treats both shapes as auth failure.
	let bad_signer = TSigner::new(
		b"this-is-a-different-key-on-purpose".to_vec(),
		TsigAlgorithm::HmacSha256,
		hickory_resolver::proto::rr::Name::from_ascii(KEY_NAME).unwrap(),
		300,
	)
	.unwrap();
	let (endpoint, captured) = spawn_server(move |bytes| {
		// Verify with a *different* key — must fail.
		assert!(
			bad_signer.verify_message_byte(bytes, None, true).is_err(),
			"verification should have failed with the wrong key"
		);
		ServerReply::NotAuth
	})
	.await;
	let provider = provider_with_endpoint(endpoint);
	let result = provider.upsert(ZONE, txt(ZONE, "v=spf1 -all")).await;
	assert_eq!(result, Err(ProviderError::Auth));
	// The server saw the request (so the failure was after the wire
	// round-trip, not a pre-flight authorization rejection).
	let _ = wait_for_wire(&captured).await;
}
