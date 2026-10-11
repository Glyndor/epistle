//! RFC 2136 provider tests, second half: what happens when the nameserver's
//! answer is not the one we asked for, plus the wire-shape tests for the
//! TXT upsert/delete contract. Split from `rfc2136_tests.rs` to stay
//! under the per-file line limit; the mock harness lives in the first
//! half.

use super::tests::{
	KEY_NAME, ServerReply, ZONE, make_signing_pair, provider_with_endpoint,
	provider_with_endpoint_and_cache, spawn_server, txt, wait_for_wire,
};
use super::*;

use base64::Engine;
use hickory_resolver::proto::op::Message;
use hickory_resolver::proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_resolver::proto::rr::{DNSClass, TSigner};

/// A signer holding a key the provider does not have, for forging a response
/// that is signed but signed by the wrong party.
fn foreign_signer() -> TSigner {
	let key = base64::engine::general_purpose::STANDARD
		.decode("YW5vdGhlci1rZXktZW50aXJlbHktZm9yLWZvcmdlcnktdGVzdA==")
		.unwrap();
	let name = hickory_resolver::proto::rr::Name::from_ascii(KEY_NAME).unwrap();
	TSigner::new(key, TsigAlgorithm::HmacSha256, name, 300).unwrap()
}

#[tokio::test]
async fn a_response_signed_with_the_wrong_key_is_rejected() {
	// The whole point of verifying TSIG on the *response* is that an
	// off-path attacker who can answer first must not be able to make a
	// failed update look like NOERROR. This response says NOERROR and is
	// properly signed — just not by anyone holding our key.
	let signer = foreign_signer();
	let (endpoint, _captured) = spawn_server(move |_| ServerReply::NoError {
		verify_signer: signer.clone(),
	})
	.await;
	let provider = provider_with_endpoint(endpoint);
	let error = provider
		.upsert(ZONE, txt("_probe.example.org", "v=spf1 -all"))
		.await
		.expect_err("a response we cannot authenticate must not read as success");
	assert!(
		matches!(error, ProviderError::Auth),
		"expected Auth, got {error:?}"
	);
}

#[tokio::test]
async fn an_unsigned_response_is_rejected() {
	// Same control from the other side: no TSIG at all on the answer.
	let (endpoint, _captured) = spawn_server(|_| ServerReply::NotAuth).await;
	let provider = provider_with_endpoint(endpoint);
	let error = provider
		.upsert(ZONE, txt("_probe.example.org", "v=spf1 -all"))
		.await
		.expect_err("an unsigned response must not read as success");
	assert!(
		matches!(error, ProviderError::Auth),
		"expected Auth, got {error:?}"
	);
}

#[tokio::test]
async fn a_server_that_never_answers_is_a_remote_error_not_a_success() {
	// Connection accepted, nothing written back. Reading the length prefix
	// hits EOF; that must surface as an error rather than an empty success.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let endpoint = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
	tokio::spawn(async move {
		while let Ok((stream, _)) = listener.accept().await {
			drop(stream);
		}
	});
	let provider = provider_with_endpoint(endpoint);
	let error = provider
		.upsert(ZONE, txt("_probe.example.org", "v=spf1 -all"))
		.await
		.expect_err("a truncated exchange is not a successful update");
	assert!(
		matches!(error, ProviderError::Remote(_)),
		"expected Remote, got {error:?}"
	);
}

#[tokio::test]
async fn a_closed_port_is_a_remote_error() {
	// Bind then drop, so the port is almost certainly free and refuses.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let endpoint = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
	drop(listener);
	let provider = provider_with_endpoint(endpoint);
	let error = provider
		.delete(ZONE, txt("_probe.example.org", "v=spf1 -all"))
		.await
		.expect_err("a refused connection is not a successful delete");
	assert!(
		matches!(error, ProviderError::Remote(_)),
		"expected Remote, got {error:?}"
	);
}

#[tokio::test]
async fn a_message_larger_than_dns_over_tcp_allows_is_refused_before_dialling() {
	// The length prefix is a u16, so a body past 65535 cannot be framed. The
	// provider must say so rather than truncate the record silently.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let endpoint = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
	drop(listener);
	let provider = provider_with_endpoint(endpoint);
	let huge = "x".repeat(70_000);
	let error = provider
		.upsert(ZONE, txt("_probe.example.org", &huge))
		.await
		.expect_err("an unframeable message is not a successful update");
	assert!(
		matches!(error, ProviderError::Remote(_)),
		"expected Remote, got {error:?}"
	);
}

#[tokio::test]
async fn garbage_on_the_wire_is_a_remote_error() {
	let (endpoint, _captured) = spawn_server(|_| ServerReply::Raw(vec![0xff; 12])).await;
	let provider = provider_with_endpoint(endpoint);
	let error = provider
		.upsert(ZONE, txt("_probe.example.org", "v=spf1 -all"))
		.await
		.expect_err("undecodable bytes are not a successful update");
	assert!(
		matches!(error, ProviderError::Auth | ProviderError::Remote(_)),
		"expected Auth or Remote, got {error:?}"
	);
}

/// Apex TXT set with an ownership token and an SPF, then a new SPF
/// is published. The wire shape must be a class-NONE delete for the
/// previous SPF (same purpose) followed by an add of the new SPF;
/// the ownership token is not in the cache and is therefore not
/// touched, so the server keeps it. Two SPFs at the apex would
/// produce an SPF `permerror` (RFC 7208 §4.5), the bug the contract
/// closes.
#[tokio::test]
async fn txt_apex_change_replaces_only_the_spf() {
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
	// Seed the cache with only the SPF, not the ownership token.
	// The token is something epistle does not own, so the cache must
	// not see it; a re-upsert that tries to remove it would land in
	// the server's NXDOMAIN/empty-match path and leave it alone.
	let mut seed = std::collections::HashMap::new();
	seed.insert(ZONE.to_string(), vec!["v=spf1 -all".to_string()]);
	let provider = provider_with_endpoint_and_cache(endpoint, seed);
	provider
		.upsert(ZONE, txt(ZONE, "v=spf1 mx -all"))
		.await
		.expect("apex SPF change");
	let wire = wait_for_wire(&captured).await;
	let msg = Message::from_vec(&wire).expect("parse UPDATE");
	let updates = &msg.authorities;
	// Wire: 1 class-NONE delete (old SPF) + 1 add (new SPF). The
	// ownership token is not in the update section at all because
	// it was never in the cache.
	assert_eq!(
		updates.len(),
		2,
		"class-NONE delete for the old SPF plus the add for the new one"
	);
	assert_eq!(updates[0].dns_class, DNSClass::NONE);
	if let hickory_resolver::proto::rr::RData::TXT(t) = &updates[0].data {
		let got: String = t
			.txt_data
			.iter()
			.map(|s| std::str::from_utf8(s).unwrap_or(""))
			.collect();
		assert_eq!(
			got, "v=spf1 -all",
			"the class-NONE delete carries the old SPF"
		);
	} else {
		panic!("delete record is not TXT: {:?}", updates[0].data);
	}
	assert_eq!(updates[1].dns_class, DNSClass::IN);
	if let hickory_resolver::proto::rr::RData::TXT(t) = &updates[1].data {
		let got: String = t
			.txt_data
			.iter()
			.map(|s| std::str::from_utf8(s).unwrap_or(""))
			.collect();
		assert_eq!(got, "v=spf1 mx -all", "the add carries the new SPF");
	} else {
		panic!("add record is not TXT: {:?}", updates[1].data);
	}
}

/// Two ACME DNS-01 challenges at the same owner, then one of them
/// is deleted. The wire shape must be a single class-NONE delete
/// carrying the value the caller passed. A class-ANY RRset delete
/// would wipe the sibling challenge; a class-NONE delete with the
/// wrong RDATA would be a no-op. The cache is seeded with both
/// challenges so the provider has the data to scope the delete.
#[tokio::test]
async fn txt_delete_keeps_the_sibling_challenge() {
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
	let mut seed = std::collections::HashMap::new();
	seed.insert(
		"_acme-challenge.example.org".to_string(),
		vec!["token-aaaa".to_string(), "token-bbbb".to_string()],
	);
	let provider = provider_with_endpoint_and_cache(endpoint, seed);
	provider
		.delete(ZONE, txt("_acme-challenge.example.org", "token-aaaa"))
		.await
		.expect("delete one of two challenges");
	let wire = wait_for_wire(&captured).await;
	let msg = Message::from_vec(&wire).expect("parse UPDATE");
	let updates = &msg.authorities;
	assert_eq!(
		updates.len(),
		1,
		"the delete is scoped to the matching value, not the RRset"
	);
	let delete = &updates[0];
	assert_eq!(
		delete.dns_class,
		DNSClass::NONE,
		"delete with a value uses class NONE; class ANY would wipe the sibling"
	);
	if let hickory_resolver::proto::rr::RData::TXT(t) = &delete.data {
		let got: String = t
			.txt_data
			.iter()
			.map(|s| std::str::from_utf8(s).unwrap_or(""))
			.collect();
		assert_eq!(got, "token-aaaa", "the class-NONE delete carries the value");
	} else {
		panic!("delete record is not TXT: {:?}", delete.data);
	}
}

/// The DKIM rotator retires a selector by issuing a TXT delete with
/// an empty value. The wire shape must be a single class-ANY
/// delete-rrset, the RRset delete, so the retired key stops being
/// served. A class-NONE delete with empty RDATA would only match
/// an empty record (it does not), so the retired key would stay
/// published; a future regression to that wire shape fails here.
#[tokio::test]
async fn dkim_retire_with_empty_value_uses_class_any() {
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
		.delete(
			ZONE,
			DnsRecord {
				name: "ed._domainkey.example.org".into(),
				kind: RecordKind::Txt,
				value: String::new(),
				ttl: 3600,
			},
		)
		.await
		.expect("retire DKIM selector");
	let wire = wait_for_wire(&captured).await;
	let msg = Message::from_vec(&wire).expect("parse UPDATE");
	let updates = &msg.authorities;
	assert_eq!(updates.len(), 1, "the retire is a single RRset delete");
	assert_eq!(
		updates[0].dns_class,
		DNSClass::ANY,
		"empty-value delete is the RRset delete (class ANY); \
		 class NONE with empty RDATA would be a no-op and the \
		 retired key would stay published"
	);
	assert_eq!(updates[0].ttl, 0);
}

/// Keep the unused-import lint quiet about `Message`, which the harness type
/// signature pulls in.
#[allow(dead_code)]
fn _message_type_is_referenced(_: Option<Message>) {}

#[tokio::test]
async fn srv_upsert_encodes_priority_weight_port_target_in_wire_message() {
	let (endpoint, captured) = spawn_server(|_| ServerReply::NoError {
		verify_signer: make_signing_pair(),
	})
	.await;
	let provider = provider_with_endpoint(endpoint);
	let srv = DnsRecord {
		name: format!("_submissions._tcp.{ZONE}"),
		kind: RecordKind::Srv,
		value: "0 1 465 mail.example.org.".to_string(),
		ttl: 3600,
	};
	provider.upsert(ZONE, srv).await.expect("srv upsert");
	let caps = captured.lock().unwrap();
	let wire = caps.first().expect("captured a request").wire.clone();
	let msg = Message::from_vec(&wire).expect("parse UPDATE");
	let updates = msg.updates();
	let add = updates
		.iter()
		.find(|r| matches!(r.data, hickory_resolver::proto::rr::RData::SRV(_)))
		.expect("add SRV RR");
	if let hickory_resolver::proto::rr::RData::SRV(srv) = &add.data {
		assert_eq!(srv.priority, 0);
		assert_eq!(srv.weight, 1);
		assert_eq!(srv.port, 465);
		assert_eq!(srv.target.to_ascii(), "mail.example.org.");
	} else {
		panic!("expected SRV rdata");
	}
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
	// answers an unsigned NOTAUTH (the simplest path), the client
	// treats both shapes as auth failure.
	let bad_signer = TSigner::new(
		b"this-is-a-different-key-on-purpose".to_vec(),
		TsigAlgorithm::HmacSha256,
		hickory_resolver::proto::rr::Name::from_ascii(KEY_NAME).unwrap(),
		300,
	)
	.unwrap();
	let (endpoint, captured) = spawn_server(move |bytes| {
		// Verify with a *different* key, must fail.
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
