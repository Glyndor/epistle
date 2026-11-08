use super::*;

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
			DnsRecord::new(ZONE, RecordKind::Mx, "10 mail.example.org", 3600),
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
	let mx = DnsRecord::new(ZONE, RecordKind::Mx, "10 mail.example.org.", 3600);
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
