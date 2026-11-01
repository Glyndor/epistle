//! Credential mutations must invalidate a login already in progress.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use epistle::directory_store::{AccountStore, DynamicAccount};
use epistle::smtp::scram::{ScramCredentials, ScramStored};
use epistle::smtp::server::Server;
use epistle::smtp::sink::MemorySink;
use ring::{digest, hmac, pbkdf2};

use super::{support::*, wire};

fn proof(first: &str, password: &str) -> String {
	let field = |prefix: &str| {
		first
			.split(',')
			.find_map(|s| s.strip_prefix(prefix))
			.expect("SCRAM field")
	};
	let salt = B64.decode(field("s=")).expect("salt");
	let iterations = field("i=").parse::<u32>().expect("iterations");
	let without_proof = format!("c=biws,r={}", field("r="));
	let auth_message = format!("n=tester,r=CN,{first},{without_proof}");
	let mut salted = [0u8; 32];
	pbkdf2::derive(
		pbkdf2::PBKDF2_HMAC_SHA256,
		NonZeroU32::new(iterations).expect("nonzero iterations"),
		&salt,
		password.as_bytes(),
		&mut salted,
	);
	let client_key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salted), b"Client Key");
	let stored_key = digest::digest(&digest::SHA256, client_key.as_ref());
	let signature = hmac::sign(
		&hmac::Key::new(hmac::HMAC_SHA256, stored_key.as_ref()),
		auth_message.as_bytes(),
	);
	let proof: Vec<u8> = client_key
		.as_ref()
		.iter()
		.zip(signature.as_ref())
		.map(|(a, b)| a ^ b)
		.collect();
	format!("{without_proof},p={}", B64.encode(proof))
}

async fn challenge(stream: &mut TlsStream) -> String {
	let reply = wire::line(stream)
		.await
		.expect("SCRAM reply")
		.expect("open");
	let payload = reply
		.strip_prefix("334 ")
		.expect("SCRAM challenge")
		.trim_end();
	String::from_utf8(B64.decode(payload).expect("challenge base64")).expect("challenge UTF-8")
}

async fn pending_login(stream: &mut TlsStream, password: &str) {
	wire::send(stream, b"AUTH SCRAM-SHA-256\r\n").await;
	wire::expect(stream, "334 \r\n").await;
	wire::send(
		stream,
		format!("{}\r\n", B64.encode("n,,n=tester,r=CN")).as_bytes(),
	)
	.await;
	let first = challenge(stream).await;
	let final_message = proof(&first, password);
	wire::send(
		stream,
		format!("{}\r\n", B64.encode(final_message)).as_bytes(),
	)
	.await;
	assert!(
		challenge(stream).await.starts_with("v="),
		"valid password proof must reach server-final"
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inflight_login_cannot_succeed_after_a_credential_mutation() {
	seed("credentials");
	let mut order = [false, true];
	let mut rng = SEED;
	if next(&mut rng) & 1 != 0 {
		order.reverse();
	}
	let mut violations = Vec::new();
	for disable in order {
		let root = tempfile::tempdir().expect("account store");
		let store = AccountStore::open(
			root.path(),
			vec!["epistle.test".into()],
			HashMap::new(),
			vec![],
		)
		.expect("open store");
		let password = &*wire::PASSWORD;
		let hash = epistle::smtp::auth::hash_password(password).expect("password hash");
		// A salt minted for this run, so no literal salt sits in the source.
		let salt: [u8; 16] = ring::rand::generate(&ring::rand::SystemRandom::new())
			.expect("random salt")
			.expose();
		let scram = ScramStored::from_credentials(&ScramCredentials::derive(password, &salt, 4096));
		store
			.add(DynamicAccount {
				name: "tester".into(),
				addresses: vec!["tester@epistle.test".into()],
				password_hash: hash,
				scram: Some(scram),
				..DynamicAccount::default()
			})
			.expect("add account");
		let sink = Arc::new(MemorySink::new());
		let tls = Tls::new();
		let listener = Listener::start(
			tls.server(Server::new("mx.epistle.test", sink.clone()).with_directory(store.handle())),
		)
		.await;
		// Positive control reaches exactly the same protocol state and succeeds.
		let mut control = tls.connect(&listener).await;
		pending_login(&mut control, password).await;
		wire::send(&mut control, b"\r\n").await;
		wire::expect(&mut control, "235 2.7.0 authentication successful\r\n").await;
		wire::quit(&mut control).await;

		let mut racing = tls.connect(&listener).await;
		pending_login(&mut racing, password).await;
		if disable {
			store.set_disabled("tester", true).expect("disable returns");
		} else {
			let new_password = format!("Fx2!{}", uuid::Uuid::new_v4().simple());
			let hash =
				epistle::smtp::auth::hash_password(&new_password).expect("new password hash");
			store
				.set_password_hash("tester", hash, None)
				.expect("password mutation returns");
		}
		// Both mutations have completed on disk and published the new directory.
		let mut fresh = tls.connect(&listener).await;
		let credentials = B64.encode(format!("\0tester\0{password}"));
		wire::send(
			&mut fresh,
			format!("AUTH PLAIN {credentials}\r\n").as_bytes(),
		)
		.await;
		wire::expect(
			&mut fresh,
			"535 5.7.8 authentication credentials invalid\r\n",
		)
		.await;

		wire::send(&mut racing, b"\r\n").await;
		let reply = wire::line(&mut racing)
			.await
			.expect("final auth reply")
			.expect("open");
		if reply == "235 2.7.0 authentication successful\r\n" {
			violations.push(disable);
		} else {
			assert_eq!(
				reply, "535 5.7.8 authentication credentials invalid\r\n",
				"seed={SEED:#x} unexpected auth outcome"
			);
		}
		assert!(sink.messages().is_empty());
	}
	assert!(
		violations.is_empty(),
		"seed={SEED:#x} login succeeded after mutation; disable cases={violations:?}"
	);
}
