//! DKIM signatures and the prior ARC chain survive the local seal.

use std::collections::HashMap;

use super::tests_auth::directory_with_password;
use super::tests_inbound_headers::{FORGED, PLAIN, receive};
use super::*;
use crate::dkim::test_support::KeyDns;
use crate::smtp::sink::MemorySink;
use crate::smtp::trace::header_values;

#[tokio::test]
async fn dkim_and_the_prior_arc_chain_survive_with_a_valid_local_seal() {
	use crate::arc::chain::ChainValidation;
	use crate::arc::sealer::ArcSealer;
	use base64::Engine;
	use ring::signature::{Ed25519KeyPair, KeyPair};
	let rng = ring::rand::SystemRandom::new();
	let make_key = || {
		let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("key");
		Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("keypair")
	};
	let prior_key = make_key();
	let local_key = make_key();
	let record = |key: &Ed25519KeyPair| {
		format!(
			"v=DKIM1; k=ed25519; p={}",
			base64::engine::general_purpose::STANDARD.encode(key.public_key().as_ref())
		)
	};
	let mut records = HashMap::from([
		("sender.example".into(), vec!["v=spf1 ~all".into()]),
		(
			"arc._domainkey.prior.example".into(),
			vec![record(&prior_key)],
		),
		(
			"arc._domainkey.mail.example.org".into(),
			vec![record(&local_key)],
		),
	]);
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, public) = crate::dkim::generate_key().expect("dkim key");
	let path = dir.path().join("key");
	std::fs::write(&path, pem).expect("write key");
	let signer = crate::dkim::Signer::load("dkim", &path).expect("signer");
	let signature = signer
		.sign("sender.example", PLAIN.as_bytes())
		.expect("signature");
	records.insert("dkim._domainkey.sender.example".into(), vec![public]);
	let original = format!("Received: from original.example\r\n{signature}{FORGED}{PLAIN}");
	let prior = ArcSealer::new(prior_key, "prior.example", "arc")
		.seal(original.as_bytes(), "spf=pass", &[], ChainValidation::None)
		.expect("prior seal");
	let dns = Arc::new(KeyDns(records));
	let sink = Arc::new(MemorySink::new());
	let server = Server::new("mail.example.org", sink.clone())
		.with_directory(directory_with_password())
		.with_spf(dns.clone())
		.with_arc_sealer(Arc::new(ArcSealer::new(
			local_key,
			"mail.example.org",
			"arc",
		)));
	receive(server, &format!("{prior}{original}"), false).await;
	let messages = sink.messages();
	assert_eq!(messages.len(), 1);
	let message = &messages[0];
	let text = std::str::from_utf8(&message.data).expect("text");
	assert!(text.contains(&signature));
	assert!(text.contains(&prior));
	assert_eq!(header_values(&message.data, "Received").len(), 2);
	assert!(text.contains("Received: from original.example\r\n"));
	let results = header_values(&message.data, "Authentication-Results");
	assert_eq!(results.len(), 1);
	assert!(
		results[0].contains("dkim=pass header.d=sender.example"),
		"{results:?}"
	);
	assert_eq!(
		crate::arc::chain::extract(&message.data)
			.expect("chain")
			.expect("present")
			.len(),
		2
	);
	assert_eq!(
		crate::arc::validate::validate(dns.as_ref(), &message.data).await,
		ChainValidation::Pass
	);
}
