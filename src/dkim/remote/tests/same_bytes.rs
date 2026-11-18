//! A signature that crossed the socket is the same bytes as one made in
//! the process.

use super::*;
use crate::dkim::test_support::{GOLDEN, ed25519_pem, fixed_signer};
use crate::dkim::{DomainSigner, PerDomainSigner, ReloadableSigner, Signer};

#[tokio::test]
async fn the_socket_signature_is_the_in_process_signature_byte_for_byte() {
	let dir = tempfile::tempdir().expect("tempdir");
	let running = start_with(fixed_signer(dir.path()));
	let local = fixed_signer(dir.path());
	let client = RemoteSigner::new(&running.socket);
	for (raw, golden) in GOLDEN {
		let in_process = local
			.sign("example.org", raw.as_bytes())
			.expect("signs here");
		let remote = client
			.sign("example.org", raw.as_bytes())
			.await
			.expect("signs over the socket");
		assert_eq!(remote, in_process, "for {raw:?}");
		assert_eq!(remote, golden, "for {raw:?}");
	}
}

#[tokio::test]
async fn a_per_domain_holder_signs_the_same_bytes_over_the_socket() {
	let dir = tempfile::tempdir().expect("tempdir");
	let build = || {
		let default_key = dir.path().join("default.pem");
		std::fs::write(&default_key, ed25519_pem([1; 32])).expect("write key");
		let own_key = dir.path().join("own.pem");
		std::fs::write(&own_key, ed25519_pem([2; 32])).expect("write key");
		PerDomainSigner::new(
			ReloadableSigner::new(Arc::new(Signer::load("def", &default_key).expect("load"))),
			vec![DomainSigner {
				domain: "example.org".into(),
				signer: ReloadableSigner::new(Arc::new(
					Signer::load("own", &own_key).expect("load"),
				)),
			}],
		)
	};
	let running = start_with(build());
	let local = build();
	let client = RemoteSigner::new(&running.socket);
	for domain in ["example.org", "Example.ORG", "other.example"] {
		for (raw, _) in GOLDEN {
			let in_process = local.sign(domain, raw.as_bytes()).expect("signs here");
			let remote = client
				.sign(domain, raw.as_bytes())
				.await
				.expect("signs over the socket");
			assert_eq!(remote, in_process, "{domain} {raw:?}");
		}
	}
	// The override and the default both answered: the test would pass
	// over one key otherwise.
	let own = client
		.sign("example.org", GOLDEN[0].0.as_bytes())
		.await
		.expect("signs");
	let default = client
		.sign("other.example", GOLDEN[0].0.as_bytes())
		.await
		.expect("signs");
	assert!(own.contains("s=own;"), "{own}");
	assert!(default.contains("s=def;"), "{default}");
}
