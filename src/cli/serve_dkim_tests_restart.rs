//! Signing after loading persisted rotation state at startup.

use super::*;
use crate::dkim::rotate::{Previous, RotationState};
use crate::dkim::test_support::{KeyDns, signature_fields};

fn config(dir: &std::path::Path) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {dir:?}\ndomains = [\"example.org\"]\n\
		[dkim]\nselector = \"original\"\nkey_file = {:?}\n",
		dir.join("original.key")
	))
	.expect("config")
}

fn build(config: &Config) -> std::io::Result<SplitCompanions> {
	build_split_with_companions(
		config,
		&Arc::new(Metrics::default()),
		DirectoryHandle::new(crate::smtp::directory::Directory::default()),
		MessageCrypto::disabled(),
	)
}

#[test]
fn startup_without_rotation_state_uses_configured_selector() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let root = dir.path().canonicalize().expect("absolute data dir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(root.join("original.key"), pem).expect("write key");
	let companions = build(&config(&root)).expect("startup without state");
	let header = companions
		.dkim_signer
		.expect("signer")
		.current()
		.sign("example.org", b"From: alice@example.org\r\n\r\nHello\r\n")
		.expect("sign");
	assert_eq!(
		signature_fields(header.as_bytes()),
		vec![(
			"original".into(),
			"example.org".into(),
			"ed25519-sha256".into()
		)],
		"startup without rotation state must use the configured selector"
	);
}

#[test]
fn startup_rejects_corrupt_rotation_state() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let root = dir.path().canonicalize().expect("absolute data dir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(root.join("original.key"), pem).expect("write key");
	std::fs::write(root.join("dkim-rotation.json"), b"invalid JSON").expect("write state");
	assert_eq!(
		build(&config(&root)).err().map(|error| error.kind()),
		Some(std::io::ErrorKind::InvalidData),
		"corrupt rotation state must stop startup with InvalidData"
	);
}

#[tokio::test]
async fn restart_signs_with_current_rotation_key() {
	for relative in [false, true] {
		for retire_at in [0, u64::MAX] {
			let dir = tempfile::tempdir_in(".").expect("tempdir");
			let root = dir.path().canonicalize().expect("absolute data dir");
			let (original, old_record) = crate::dkim::generate_key().expect("original key");
			let (current, current_record) = crate::dkim::generate_key().expect("current key");
			std::fs::write(root.join("original.key"), original).expect("write original");
			std::fs::write(root.join("current.key"), current).expect("write current");
			let state = RotationState {
				selector: "current".into(),
				key_file: if relative {
					"current.key".into()
				} else {
					root.join("current.key")
				},
				rotated_at: 123,
				previous: Some(Previous {
					selector: "original".into(),
					key_file: root.join("original.key"),
					retire_at,
				}),
				pending: None,
			};
			std::fs::write(
				root.join("dkim-rotation.json"),
				serde_json::to_vec(&state).expect("state JSON"),
			)
			.expect("write state");
			let config = config(&root);
			let raw = b"From: alice@example.org\r\nSubject: restart\r\n\r\nHello\r\n";
			let companions = build(&config).expect("startup");
			let handle = companions.dkim_signer.expect("signer configured");
			let header = handle.current().sign("example.org", raw).expect("sign");
			assert_eq!(
				signature_fields(header.as_bytes()),
				vec![(
					"current".into(),
					"example.org".into(),
					"ed25519-sha256".into()
				)],
				"restart must sign only with the current rotation selector"
			);
			let dns = KeyDns(std::collections::HashMap::from([
				(
					"current._domainkey.example.org".into(),
					vec![current_record],
				),
				("original._domainkey.example.org".into(), vec![old_record]),
			]));
			let signed = [header.as_bytes(), raw].concat();
			let results = crate::dkim::verify_message(&dns, &signed).await;
			assert_eq!(results.len(), 1, "restart emits one ed25519 signature");
			assert_eq!(
				results[0].outcome,
				crate::dkim::DkimOutcome::Pass,
				"restart signature must verify with the current public key"
			);
			std::fs::remove_file(root.join("original.key")).expect("remove retired key");
			assert!(
				build(&config).is_ok(),
				"startup uses only the current key file"
			);
		}
	}
}
