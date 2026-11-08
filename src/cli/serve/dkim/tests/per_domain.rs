//! A `[[dkim.domain]]` key is read at startup like the default key: one
//! that cannot be read or is not a key stops the start.

use super::*;

fn build_with_override(write_override: Option<&[u8]>) -> std::io::Result<SplitCompanions> {
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.path().join("default.key"), pem).expect("write default");
	if let Some(bytes) = write_override {
		std::fs::write(dir.path().join("override.key"), bytes).expect("write override");
	}
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org', 'example.net']\n\
		 [dkim]\nselector = 'mail'\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = 'example.net'\nselector = 'net'\nkey_file = {:?}\n",
		dir.path(),
		dir.path().join("default.key"),
		dir.path().join("override.key"),
	))
	.expect("config");
	build_split_with_companions(
		&config,
		&Arc::new(Metrics::default()),
		DirectoryHandle::new(crate::smtp::directory::Directory::default()),
		MessageCrypto::disabled(),
	)
}

#[test]
fn a_readable_override_key_starts() {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	assert!(build_with_override(Some(pem.as_bytes())).is_ok());
}

#[test]
fn a_missing_or_invalid_override_key_stops_the_start() {
	assert!(
		build_with_override(None).is_err(),
		"a missing key file must stop the start"
	);
	assert!(
		build_with_override(Some(b"not a key")).is_err(),
		"a file that is not a key must stop the start"
	);
}

/// A data directory where `example.net` has an entry key (`net`) and its
/// rotation state names a rotated key (`own20000`); `state` is the state
/// file's content, `None` for the state the rotation writes.
fn build_after_rotation(
	state: Option<&[u8]>,
) -> (tempfile::TempDir, std::io::Result<SplitCompanions>) {
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.path().join("default.key"), pem).expect("write default");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.path().join("override.key"), pem).expect("write override");
	let key_dir = crate::dkim::domain_rotate::state_dir(dir.path(), "example.net").expect("dir");
	std::fs::create_dir_all(&key_dir).expect("mkdir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(key_dir.join("own20000.pem"), pem).expect("write rotated");
	let written = crate::dkim::rotate::RotationState {
		selector: "own20000".into(),
		key_file: key_dir.join("own20000.pem"),
		rotated_at: 20_000 * 86_400,
		previous: None,
		pending: None,
		rsa: None,
	};
	let bytes = match state {
		Some(bytes) => bytes.to_vec(),
		None => serde_json::to_vec(&written).expect("json"),
	};
	std::fs::write(key_dir.join(crate::dkim::domain_rotate::STATE_FILE), bytes).expect("state");
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org', 'example.net']\n\
		 [dkim]\nselector = 'mail'\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = 'example.net'\nselector = 'net'\nkey_file = {:?}\n",
		dir.path(),
		dir.path().join("default.key"),
		dir.path().join("override.key"),
	))
	.expect("config");
	let built = build_split_with_companions(
		&config,
		&Arc::new(Metrics::default()),
		DirectoryHandle::new(crate::smtp::directory::Directory::default()),
		MessageCrypto::disabled(),
	);
	(dir, built)
}

#[test]
fn a_domain_that_rotated_starts_on_its_rotated_key() {
	let (_dir, built) = build_after_rotation(None);
	let companions = built.expect("starts");
	let net = companions
		.domain_signers
		.iter()
		.find(|s| s.domain == "example.net")
		.expect("the domain's signer is handed to its rotation");
	assert_eq!(net.signer.current().selector(), "own20000");
	let header = net
		.signer
		.current()
		.sign("example.net", b"From: a@example.net\r\n\r\nHi\r\n")
		.expect("signs");
	assert!(header.contains("s=own20000;"), "{header}");
}

#[test]
fn a_domain_whose_rotation_state_cannot_be_read_stops_the_start() {
	let (_dir, built) = build_after_rotation(Some(b"{ not json"));
	assert!(
		built.is_err(),
		"signing with the entry's key could use a record the rotation already moved on from"
	);
}
