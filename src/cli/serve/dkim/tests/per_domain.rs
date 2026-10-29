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
