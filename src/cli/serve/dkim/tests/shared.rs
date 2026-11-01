//! Two domains that publish one public key stop the start; the default key
//! shared by several domains does not.

use super::*;

fn build(extra_override: bool) -> std::io::Result<SplitCompanions> {
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.path().join("default.key"), &pem).expect("write default");
	let copy_or_new = if extra_override {
		pem
	} else {
		crate::dkim::generate_key().expect("key").0
	};
	std::fs::write(dir.path().join("net.key"), copy_or_new).expect("write override");
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org', 'example.net']\n\
		 [dkim]\nselector = 'mail'\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = 'example.net'\nselector = 'net'\nkey_file = {:?}\n",
		dir.path(),
		dir.path().join("default.key"),
		dir.path().join("net.key"),
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
fn an_override_that_copies_the_default_key_stops_the_start() {
	let error = build(true).err().expect("a shared key must stop the start");
	assert!(
		error.to_string().contains("the same ed25519 public key"),
		"{error}"
	);
}

#[test]
fn an_override_with_its_own_key_starts() {
	assert!(build(false).is_ok());
}

#[test]
fn several_domains_on_the_default_key_still_start() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.path().join("default.key"), pem).expect("write default");
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org', 'example.net']\n\
		 [dkim]\nselector = 'mail'\nkey_file = {:?}\n",
		dir.path(),
		dir.path().join("default.key"),
	))
	.expect("config");
	let started = build_split_with_companions(
		&config,
		&Arc::new(Metrics::default()),
		DirectoryHandle::new(crate::smtp::directory::Directory::default()),
		MessageCrypto::disabled(),
	);
	assert!(
		started.is_ok(),
		"an install made before per-domain keys keeps signing as it did"
	);
}
