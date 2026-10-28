//! Once a rotation names an RSA key, every command that names the RSA key
//! in service follows the state like the ed25519 key does: `dns-records`,
//! `verify-dns` and the signer `serve` starts with.

use crate::config::Config;
use crate::dkim::rotate::{RotationState, RsaKey, STATE_FILE};

/// A data directory whose state names `ed7` and the rotated RSA key `rsa7`,
/// and a dual-signing configuration that names other keys. The RSA key is
/// made in process at test time; `Err` says why it could not be.
fn dual(dir: &std::path::Path) -> Result<Config, String> {
	let (rsa_pem, _) = crate::dkim::generate_rsa_key(2048).map_err(|e| e.to_string())?;
	let (pem, _) = crate::dkim::generate_key().expect("ed25519 key");
	std::fs::write(dir.join("dkim-ed7.key"), pem).expect("write key");
	std::fs::write(dir.join("dkim-rsa7.key"), rsa_pem).expect("write RSA key");
	let state = RotationState {
		selector: "ed7".into(),
		key_file: "dkim-ed7.key".into(),
		rotated_at: 7 * 86_400,
		previous: None,
		pending: None,
		rsa: Some(RsaKey {
			selector: "rsa7".into(),
			key_file: "dkim-rsa7.key".into(),
		}),
	};
	std::fs::write(
		dir.join(STATE_FILE),
		serde_json::to_vec(&state).expect("json"),
	)
	.expect("state");
	Ok(toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['example.org']\n[dkim]\nselector = 'ed-configured'\nkey_file = '/nonexistent/ed.key'\nrsa_selector = 'rsa-configured'\nrsa_key_file = '/nonexistent/rsa.key'\n"
	))
	.expect("config"))
}

fn skipped(reason: &str) {
	eprintln!(
		"skip: no RSA key could be generated ({reason}); the rotated RSA key was not exercised"
	);
}

#[test]
fn dns_records_prints_the_rotated_rsa_selector() {
	let dir = tempfile::tempdir().expect("dir");
	let config = match dual(dir.path()) {
		Ok(config) => config,
		Err(reason) => return skipped(&reason),
	};
	let mut out = Vec::new();
	assert_eq!(
		super::run(&config, false, &mut out),
		std::process::ExitCode::SUCCESS
	);
	let text = String::from_utf8_lossy(&out);
	assert!(
		text.contains("rsa7._domainkey.example.org") && text.contains("k=rsa"),
		"the rotated RSA key is printed"
	);
	assert!(
		!text.contains("rsa-configured._domainkey"),
		"the configured RSA selector is not printed"
	);
}

#[test]
fn verify_dns_looks_up_the_rotated_rsa_selector() {
	let dir = tempfile::tempdir().expect("dir");
	let config = match dual(dir.path()) {
		Ok(config) => config,
		Err(reason) => return skipped(&reason),
	};
	assert_eq!(
		super::super::verify_dns::dkim_default_selectors(&config)
			.unwrap_or_else(|_| panic!("the selectors resolve")),
		vec!["ed7".to_string(), "rsa7".to_string()]
	);
}

#[test]
fn serve_starts_signing_with_the_rotated_rsa_key() {
	use std::sync::Arc;
	let dir = tempfile::tempdir().expect("dir");
	let config = match dual(dir.path()) {
		Ok(config) => config,
		Err(reason) => return skipped(&reason),
	};
	let companions = super::super::serve_dkim::build_split_with_companions(
		&config,
		&Arc::new(crate::metrics::Metrics::default()),
		crate::directory_store::DirectoryHandle::new(crate::smtp::directory::Directory::default()),
		crate::storage::MessageCrypto::disabled(),
	)
	.unwrap_or_else(|_| panic!("startup with a rotated RSA key"));
	let signer = companions.dkim_signer.expect("signer").current();
	assert_eq!(signer.selector(), "ed7");
	assert_eq!(signer.rsa_selector(), Some("rsa7"));
}
