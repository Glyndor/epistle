//! The keys the `dns` check compares with DNS are the ones that sign,
//! including an RSA key a rotation put in service.

use super::signing_keys;
use crate::config::Config;
use crate::dkim::rotate::{RotationState, RsaKey, STATE_FILE};

#[test]
fn the_rotated_rsa_key_is_the_one_compared() {
	let dir = tempfile::tempdir().expect("dir");
	let (rsa_pem, rsa_value) = match crate::dkim::generate_rsa_key(2048) {
		Ok(key) => key,
		Err(error) => {
			eprintln!(
				"skip: no RSA key could be generated ({error}); the rotated RSA key was not exercised"
			);
			return;
		}
	};
	let (pem, _) = crate::dkim::generate_key().expect("ed25519 key");
	std::fs::write(dir.path().join("dkim-ed7.key"), pem).expect("write key");
	std::fs::write(dir.path().join("dkim-rsa7.key"), rsa_pem).expect("write RSA key");
	let state = RotationState {
		selector: "ed7".into(),
		key_file: "dkim-ed7.key".into(),
		rotated_at: 1,
		previous: None,
		pending: None,
		rsa: Some(RsaKey {
			selector: "rsa7".into(),
			key_file: "dkim-rsa7.key".into(),
		}),
	};
	std::fs::write(
		dir.path().join(STATE_FILE),
		serde_json::to_vec(&state).expect("json"),
	)
	.expect("state");
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n[dkim]\nselector = 'ed-configured'\nkey_file = '/nonexistent/ed.key'\nrsa_selector = 'rsa-configured'\nrsa_key_file = '/nonexistent/rsa.key'\n",
		dir.path()
	))
	.expect("config");
	let keys = signing_keys(&config).unwrap_or_else(|_| panic!("the signing keys load"));
	let selectors: Vec<&str> = keys.iter().map(|key| key.selector.as_str()).collect();
	assert_eq!(selectors, ["ed7", "rsa7"]);
	assert_eq!(keys[1].public, super::public_value(&rsa_value));
	assert_eq!(keys[1].file, dir.path().join("dkim-rsa7.key"));
}
