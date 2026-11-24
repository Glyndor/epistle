//! A network `api-key create` cannot take is refused with exit code 2 before
//! a class is bound or the key store is touched.

use super::*;
use crate::evidence::MailClass;

fn config(data_dir: &std::path::Path) -> Config {
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		data_dir.display()
	);
	toml::from_str(&toml).expect("config parses")
}

#[test]
fn a_bad_network_binds_no_class_and_stores_no_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = config(dir.path());
	let code = create(
		&config,
		NewKey {
			label: "mailer".into(),
			scopes: vec!["send".into()],
			ip_cidr: Some("not-a-network".into()),
			class: Some(MailClass::Marketing),
			..NewKey::default()
		},
		false,
		&mut Vec::new(),
		&mut Vec::new(),
	);
	assert_eq!(code, ExitCode::from(2));
	assert!(
		crate::evidence::bindings::load(dir.path())
			.expect("bindings")
			.credentials
			.is_empty(),
		"a class was bound for a key that was never made"
	);
	assert!(
		ApiKeyStore::open(dir.path())
			.expect("open")
			.keys()
			.is_empty()
	);
}
