use super::*;

#[test]
fn parses_api_section() {
	let api: Api = toml::from_str(r#"token_hash = "$argon2id$x""#).expect("parse");
	assert_eq!(api.token_hash, "$argon2id$x");
	assert!(api.admins.is_empty());
	assert!(api.trusted_proxies.is_empty());
}

#[test]
fn parses_admins_list() {
	let api: Api = toml::from_str(
		r#"token_hash = "$argon2id$x"
admins = ["ops-a1b2"]"#,
	)
	.expect("parse");
	assert_eq!(api.admins, vec!["ops-a1b2".to_string()]);
}

#[test]
fn rejects_unknown_keys() {
	assert!(
		toml::from_str::<Api>(
			r#"token_hash = "x"
port = 1"#
		)
		.is_err()
	);
}

#[test]
fn trusted_proxy_cidrs_are_validated_during_config_loading() {
	use crate::config::Config;
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().unwrap();
	let base = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/tmp/epistle\"\n[api]\ntoken_hash = \"sha256:{}\"\n",
		"0".repeat(64)
	);
	for invalid in [
		"bad",
		"192.0.2.0/33",
		"2001:db8::/129",
		"192.0.2.0/x",
		"192.0.2.0/24/1",
		"192.0.2.1",
	] {
		file.as_file_mut().set_len(0).unwrap();
		use std::io::Seek;
		file.as_file_mut().rewind().unwrap();
		write!(file, "{base}trusted_proxies = [\"{invalid}\"]").unwrap();
		let err = Config::load(file.path()).unwrap_err().to_string();
		assert!(err.contains("[api] trusted_proxies"), "{err}");
	}
	for networks in ["[]", "[\"192.0.2.0/24\", \"2001:db8::/32\"]"] {
		let config =
			Config::parse_text(&format!("{base}trusted_proxies = {networks}"), file.path())
				.unwrap();
		assert_eq!(
			config.api.unwrap().trusted_proxies.len(),
			if networks == "[]" { 0 } else { 2 }
		);
	}
}
