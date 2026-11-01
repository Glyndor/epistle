use super::*;

#[test]
fn parses_api_section() {
	let api: Api = toml::from_str(r#"token_hash = "$argon2id$x""#).expect("parse");
	assert_eq!(api.token_hash.as_deref(), Some("$argon2id$x"));
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

#[test]
fn trusted_proxies_rejects_universal_slash_zero_prefix() {
	use crate::config::Config;
	let base = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/tmp/epistle\"\n[api]\ntoken_hash = \"sha256:{}\"\n",
		"0".repeat(64)
	);
	let file = tempfile::NamedTempFile::new().unwrap();
	for invalid in ["0.0.0.0/0", "::/0"] {
		let err = Config::parse_text(
			&format!("{base}trusted_proxies = [\"{invalid}\"]"),
			file.path(),
		)
		.unwrap_err()
		.to_string();
		assert!(
			err.contains("[api] trusted_proxies") && err.contains(invalid),
			"{err}"
		);
	}
}

#[test]
fn trusted_proxies_deduplicates_entries_at_load_time() {
	use crate::config::Config;
	let base = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/tmp/epistle\"\n[api]\ntoken_hash = \"sha256:{}\"\n",
		"0".repeat(64)
	);
	let file = tempfile::NamedTempFile::new().unwrap();
	let config = Config::parse_text(
		&format!(
			"{base}trusted_proxies = [\"192.0.2.0/24\", \"192.0.2.0/24\", \
			 \"192.0.2.55/24\", \"2001:db8::/32\"]"
		),
		file.path(),
	)
	.unwrap();
	assert_eq!(config.api.unwrap().trusted_proxies.len(), 2);
}

#[test]
fn trusted_proxies_rejects_lists_above_the_documented_maximum() {
	use crate::config::Config;
	let base = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/tmp/epistle\"\n[api]\ntoken_hash = \"sha256:{}\"\n",
		"0".repeat(64)
	);
	let file = tempfile::NamedTempFile::new().unwrap();
	let mut entries: Vec<String> = (0..=super::MAX_TRUSTED_PROXIES)
		.map(|n| format!("\"10.0.{}.0/24\"", n / 256))
		.collect();
	entries.push("\"10.0.99.0/24\"".to_string());
	let toml = format!("{base}trusted_proxies = [{}]", entries.join(", "));
	let err = Config::parse_text(&toml, file.path())
		.unwrap_err()
		.to_string();
	assert!(err.contains("[api] trusted_proxies"), "{err}");
	assert!(
		err.contains(&format!("{}", super::MAX_TRUSTED_PROXIES + 2)),
		"{err}"
	);
}

#[test]
fn a_refused_trusted_proxy_names_the_value_the_rule_and_a_network_to_write() {
	use crate::config::Config;
	let base = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n[api]\n";
	for (invalid, rule) in [
		("192.0.2.1", "has no prefix length"),
		("foo", "is not an IP address or CIDR block"),
		("192.0.2.0/33", "is not an IP address or CIDR block"),
	] {
		let err = Config::parse_text(
			&format!("{base}trusted_proxies = [\"{invalid}\"]"),
			std::path::Path::new("mail.toml"),
		)
		.unwrap_err()
		.to_string();
		assert!(err.contains(&format!("\"{invalid}\"")), "{err}");
		assert!(err.contains(rule), "{err}");
		assert!(
			err.contains("for example \"10.0.0.0/8\"")
				|| err.contains("for example \"203.0.113.0/24\""),
			"{err}"
		);
	}
}

#[test]
fn optional_static_token_loads_but_listener_still_requires_api_section() {
	let api: Api = toml::from_str("").expect("no static credential required");
	assert!(api.token_hash.is_none());
	let base =
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n";
	let listener = "[[listeners]]\nkind = 'api'\naddr = '127.0.0.1'\n";
	let file = tempfile::NamedTempFile::new().unwrap();
	assert!(
		crate::config::Config::parse_text(&format!("{base}{listener}[api]\n"), file.path()).is_ok()
	);
	assert!(crate::config::Config::parse_text(&format!("{base}{listener}"), file.path()).is_err());
	for invalid in ["", "sha256:", "plaintext"] {
		assert!(
			crate::config::Config::parse_text(
				&format!("{base}{listener}[api]\ntoken_hash = {invalid:?}\n"),
				file.path()
			)
			.is_err()
		);
	}
}
