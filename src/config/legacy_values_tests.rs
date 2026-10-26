//! A file an older release wrote must still load, with the value that the
//! new rules refuse ignored and said so; the lenient load must carry on past
//! a validation failure; and the validation itself must still refuse the
//! value.

use std::io::Write;
use std::path::Path;

use super::super::{Config, ConfigError};

const BASE: &str = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";

fn parse(extra: &str) -> Result<Config, ConfigError> {
	Config::parse_text(&format!("{BASE}{extra}"), Path::new("mail.toml"))
}

#[test]
fn a_site_local_public_ipv6_loads_and_is_ignored_with_a_line() {
	let config = parse("public_ipv6 = \"fec0::5054:ff:fe12:3456\"\n").expect("loads");
	assert_eq!(config.public_ipv6, None);
	let line = config.adjusted.first().expect("a line says so");
	assert!(
		line.contains("public_ipv6 \"fec0::5054:ff:fe12:3456\" in the file"),
		"{line}"
	);
	assert!(
		line.contains("outside global IPv6 unicast space (2000::/3)"),
		"{line}"
	);
	assert!(line.contains("ignored"), "{line}");
	assert!(line.contains("remove the line"), "{line}");
}

#[test]
fn a_private_public_ipv4_loads_and_is_ignored_with_a_line() {
	let config = parse("public_ipv4 = \"10.0.2.15\"\n").expect("loads");
	assert_eq!(config.public_ipv4, None);
	assert!(config.adjusted[0].contains("public_ipv4 \"10.0.2.15\" in the file"));
}

#[test]
fn a_global_public_address_is_kept() {
	let config = parse("public_ipv6 = \"2606:4700::1111\"\npublic_ipv4 = \"1.1.1.1\"\n").unwrap();
	assert_eq!(config.public_ipv6, Some("2606:4700::1111".parse().unwrap()));
	assert!(config.public_ipv4.is_some());
	assert!(config.adjusted.is_empty(), "{:?}", config.adjusted);
}

/// The validation is what `init` and the writers still call, so the same
/// value stays refused where it is new.
#[test]
fn validation_still_refuses_the_value() {
	let raw = format!("{BASE}public_ipv6 = \"fec0::1\"\n");
	let config: Config = toml::from_str(&raw).expect("parses");
	let error = config.validate().expect_err("refused").to_string();
	assert!(
		error.contains("outside global IPv6 unicast space"),
		"{error}"
	);
}

#[test]
fn a_list_id_the_headers_cannot_carry_is_ignored_with_a_line() {
	let config = parse(
		"[[alias]]\naddress = \"team@example.org\"\nmembers = [\"a@example.org\"]\nlist_id = \"Team List team.example.org\"\n",
	)
	.expect("loads");
	assert_eq!(config.alias[0].list_id, None);
	assert!(
		config.adjusted[0].contains("team@example.org"),
		"{:?}",
		config.adjusted
	);
	assert!(config.adjusted[0].contains("list_id \"Team List team.example.org\""));
}

fn temp(content: &str) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().expect("temp");
	file.write_all(content.as_bytes()).expect("write");
	file
}

/// An alias with no members fails validation, whatever the release.
const INVALID: &str = "[[alias]]\naddress = \"team@example.org\"\nmembers = []\n";

#[test]
fn the_lenient_load_carries_on_past_a_validation_failure() {
	let file = temp(&format!("{BASE}{INVALID}"));
	assert!(
		Config::load(file.path()).is_err(),
		"the strict load refuses"
	);
	let config = Config::load_lenient(file.path()).expect("lenient load");
	let why = config.validation_error.expect("the reason is kept");
	assert!(why.contains("has no members"), "{why}");
	assert_eq!(config.data_dir, Path::new("/var/lib/mail"));
}

#[test]
fn the_lenient_load_still_refuses_a_file_that_does_not_parse() {
	let file = temp(&format!("{BASE}not_a_key = 1\n"));
	assert!(Config::load_lenient(file.path()).is_err());
}

#[test]
fn a_valid_file_has_no_validation_error_either_way() {
	let file = temp(BASE);
	assert!(
		Config::load_lenient(file.path())
			.unwrap()
			.validation_error
			.is_none()
	);
	assert!(
		Config::load(file.path())
			.unwrap()
			.validation_error
			.is_none()
	);
}
