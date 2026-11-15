//! `[deliverability]`: the default, the names and the portal strings.

use super::*;

fn parse(extra: &str) -> Result<crate::config::Config, crate::config::ConfigError> {
	let dir = tempfile::tempdir().expect("directory");
	let text = format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n{extra}",
		dir.path()
	);
	crate::config::Config::parse_text(&text, std::path::Path::new("mail.toml"))
}

const EVERY_NAME: [&str; 5] = ["postmaster", "snds", "jmrp", "yahoo-cfl", "apple"];

#[test]
fn the_section_is_empty_by_default() {
	let config = parse("").expect("config");
	assert!(config.deliverability.enrolled.is_empty());
	assert_eq!(config.deliverability.missing(), Portal::ALL.to_vec());
	assert_eq!(
		config
			.deliverability
			.missing()
			.into_iter()
			.map(Portal::name)
			.collect::<Vec<_>>(),
		EVERY_NAME
	);
}

#[test]
fn every_known_name_is_accepted() {
	let config = parse(
		"[deliverability]\nenrolled = ['postmaster', 'snds', 'jmrp', 'yahoo-cfl', 'apple']\n",
	)
	.expect("config");
	assert_eq!(config.deliverability.enrolled, Portal::ALL.to_vec());
	assert!(config.deliverability.missing().is_empty());
}

#[test]
fn a_marked_portal_leaves_the_missing_list_and_the_order_is_kept() {
	let config = parse("[deliverability]\nenrolled = ['jmrp', 'postmaster']\n").expect("config");
	assert_eq!(
		config.deliverability.missing(),
		vec![Portal::Snds, Portal::YahooCfl, Portal::Apple]
	);
}

#[test]
fn an_unknown_name_is_refused_naming_the_panels_that_exist() {
	for unknown in ["gmx", "Postmaster", "", "yahoo"] {
		let error = parse(&format!("[deliverability]\nenrolled = ['{unknown}']\n"))
			.expect_err("not a panel");
		let text = error.to_string();
		for name in EVERY_NAME {
			assert!(
				text.contains(name),
				"{unknown:?}: {name} missing from {text}"
			);
		}
	}
}

#[test]
fn an_unknown_key_is_refused() {
	assert!(parse("[deliverability]\nenrolledd = []\n").is_err());
}

#[test]
fn the_names_round_trip_and_match_the_list_the_error_prints() {
	assert_eq!(Portal::names(), EVERY_NAME);
	for portal in Portal::ALL {
		assert_eq!(Portal::parse(portal.name()), Some(portal));
	}
	assert_eq!(Portal::parse("gmx"), None);
}

#[test]
fn the_page_and_the_description_of_every_portal_are_not_empty() {
	for portal in Portal::ALL {
		assert!(!portal.what().trim().is_empty(), "{portal:?}");
		assert!(portal.page().starts_with("https://"), "{portal:?}");
		assert!(!portal.page().contains(char::is_whitespace), "{portal:?}");
	}
}
