//! The `[smtp]` section parses, defaults to today's behaviour and refuses
//! a level it does not know.

use super::{RefusalDetail, Smtp};

#[test]
fn the_defaults_keep_the_current_wording_and_turn_the_reference_on() {
	let smtp: Smtp = toml::from_str("").expect("parses");
	assert_eq!(smtp.reject_detail, RefusalDetail::Standard);
	assert!(smtp.reject_reference);
	assert_eq!(smtp, Smtp::default());
}

#[test]
fn each_level_parses() {
	for (word, level) in [
		("terse", RefusalDetail::Terse),
		("standard", RefusalDetail::Standard),
		("verbose", RefusalDetail::Verbose),
	] {
		let smtp: Smtp = toml::from_str(&format!("reject_detail = \"{word}\"")).expect("parses");
		assert_eq!(smtp.reject_detail, level);
	}
}

#[test]
fn an_unknown_level_is_refused() {
	let error = toml::from_str::<Smtp>("reject_detail = \"chatty\"").expect_err("refused");
	assert!(error.to_string().contains("chatty"), "{error}");
}

#[test]
fn the_reference_can_be_turned_off_and_an_unknown_key_is_refused() {
	let smtp: Smtp = toml::from_str("reject_reference = false").expect("parses");
	assert!(!smtp.reject_reference);
	assert!(toml::from_str::<Smtp>("reject_ref = true").is_err());
}

#[test]
fn the_section_loads_inside_the_whole_configuration() {
	let text = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/epistle\"\n\n\
		[smtp]\nreject_detail = \"verbose\"\nreject_reference = false\n";
	let config: crate::config::Config = toml::from_str(text).expect("parses");
	assert_eq!(config.smtp.reject_detail, RefusalDetail::Verbose);
	assert!(!config.smtp.reject_reference);
}
