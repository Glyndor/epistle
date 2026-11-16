//! The `[smtp]` section parses, defaults to today's behaviour and refuses
//! a level it does not know.

use super::{MailboxFull, RefusalDetail, Smtp};

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

fn networks(list: &str) -> Result<Smtp, toml::de::Error> {
	toml::from_str(&format!("trusted_networks = {list}"))
}

#[test]
fn the_new_keys_default_to_trusting_nobody_and_a_temporary_full_mailbox() {
	let smtp: Smtp = toml::from_str("").expect("parses");
	assert!(smtp.trusted_networks.is_empty());
	assert_eq!(smtp.mailbox_full, MailboxFull::Temporary);
}

#[test]
fn a_full_mailbox_can_be_made_permanent_and_an_unknown_word_is_refused() {
	let smtp: Smtp = toml::from_str("mailbox_full = \"permanent\"").expect("parses");
	assert_eq!(smtp.mailbox_full, MailboxFull::Permanent);
	assert!(toml::from_str::<Smtp>("mailbox_full = \"sometimes\"").is_err());
}

#[test]
fn trusted_networks_parse_into_blocks() {
	let smtp = networks("[\"192.0.2.0/24\", \"2001:db8::/32\", \"198.51.100.7\"]").expect("parses");
	let ip = |text: &str| text.parse::<std::net::IpAddr>().expect("address");
	assert!(
		smtp.trusted_networks
			.iter()
			.any(|n| n.contains(ip("192.0.2.9")))
	);
	assert!(
		smtp.trusted_networks
			.iter()
			.any(|n| n.contains(ip("2001:db8::1")))
	);
	assert!(
		smtp.trusted_networks
			.iter()
			.any(|n| n.contains(ip("198.51.100.7")))
	);
	assert!(
		!smtp
			.trusted_networks
			.iter()
			.any(|n| n.contains(ip("203.0.113.1")))
	);
}

/// Every refusal names the key, so the operator knows which line to fix.
#[test]
fn a_network_that_is_malformed_too_wide_or_repeated_is_refused_by_key() {
	for list in [
		"[\"not-an-address\"]",
		"[\"0.0.0.0/0\"]",
		"[\"::/0\"]",
		"[\"10.0.0.0/7\"]",
		"[\"2001:db8::/31\"]",
		"[\"192.0.2.0/24\", \"192.0.2.0/24\"]",
	] {
		let error = networks(list).expect_err(list);
		assert!(
			error.to_string().contains("[smtp] trusted_networks"),
			"{list}: {error}"
		);
	}
}

#[test]
fn the_narrowest_allowed_networks_are_accepted() {
	assert!(networks("[\"10.0.0.0/8\", \"2001:db8::/32\"]").is_ok());
}

#[test]
fn a_list_over_the_cap_is_refused() {
	let many: Vec<String> = (0..=256)
		.map(|n| format!("\"10.{}.{}.0/24\"", n / 256, n % 256))
		.collect();
	let error = networks(&format!("[{}]", many.join(", "))).expect_err("over the cap");
	assert!(error.to_string().contains("maximum is 256"), "{error}");
}
