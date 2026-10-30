//! Parsing `"none"` for the public addresses of an answers file.

use super::super::super::Answers;
use super::*;

fn file(addresses: &str) -> String {
	format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 {addresses}\
		 data_dir = \"/var/lib/epistle\"\n\
		 config_path = \"/etc/epistle/mail.toml\"\n\n\
		 [services]\n\
		 database = false\n"
	)
}

#[test]
fn none_parses_as_no_address_and_is_reported_as_declined() {
	let raw = file("public_ipv4 = \"none\"\npublic_ipv6 = \"none\"\n");
	let parsed: Result<Answers, _> = toml::from_str(&raw);
	let answers = match parsed {
		Ok(answers) => answers,
		Err(error) => panic!("\"none\" must be accepted: {}", error.message()),
	};
	assert_eq!((answers.public_ipv4, answers.public_ipv6), (None, None));
	assert_eq!(declined(&raw), Declined { v4: true, v6: true });
}

#[test]
fn a_left_out_key_is_not_declined() {
	let raw = file("public_ipv6 = \"none\"\n");
	assert_eq!(
		declined(&raw),
		Declined {
			v4: false,
			v6: true
		}
	);
}

#[test]
fn an_address_is_not_declined() {
	let raw = file("public_ipv4 = \"8.8.8.8\"\n");
	let answers: Answers = toml::from_str(&raw).expect("an address parses");
	assert_eq!(answers.public_ipv4, Some("8.8.8.8".parse().expect("v4")));
	assert_eq!(declined(&raw), Declined::default());
}

#[test]
fn any_other_string_is_still_an_invalid_address() {
	let raw = file("public_ipv4 = \"nowhere\"\n");
	let error = toml::from_str::<Answers>(&raw).expect_err("not an address");
	assert_eq!(error.message(), "invalid IPv4 address syntax");
}
