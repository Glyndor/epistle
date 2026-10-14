//! `[dkim]` stays the default key when `[[dkim.domain]]` overrides are
//! present, and the overrides are looked up the way the signer does.

use super::Dkim;

#[test]
fn the_default_block_still_needs_its_selector_and_key_file() {
	for (text, missing) in [
		("selector = \"mail\"", "key_file"),
		("key_file = \"/k.pem\"", "selector"),
		(
			"[[domain]]\nname = \"example.org\"\nselector = \"ed-a\"\nkey_file = \"/a.pem\"",
			"selector",
		),
	] {
		match toml::from_str::<Dkim>(text) {
			Ok(_) => panic!("a [dkim] block without {missing} must be refused"),
			Err(error) => assert!(
				error.to_string().contains(missing),
				"the refusal must name {missing}"
			),
		}
	}
}

fn two_overrides() -> Dkim {
	toml::from_str(
		r#"
selector = "mail"
key_file = "/etc/mail/dkim.pem"
rsa_selector = "mail-rsa"
rsa_key_file = "/etc/mail/rsa.pem"

[[domain]]
name = "example.org"
selector = "org-ed"
key_file = "/var/lib/epistle/dkim-ed20000.key"

[[domain]]
name = "example.net"
selector = "net-ed"
key_file = "/etc/mail/net.pem"
rsa_selector = "net-rsa"
rsa_key_file = "/etc/mail/net-rsa.pem"
"#,
	)
	.unwrap_or_else(|error| panic!("the [dkim] block parses: {error}"))
}

#[test]
fn override_for_matches_the_domain_in_any_case() {
	let dkim = two_overrides();
	let found = dkim
		.override_for("EXAMPLE.org")
		.map(|d| d.selector.as_str());
	assert_eq!(found, Some("org-ed"));
	assert!(dkim.override_for("other.example").is_none());
}

#[test]
fn kept_selectors_name_the_default_and_every_override() {
	let kept = two_overrides().kept_selectors();
	for selector in ["mail", "mail-rsa", "org-ed", "net-ed", "net-rsa"] {
		assert!(
			kept.iter().any(|kept| kept == selector),
			"{selector} must never be taken for a leftover"
		);
	}
	// The override's key file has the shape of a rotated key file, so
	// the selector its name carries is kept too: removing that file
	// would leave the domain without a key.
	assert!(
		kept.iter().any(|kept| kept == "ed20000"),
		"the selector in an override's key file name must be kept"
	);
}
