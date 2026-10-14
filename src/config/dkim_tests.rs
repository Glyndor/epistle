//! Tests for `Dkim` configuration parsing and `single_signature_warning`.

use std::path::PathBuf;

use super::{DKIM_RSA_REQUIRED_FROM, Dkim};

#[test]
fn parses_dkim_section() {
	let dkim: Dkim = toml::from_str(
		r#"
selector = "mail"
key_file = "/etc/mail/dkim.pem"
"#,
	)
	.expect("parse dkim");
	assert_eq!(dkim.selector.as_deref(), Some("mail"));
	// Deprecated fields default to None when absent.
	assert!(dkim.rotate_days.is_none());
	assert!(dkim.rotate_overlap_days.is_none());
}

#[test]
fn rejects_missing_fields_and_unknown_keys() {
	// A half-configured RSA pair is still rejected (the validator
	// runs the cross-field check, not serde); unknown keys remain a
	// load-time error from `deny_unknown_fields`.
	assert!(
		toml::from_str::<Dkim>(
			r#"
			selector = "mail"
			key_file = "/k.pem"
			algorithm = "rsa"
			"#
		)
		.is_err()
	);
}

#[test]
fn deprecated_rotation_fields_still_parse() {
	// Existing configs written before the interval became constant must
	// keep loading: `deny_unknown_fields` would otherwise reject the
	// whole file on upgrade. The values are captured but never read.
	let dkim: Dkim = toml::from_str(
		r#"
selector = "mail"
key_file = "/k.pem"
rotate_days = 30
rotate_overlap_days = 3
"#,
	)
	.expect("deprecated fields parse");
	assert_eq!(dkim.rotate_days, Some(30));
	assert_eq!(dkim.rotate_overlap_days, Some(3));
}

#[test]
fn only_one_deprecated_field_is_enough_to_be_ignored() {
	// Either field set on its own is also tolerated.
	let only_days: Dkim = toml::from_str(
		r#"
selector = "mail"
key_file = "/k.pem"
rotate_days = 30
"#,
	)
	.expect("parse");
	assert_eq!(only_days.rotate_days, Some(30));
	assert!(only_days.rotate_overlap_days.is_none());

	let only_overlap: Dkim = toml::from_str(
		r#"
selector = "mail"
key_file = "/k.pem"
rotate_overlap_days = 21
"#,
	)
	.expect("parse");
	assert!(only_overlap.rotate_days.is_none());
	assert_eq!(only_overlap.rotate_overlap_days, Some(21));
}

fn dkim_with_rsa() -> Dkim {
	Dkim {
		selector: Some("mail".into()),
		key_file: Some("/etc/mail/dkim.pem".into()),
		rsa_selector: Some("rsa1".into()),
		rsa_key_file: Some("/etc/mail/rsa.pem".into()),
		rotate_days: None,
		rotate_overlap_days: None,
		domain: Vec::new(),
	}
}

fn dkim_without_rsa() -> Dkim {
	Dkim {
		selector: Some("mail".into()),
		key_file: Some("/etc/mail/dkim.pem".into()),
		rsa_selector: None,
		rsa_key_file: None,
		rotate_days: None,
		rotate_overlap_days: None,
		domain: Vec::new(),
	}
}

#[test]
fn single_signature_warning_is_none_when_both_rsa_fields_are_set() {
	let dkim = dkim_with_rsa();
	assert!(
		dkim.single_signature_warning().is_none(),
		"both RSA fields set: warning must be suppressed"
	);
}

#[test]
fn single_signature_warning_is_some_when_neither_rsa_field_is_set() {
	let dkim = dkim_without_rsa();
	let warning = dkim
		.single_signature_warning()
		.expect("missing RSA fields must warn");
	assert!(
		warning.contains("dkim-keygen --rsa"),
		"warning must point at the remedy command: {warning}"
	);
	assert!(
		warning.contains(DKIM_RSA_REQUIRED_FROM),
		"warning must name the version that flips to refusal: {warning}"
	);
}

#[test]
fn single_signature_warning_is_some_when_only_rsa_selector_is_set() {
	let mut dkim = dkim_with_rsa();
	dkim.rsa_key_file = None;
	assert!(
		dkim.single_signature_warning().is_some(),
		"missing key file must warn (the pair has to be complete)"
	);
}

#[test]
fn single_signature_warning_is_some_when_only_rsa_key_file_is_set() {
	let mut dkim = dkim_with_rsa();
	dkim.rsa_selector = None;
	assert!(
		dkim.single_signature_warning().is_some(),
		"missing selector must warn (the pair has to be complete)"
	);
}

#[test]
fn parses_a_per_domain_override() {
	let dkim: Dkim = toml::from_str(
		r#"
selector = "mail"
key_file = "/etc/mail/dkim.pem"

[[domain]]
name = "example.org"
selector = "ed-2024a"
key_file = "/etc/mail/example-ed25519.pem"
rsa_selector = "rsa-2024a"
rsa_key_file = "/etc/mail/example-rsa.pem"
"#,
	)
	.expect("parse dkim with per-domain override");
	assert_eq!(dkim.domain.len(), 1, "one per-domain override parsed");
	assert_eq!(dkim.domain[0].name, "example.org");
	assert_eq!(dkim.domain[0].selector, "ed-2024a");
	assert_eq!(
		dkim.domain[0].key_file,
		PathBuf::from("/etc/mail/example-ed25519.pem")
	);
	assert_eq!(dkim.domain[0].rsa_selector.as_deref(), Some("rsa-2024a"));
	assert_eq!(
		dkim.domain[0].rsa_key_file.as_deref(),
		Some(std::path::Path::new("/etc/mail/example-rsa.pem"))
	);
}

#[test]
fn override_for_returns_the_match_by_name() {
	let dkim: Dkim = toml::from_str(
		r#"
selector = "mail"
key_file = "/etc/mail/dkim.pem"

[[domain]]
name = "example.org"
selector = "ed-a"
key_file = "/k-a.pem"

[[domain]]
name = "example.net"
selector = "ed-b"
key_file = "/k-b.pem"
"#,
	)
	.expect("parse");
	let one = dkim
		.override_for("example.org")
		.expect("example.org has an override");
	assert_eq!(one.selector, "ed-a");
	assert_eq!(
		dkim.override_for("example.net").expect("net").selector,
		"ed-b"
	);
	assert!(
		dkim.override_for("other.example").is_none(),
		"a domain with no override returns None"
	);
}

#[test]
fn override_rejects_an_unknown_key() {
	let result = toml::from_str::<Dkim>(
		r#"
selector = "mail"
key_file = "/k.pem"

[[domain]]
name = "example.org"
selector = "ed-a"
key_file = "/k-a.pem"
algorithm = "ed25519"
"#,
	);
	let err = result.expect_err("unknown field on a per-domain override is rejected");
	let message = format!("{err:?}");
	assert!(
		message.contains("algorithm"),
		"the rejection must name the unknown field, got {message:?}"
	);
}

#[test]
fn override_rsa_pair_check_matches_the_default_block() {
	let mut dkim: Dkim = toml::from_str(
		r#"
selector = "mail"
key_file = "/k.pem"

[[domain]]
name = "example.org"
selector = "ed-a"
key_file = "/k-a.pem"
rsa_selector = "rsa-a"
rsa_key_file = "/k-a-rsa.pem"
"#,
	)
	.expect("parse");
	assert!(dkim.domain[0].rsa_pair_is_complete());
	dkim.domain[0].rsa_key_file = None;
	assert!(
		!dkim.domain[0].rsa_pair_is_complete(),
		"a selector without a key file is half-configured"
	);
	dkim.domain[0].rsa_key_file = Some("/k-a-rsa.pem".into());
	dkim.domain[0].rsa_selector = None;
	assert!(
		!dkim.domain[0].rsa_pair_is_complete(),
		"a key file without a selector is half-configured"
	);
}
