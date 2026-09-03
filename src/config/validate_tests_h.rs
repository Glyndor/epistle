//! Validation tests for IDNA: domains in config stay ASCII on disk.
//!
//! Split out of `validate_tests.rs` to stay under the line limit, matching
//! the precedent set by the alert tests in `validate_tests_c.rs`, the
//! tenant tests in `validate_tests_d.rs`, the SRS tests in
//! `validate_tests_e.rs`, the database TLS tests in `validate_tests_f.rs`
//! and the postmaster tests in `validate_tests_g.rs`.

use super::tests::config_from;

#[test]
fn rejects_a_u_label_domain_and_names_the_ascii_form() {
	// A U-label in `domains` is refused. The error pins the A-label the
	// operator should write so they can fix the config without consulting
	// the IDNA standard.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["bücher.example"]

[[listeners]]
kind = "smtp"
"#,
	);
	let err = result.expect_err("u-label domain must be rejected");
	let message = format!("{err:?}");
	assert!(
		message.contains("xn--bcher-kva.example"),
		"expected the error to name the A-label form, got {message:?}"
	);
}

#[test]
fn rejects_a_confusable_domain_in_config() {
	// A Cyrillic look-alike of an ASCII name is refused with its own
	// wording so the operator understands why.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["раypal.com"]

[[listeners]]
kind = "smtp"
"#,
	);
	let err = result.expect_err("confusable domain must be rejected");
	let message = format!("{err:?}");
	assert!(
		message.contains("confusable"),
		"expected the error to call the domain confusable, got {message:?}"
	);
}
