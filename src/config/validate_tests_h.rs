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

#[test]
fn rejects_a_private_or_loopback_public_address() {
	// A private (RFC 1918) IPv4 is refused with the range named so the
	// operator can fix it without guessing why.
	let private_v4 = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
public_ipv4 = "10.0.0.5"
"#,
	);
	let err = private_v4.expect_err("RFC 1918 IPv4 must be rejected");
	let message = format!("{err:?}");
	assert!(
		message.contains("public_ipv4") && message.contains("private"),
		"expected the error to name the field and the range, got {message:?}"
	);

	// A loopback IPv4 is refused.
	let loopback_v4 = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
public_ipv4 = "127.0.0.1"
"#,
	);
	let err = loopback_v4.expect_err("loopback IPv4 must be rejected");
	assert!(
		format!("{err:?}").contains("loopback"),
		"expected the error to call the address loopback, got {err:?}"
	);

	// A ULA IPv6 is refused with its range named.
	let ula_v6 = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
public_ipv6 = "fd00::1"
"#,
	);
	let err = ula_v6.expect_err("ULA IPv6 must be rejected");
	assert!(
		format!("{err:?}").contains("public_ipv6") && format!("{err:?}").contains("unique-local"),
		"expected the v6 error to name the field and the ULA range, got {err:?}"
	);

	// An IPv4-mapped IPv6 carrying a private IPv4 is refused: a v6
	// value must not be a back door for an RFC 1918 payload.
	let mapped = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
public_ipv6 = "::ffff:10.0.0.1"
"#,
	);
	assert!(
		mapped.is_err(),
		"IPv4-mapped IPv6 carrying a private address must be rejected, got {mapped:?}"
	);
}

#[test]
fn accepts_a_global_public_address() {
	let config = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
public_ipv4 = "8.8.8.8"
public_ipv6 = "2606:4700:4700::1111"
"#,
	)
	.expect("global addresses must be accepted");
	assert_eq!(
		config.public_ipv4.map(|ip| ip.to_string()),
		Some("8.8.8.8".into())
	);
	assert_eq!(
		config.public_ipv6.map(|ip| ip.to_string()),
		Some("2606:4700:4700::1111".into())
	);
}
