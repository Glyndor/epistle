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
		"IPv4-mapped IPv6 carrying a private address must be rejected"
	);
}

#[test]
fn rejects_a_public_ipv6_that_carries_a_non_global_ipv4() {
	// Every form that carries an IPv4 payload must be read as that IPv4:
	// NAT64 (64:ff9b::/96), 6to4 (2002::/16), IPv4-compatible (::a.b.c.d) and
	// IPv4-mapped (::ffff:a.b.c.d). A v6 value must not be a way in for
	// loopback, RFC 1918 or the link-local address of the metadata service.
	for value in [
		"64:ff9b::7f00:1",
		"64:ff9b::a00:1",
		"64:ff9b::169.254.169.254",
		"2002:7f00:1::1",
		"2002:c000:201::1",
		"::127.0.0.1",
		"::ffff:192.168.1.10",
	] {
		let config = config_from(&format!(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
public_ipv6 = "{value}"
"#
		));
		let err = config.expect_err("an IPv6 carrying a non-global IPv4 must be rejected");
		let message = format!("{err:?}");
		assert!(
			message.contains("public_ipv6") && message.contains("carrying"),
			"expected the error to name the field and the payload it carries, got {message:?}"
		);
	}
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

#[test]
fn rejects_dkim_with_only_rsa_selector() {
	// Setting `rsa_selector` without `rsa_key_file` points a published
	// `_domainkey` TXT at a key we never load. The validator rejects the
	// half-configured state so the misconfiguration cannot ship.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"
rsa_selector = "rsa1"
"#,
	);
	let err = result.expect_err("half-configured RSA must be rejected");
	let message = format!("{err:?}");
	assert!(
		message.contains("rsa_selector and rsa_key_file must be set together"),
		"expected the rejection to name both fields, got {message:?}"
	);
}

#[test]
fn rejects_dkim_with_only_rsa_key_file() {
	// Symmetric to the previous test: a key file without a selector has
	// no TXT to point at, so the load must fail.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"
rsa_key_file = "/etc/mail/rsa.pem"
"#,
	);
	let err = result.expect_err("half-configured RSA must be rejected");
	let message = format!("{err:?}");
	assert!(
		message.contains("rsa_selector and rsa_key_file must be set together"),
		"expected the rejection to name both fields, got {message:?}"
	);
}

#[test]
fn accepts_dkim_with_both_rsa_fields_set() {
	// Both halves of the pair set: the validator must accept the config.
	// The keys do not need to exist on disk at validate time (loading is
	// the signer's job); the test only asserts the validator's gate.
	let config = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"
rsa_selector = "rsa1"
rsa_key_file = "/etc/mail/rsa.pem"
"#,
	)
	.expect("both RSA fields set must be accepted");
	let dkim = config.dkim.expect("dkim section present");
	assert_eq!(dkim.rsa_selector.as_deref(), Some("rsa1"));
	assert_eq!(
		dkim.rsa_key_file.as_ref().map(|p| p.to_str()),
		Some(Some("/etc/mail/rsa.pem"))
	);
}

#[test]
fn accepts_dkim_with_neither_rsa_field_set() {
	// Without RSA configured the validator must still accept the config:
	// the runtime emits a startup warning (a single-signature warning),
	// but a refusal here would refuse every installation that follows
	// the current documentation, breaking upgrades.
	let config = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"
"#,
	)
	.expect("missing RSA must be accepted (warning, not refusal)");
	assert!(config.dkim.is_some());
}

#[test]
fn accepts_a_per_domain_dkim_override_for_a_hosted_domain() {
	// A per-domain override for a domain in [domains] must pass. The
	// per-domain block is the same shape as [dkim], so the validator
	// must accept it just like the main block.
	let config = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org", "example.net"]

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"

[[dkim.domain]]
name = "example.org"
selector = "ed-2024a"
key_file = "/etc/mail/example-ed25519.pem"
rsa_selector = "rsa-2024a"
rsa_key_file = "/etc/mail/example-rsa.pem"
"#,
	)
	.expect("per-domain override for a hosted domain is accepted");
	let dkim = config.dkim.expect("[dkim] is set");
	assert_eq!(dkim.domain.len(), 1);
	assert_eq!(dkim.domain[0].name, "example.org");
}

#[test]
fn accepts_a_per_domain_dkim_override_for_an_alias_domain() {
	// A per-domain override for an alias domain is also accepted: the
	// server still signs mail whose `d=` is the alias, so the key must
	// be just as publishable as one tied to an apex domain.
	let config = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[domain_aliases]
"example.net" = "example.org"

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"

[[dkim.domain]]
name = "example.net"
selector = "ed-2024a"
key_file = "/etc/mail/example-ed25519.pem"
"#,
	)
	.expect("per-domain override for an alias domain is accepted");
	assert_eq!(config.dkim.expect("dkim").domain.len(), 1);
}

#[test]
fn rejects_a_per_domain_dkim_override_for_a_non_hosted_domain() {
	// The override names a domain the server does not host: the
	// published TXT would never match a domain any message can sign
	// with, so the config must be rejected at load.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"

[[dkim.domain]]
name = "other.example"
selector = "ed-2024a"
key_file = "/etc/mail/other-ed25519.pem"
"#,
	);
	let err = result.expect_err("non-hosted domain must be rejected");
	let message = format!("{err:?}");
	assert!(
		message.contains("[dkim.domain]") && message.contains("other.example"),
		"the rejection must name the override and the offending domain, got {message:?}"
	);
	assert!(
		message.contains("[domains]") || message.contains("[domain_aliases]"),
		"the rejection must point the operator at the two lists the override has to match, got {message:?}"
	);
}

#[test]
fn rejects_a_duplicate_per_domain_dkim_override() {
	// The same name twice in [[dkim.domain]] is an error: only one
	// selector can win, and a silent one-wins is exactly the kind of
	// misconfiguration that the validator should not let ship.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"

[[dkim.domain]]
name = "example.org"
selector = "ed-a"
key_file = "/etc/mail/a.pem"

[[dkim.domain]]
name = "example.org"
selector = "ed-b"
key_file = "/etc/mail/b.pem"
"#,
	);
	let err = result.expect_err("duplicate override must be rejected");
	let message = format!("{err:?}");
	assert!(
		message.contains("example.org") && message.contains("more than once"),
		"the rejection must name the duplicate and call it out, got {message:?}"
	);
}

#[test]
fn rejects_a_per_domain_override_with_only_rsa_selector() {
	// Same rule as the configured block: a selector without a key file
	// points a published TXT at a key we never load.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"

[[dkim.domain]]
name = "example.org"
selector = "ed-a"
key_file = "/etc/mail/a.pem"
rsa_selector = "rsa-a"
"#,
	);
	let err = result.expect_err("half-configured RSA on an override must be rejected");
	let message = format!("{err:?}");
	assert!(
		message.contains("rsa_selector and rsa_key_file must be set together"),
		"the rejection must match the configured-block wording, got {message:?}"
	);
}
