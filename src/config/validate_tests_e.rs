//! Validation tests for the SRS / forwarding interaction. Split out of
//! `validate_tests.rs` to stay under the line limit, matching the precedent
//! set by the alert tests in `validate_tests_c.rs` and the tenant tests in
//! `validate_tests_d.rs`.
//!
//! The check has to keep the SPF policy and the SRS config in sync: the
//! published SPF record hardfails (`-all`) and that is only safe to
//! advertise when every forwarded message has its envelope sender rewritten
//! onto our domain (SRS) before the next hop evaluates SPF.

use super::tests::config_from;

#[test]
fn rejects_forward_without_srs_secret() {
	// The recommended SPF policy is `-all`; for that to stay safe to publish
	// (rather than silently dropping every forwarded message whose original
	// domain also hardfails), forwarding needs SRS to rewrite the envelope
	// sender onto our domain before the next hop.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
forward = ["alice@elsewhere.example"]
"#,
	);
	let message = result.expect_err("forward without srs_secret").to_string();
	// The message has to name the offender so the operator can find it,
	// the missing field so they know what to add, and the consequence
	// (`-all` SPF rejection) so they know why it matters.
	assert!(message.contains("alice"), "{message}");
	assert!(message.contains("forward"), "{message}");
	assert!(message.contains("srs_secret"), "{message}");
	assert!(message.contains("-all"), "{message}");
}

#[test]
fn accepts_forward_with_srs_secret() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]
srs_secret = "a shared srs secret"

[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
forward = ["alice@elsewhere.example"]
"#,
	);
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn accepts_accounts_without_forward_when_srs_secret_is_absent() {
	// The default account does not forward, so an absent srs_secret stays
	// valid — only forwarding triggers the requirement.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
"#,
	);
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn rejects_when_one_of_many_accounts_forwards_without_srs_secret() {
	// Bob is fine; Alice forwards. The whole config is rejected — there is no
	// per-account opt-out from the SPF invariant.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
forward = ["alice@elsewhere.example"]

[[accounts]]
name = "bob"
addresses = ["bob@example.org"]
"#,
	);
	let message = result.expect_err("alice forwards without srs").to_string();
	assert!(message.contains("alice"), "{message}");
	assert!(message.contains("srs_secret"), "{message}");
}
