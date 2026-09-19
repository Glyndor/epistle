//! Validation tests for SubjectPass: enabling the signed-retry-token
//! opt-in without a `[database]` section is a logical impossibility
//! (the uncertain band needs the Bayesian score to test against), so the
//! validator refuses the configuration at load time.
//!
//! Split out of `validate_tests.rs` to stay under the line limit, matching
//! the precedent set by the alert tests in `validate_tests_c.rs`, the
//! tenant tests in `validate_tests_d.rs`, the SRS tests in
//! `validate_tests_e.rs`, the database TLS tests in `validate_tests_f.rs`,
//! the postmaster tests in `validate_tests_g.rs`, and the IDNA tests in
//! `validate_tests_h.rs`.

use super::tests::config_from;

#[test]
fn subjectpass_requires_a_database() {
	// `subjectpass.enabled = true` without a `[database]` section is
	// refused at validate time with a message that names the field and
	// points at the fix (add `[database]` or set `enabled = false`).
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

subjectpass = { enabled = true }

[[listeners]]
kind = "smtp"
"#,
	);
	let err = result.expect_err("subjectpass without a database must be rejected");
	let message = format!("{err:?}");
	assert!(
		message.contains("subjectpass"),
		"expected the error to name the field, got {message:?}"
	);
	assert!(
		message.contains("database"),
		"expected the error to mention the missing database, got {message:?}"
	);
}

#[test]
fn subjectpass_with_a_database_passes_validation() {
	// The same opt-in with a `[database]` section is accepted: the
	// uncertain band has a Bayesian score to test against, so the
	// validator does not intervene.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

subjectpass = { enabled = true }

[database]
url = "postgres://user:pass@db/mail?sslmode=verify-full"

[[listeners]]
kind = "smtp"
"#,
	);
	assert!(
		result.is_ok(),
		"subjectpass with a database must validate, got {result:?}"
	);
}

#[test]
fn subjectpass_off_does_not_require_a_database() {
	// The default `subjectpass.enabled = false` is the historical
	// behaviour (band acts only with an LLM hook); without a database,
	// the validator accepts the configuration.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[listeners]]
kind = "smtp"
"#,
	);
	assert!(
		result.is_ok(),
		"subjectpass off must not require a database, got {result:?}"
	);
}
