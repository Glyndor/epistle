//! Validation tests for the `[database]` section's `sslmode` enforcement.
//!
//! Split out of `validate_tests.rs`, matching the precedent set by the alerts
//! tests in `validate_tests_c.rs` and the tenants tests in `validate_tests_d.rs`.
//!
//! The PostgreSQL connection carries the reputation, the Bayes corpus and, with
//! `directory = true`, the mail accounts. libpq's default `sslmode` is
//! `prefer`, which attempts TLS and silently falls back to plaintext if the
//! server does not offer it — the operator never asked for plaintext and never
//! sees the fallback happen. These tests pin the matrix the validation accepts
//! and rejects, so a future loosening cannot sneak past unnoticed.

use super::tests::config_from;

/// Build a TOML document with a `[database]` block carrying the given URL and
/// optional `tls` override, plus the minimum host/data-dir scaffolding the
/// validator needs to reach the database check.
fn db(url: &str) -> String {
	format!(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[database]
url = "{url}"
"#
	)
}

fn db_with_tls(url: &str, tls: &str) -> String {
	format!(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[database]
url = "{url}"
tls = "{tls}"
"#
	)
}

#[test]
fn rejects_url_without_sslmode() {
	// libpq's default when `sslmode` is absent is `prefer`, which silently
	// falls back to plaintext. The validation must refuse the URL outright
	// rather than let a future server config surprise the operator.
	let result = config_from(&db("postgres://mail:secret@db.internal/mail"));
	let message = result.expect_err("no sslmode must be rejected").to_string();
	assert!(message.contains("sslmode"), "{message}");
	assert!(message.contains("require"), "{message}");
}

#[test]
fn rejects_url_with_sslmode_disable() {
	let result = config_from(&db(
		"postgres://mail:secret@db.internal/mail?sslmode=disable",
	));
	assert!(
		result.is_err(),
		"sslmode=disable must be rejected: {result:?}"
	);
}

#[test]
fn rejects_url_with_sslmode_allow() {
	// `allow` never even attempts TLS unless the server asks first; the
	// server never does for a vanilla Postgres, so this is effectively
	// plaintext. Rejected under the same umbrella as `disable`.
	let result = config_from(&db("postgres://mail:secret@db.internal/mail?sslmode=allow"));
	assert!(
		result.is_err(),
		"sslmode=allow must be rejected: {result:?}"
	);
}

#[test]
fn rejects_explicit_sslmode_prefer() {
	// `prefer` is the dangerous one: the operator picked it, so the URL
	// looks intentional, but it still silently falls back to plaintext.
	let result = config_from(&db(
		"postgres://mail:secret@db.internal/mail?sslmode=prefer",
	));
	assert!(
		result.is_err(),
		"sslmode=prefer must be rejected: {result:?}"
	);
}

#[test]
fn accepts_url_with_sslmode_require() {
	let result = config_from(&db(
		"postgres://mail:secret@db.internal/mail?sslmode=require",
	));
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn accepts_url_with_sslmode_verify_ca() {
	let result = config_from(&db(
		"postgres://mail:secret@db.internal/mail?sslmode=verify-ca",
	));
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn accepts_url_with_sslmode_verify_full() {
	let result = config_from(&db(
		"postgres://mail:secret@db.internal/mail?sslmode=verify-full",
	));
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn accepts_unix_domain_socket_url() {
	// Both spellings sqlx understands: percent-encoded in the host slot (so
	// only two slashes after the scheme: `postgres://%2F...` — the encoded
	// `/` IS the start of the host), and the `host=` query parameter (which
	// may carry three slashes because the authority is empty). No network on
	// the wire, so sslmode is moot.
	let result = config_from(&db("postgres://%2Fvar%2Frun%2Fpostgresql/mail"));
	assert!(result.is_ok(), "{:?}", result.err());

	let result = config_from(&db("postgres:///mail?host=/var/run/postgresql"));
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn accepts_unix_socket_even_with_sslmode_disable() {
	// The two exceptions (Unix socket, operator opt-in) stack: a socket URL
	// is accepted regardless of sslmode, so the operator does not have to set
	// `tls = "insecure"` just to silence the check for an internal socket.
	let result = config_from(&db(
		"postgres://%2Fvar%2Frun%2Fpostgresql/mail?sslmode=disable",
	));
	assert!(result.is_ok(), "{:?}", result.err());

	let result = config_from(&db(
		"postgres:///mail?host=/var/run/postgresql&sslmode=disable",
	));
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn insecure_opt_in_accepts_sslmode_disable() {
	// The operator has declared that the connection stays on a network they
	// trust. The validator must accept the URL as written, sslmode and all.
	let result = config_from(&db_with_tls(
		"postgres://mail:secret@db.internal/mail?sslmode=disable",
		"insecure",
	));
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn insecure_opt_in_accepts_url_without_sslmode() {
	// Same as above but for an operator who did not bother setting any
	// sslmode: the opt-in still accepts the URL.
	let result = config_from(&db_with_tls(
		"postgres://mail:secret@db.internal/mail",
		"insecure",
	));
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn insecure_opt_in_accepts_unix_socket_too() {
	// Both exemptions compose: a Unix-socket URL plus `tls = "insecure"`
	// also loads.
	let result = config_from(&db_with_tls(
		"postgres://%2Fvar%2Frun%2Fpostgresql/mail",
		"insecure",
	));
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn database_section_absent_means_no_check() {
	// No `[database]` block at all: the validator must not raise a
	// database-shape error, and must not synthesise a URL to test.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
	);
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn malformed_url_is_rejected_at_validate_not_parse() {
	// The TOML parser is happy with any string; the URL parser is not. The
	// failure must still be a `ConfigError::Invalid`, not a panic, and the
	// message must identify the field that was bad.
	let result = config_from(&db("not a postgres url"));
	let message = result
		.expect_err("garbage url must be rejected")
		.to_string();
	assert!(message.contains("[database]"), "{message}");
	assert!(message.contains("url"), "{message}");
}
