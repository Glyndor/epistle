//! Validation tests for the `[database]` section's `password_file` companion:
//! the file-or-URL refusal, the existence check, the regular-file check, and
//! the permission-bit check that mirrors what `Config::load` applies to the
//! config file itself. Split out of `validate_tests_f.rs` to keep that file
//! scoped to the `sslmode` enforcement and leave room for both to grow.
//!
//! Mode and existence are checked on `st_mode` and `metadata` (the kernel is
//! the oracle), so the assertions hold when the suite runs as root. The
//! `redaction_tests.rs` precedent makes the same point about file-mode
//! checks at the file-system layer rather than at the uid layer.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use super::tests::config_from;

/// Build a TOML `[database]` block that omits the password (the form
/// `password_file` is designed to complete). Pass the URL as a percent-encoded
/// Unix-socket path so the TLS check cannot flag the URL itself: the
/// `password_file` cases below are about the file, not the URL.
fn db_with_password_file(url: &str, password_file: &str) -> String {
	format!(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[database]
url = "{url}"
password_file = "{password_file}"
"#
	)
}

/// Mint a unique temp file the test owns, write the given bytes, and chmod it
/// `0600` (owner read/write only) so the default perms are not the test
/// failure mode. Returns the path so the caller can `chmod` or otherwise
/// tamper with it.
fn temp_secret(content: &[u8]) -> PathBuf {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("epistle_test_secret");
	std::fs::write(&path, content).expect("write secret");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
	// Keep the dir alive for the lifetime of the path by leaking it: the
	// test process is short-lived, and leaking here is simpler than
	// threading a guard through every signature below.
	std::mem::forget(dir);
	path
}

/// Same as [`temp_secret`] but with an explicitly chosen mode so the test can
/// exercise the group/world rejection paths without playing uid tricks.
fn temp_secret_with_mode(content: &[u8], mode: u32) -> PathBuf {
	let path = temp_secret(content);
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
	path
}

/// URL + `password_file` together: refused. The refusal names both fields so
/// the operator does not have to guess which configuration is wrong. The
/// test uses the userinfo-password form; the query-parameter form is covered
/// separately so a future regression in either detector is caught.
#[test]
fn rejects_url_password_and_password_file_together_userinfo() {
	let secret = temp_secret(b"some secret bytes\n");
	let result = config_from(&db_with_password_file(
		"postgres://epistle:s3cret@db.internal/mail",
		secret.to_str().unwrap(),
	));
	let message = result
		.expect_err("both sources must be rejected")
		.to_string();
	assert!(message.contains("url"), "{message}");
	assert!(message.contains("password_file"), "{message}");
}

/// Same as the userinfo form, but the URL puts the password in the query
/// string (the other form sqlx accepts). The refusal must still fire; the
/// two-source ambiguity is independent of how the URL happens to spell it.
#[test]
fn rejects_url_password_and_password_file_together_query() {
	let secret = temp_secret(b"some secret bytes\n");
	let result = config_from(&db_with_password_file(
		"postgres://epistle@db.internal/mail?password=s3cret",
		secret.to_str().unwrap(),
	));
	let message = result
		.expect_err("both sources must be rejected")
		.to_string();
	assert!(message.contains("url"), "{message}");
	assert!(message.contains("password_file"), "{message}");
}

/// `password_file` set with no password in the URL: accepted. The URL uses a
/// percent-encoded Unix-domain socket so the TLS check has nothing to say
/// and the test exercises the new code path (and only the new code path)
/// end-to-end.
#[test]
fn accepts_password_file_with_clean_url() {
	let secret = temp_secret(b"some secret bytes\n");
	let result = config_from(&db_with_password_file(
		"postgres://epistle@%2Frun%2Fpostgresql/epistle",
		secret.to_str().unwrap(),
	));
	assert!(result.is_ok(), "{:?}", result.err());
}

/// A path that does not exist on disk is refused with the path in the
/// message. The variant is `ConfigError::Read` (the same variant a missing
/// config file produces) so the operator sees a consistent refusal shape for
/// both "the file the operator pointed at is not there" cases.
#[cfg(unix)]
#[test]
fn rejects_missing_password_file() {
	let missing = "/nonexistent/epistle_test_secret";
	let result = config_from(&db_with_password_file(
		"postgres://epistle@%2Frun%2Fpostgresql/epistle",
		missing,
	));
	let error = result.expect_err("missing password_file must be rejected");
	let message = error.to_string();
	assert!(message.contains(missing), "{message}");
}

/// The path is a directory, not a regular file. `read_to_string` at pool
/// construction would succeed on a directory (POSIX allows it as a zero-byte
/// read), but the operator's intent is clearly wrong, so the validation
/// surfaces it as a refusal rather than letting the empty password trip the
/// pool-builder error.
#[cfg(unix)]
#[test]
fn rejects_password_file_that_is_a_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let dir_path = dir.path().to_path_buf();
	let result = config_from(&db_with_password_file(
		"postgres://epistle@%2Frun%2Fpostgresql/epistle",
		dir_path.to_str().unwrap(),
	));
	let message = result
		.expect_err("directory at password_file must be rejected")
		.to_string();
	assert!(message.contains("password_file"), "{message}");
	assert!(message.contains("regular file"), "{message}");
	// Leak the dir so the cleanup that runs at the end of the test does not
	// race the validation that just read its metadata.
	std::mem::forget(dir);
}

/// Mode `0644` (group-readable): refused by the same rule `Config::load`
/// applies to the config file itself. The variant is `InsecurePermissions`
/// and the message names the path; whether the bit pattern matches a
/// config-file refusal or a `password_file` refusal differs only in the
/// `kind` field the variant carries, which both call sites exercise.
#[cfg(unix)]
#[test]
fn rejects_password_file_with_group_readable_mode() {
	let secret = temp_secret_with_mode(b"some secret bytes\n", 0o644);
	let result = config_from(&db_with_password_file(
		"postgres://epistle@%2Frun%2Fpostgresql/epistle",
		secret.to_str().unwrap(),
	));
	let error = result.expect_err("group-readable password_file must be rejected");
	let message = error.to_string();
	assert!(message.contains(secret.to_str().unwrap()), "{message}");
}

/// Mode `0666` (group- and world-writable): refused, even though the operator
/// may think "world-writable but only I can read it is fine". The
/// permission rule is the bit rule: any group/world bit is refused, full
/// stop.
#[cfg(unix)]
#[test]
fn rejects_password_file_with_world_writable_mode() {
	let secret = temp_secret_with_mode(b"some secret bytes\n", 0o666);
	let result = config_from(&db_with_password_file(
		"postgres://epistle@%2Frun%2Fpostgresql/epistle",
		secret.to_str().unwrap(),
	));
	assert!(
		matches!(result, Err(super::ConfigError::InsecurePermissions { .. })),
		"world-writable password_file must be rejected as InsecurePermissions, got {result:?}"
	);
}

/// Mode `0400` (the recommended podup deployment: a read-only secret the
/// container uid owns and nobody else can read) is accepted. The
/// group/world check fires on bits `0o077`, so `0400` and `0600` both pass.
#[cfg(unix)]
#[test]
fn accepts_password_file_with_mode_0400() {
	let secret = temp_secret_with_mode(b"some secret bytes\n", 0o400);
	let result = config_from(&db_with_password_file(
		"postgres://epistle@%2Frun%2Fpostgresql/epistle",
		secret.to_str().unwrap(),
	));
	assert!(result.is_ok(), "{:?}", result.err());
}

/// The refusal names both fields, so an operator who set the password in
/// the URL and in `password_file` sees which two settings collide. Without
/// the refusal such a config would load with the password in two places.
#[test]
fn both_sources_refusal_message_names_both_fields() {
	let secret = temp_secret(b"some secret bytes\n");
	let result = config_from(&db_with_password_file(
		"postgres://epistle:s3cret@db.internal/mail",
		secret.to_str().unwrap(),
	));
	let message = result
		.expect_err("both sources must be rejected")
		.to_string();
	assert!(
		message.contains("url") && message.contains("password_file"),
		"refusal must name both fields; got {message:?}"
	);
}

/// A file that contains only a single line ending is rejected by
/// validation as empty. The validator must take the same read + strip +
/// empty-check path the pool constructor does, or this case would slip
/// past validation and surface as a misleading authentication failure at
/// connect (the server reports `password authentication failed for user
/// "..."` with no hint that the secret file is empty, and the operator
/// wastes an afternoon chasing the wrong knob). The refusal names the
/// path and never the file's contents (the bytes are a bare `\n` and
/// the message says "is empty after stripping the trailing newline",
/// not the byte itself).
#[test]
fn rejects_password_file_that_is_only_a_newline() {
	let secret = temp_secret(b"\n");
	let result = config_from(&db_with_password_file(
		"postgres://epistle@%2Frun%2Fpostgresql/epistle",
		secret.to_str().unwrap(),
	));
	let error = result.expect_err("\\n alone must be rejected");
	let message = error.to_string();
	assert!(
		message.contains(secret.to_str().unwrap()),
		"refusal must name the path; got {message:?}"
	);
	assert!(
		message.contains("empty"),
		"refusal must say the file is empty; got {message:?}"
	);
}

/// A file that contains non-UTF-8 bytes is rejected by validation.
/// `read_to_string` on the pool constructor side would fail on the same
/// bytes with an `InvalidData` I/O error; the validator must take the
/// same path or the operator would see a misleading authentication
/// failure at connect with no hint that the secret file's encoding is
/// the problem. The refusal names the path and never the file's
/// contents (the raw bytes are not valid UTF-8 and cannot appear in a
/// `String`, so the operator-facing message is structurally free of
/// the secret).
#[cfg(unix)]
#[test]
fn rejects_password_file_with_invalid_utf8() {
	let secret = temp_secret(&[0xFF, 0xFE, 0xFD]);
	let result = config_from(&db_with_password_file(
		"postgres://epistle@%2Frun%2Fpostgresql/epistle",
		secret.to_str().unwrap(),
	));
	let error = result.expect_err("invalid utf-8 must be rejected");
	let message = error.to_string();
	assert!(
		message.contains(secret.to_str().unwrap()),
		"refusal must name the path; got {message:?}"
	);
}
