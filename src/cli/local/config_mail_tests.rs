//! Tests for mail configuration diagnostics and preserving files on load failures.

use super::test_support::{fresh_dir, load_for_test};
use super::{DEFAULT_PORT_BASE, prepare};

/// Pin: a `mail.toml` that exists but cannot be read is propagated as an
/// error and the credential files stay byte-for-byte intact. The runtime
/// distinguishes four states when it looks at the path: missing,
/// read-failed, parse-failed, loaded. A directory at the path is the
/// only read failure a non-root uid can provoke, and root still cannot
/// read it either: `read_to_string` on a directory fails with `EISDIR`
/// for every uid.
#[cfg(unix)]
#[test]
fn unreadable_mail_toml_propagates_and_does_not_wipe_accounts() {
	let dir = fresh_dir("unreadable-mail");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let accounts_path = dir.path().join("data").join("accounts.toml");
	let accounts_before = std::fs::read(&accounts_path).expect("read accounts.toml");

	// Replace `mail.toml` with a directory. `read_to_string` on a
	// directory fails with `EISDIR` for every uid, so the test is
	// root-safe: no chmod dance that a setuid build would bypass.
	std::fs::remove_file(&mail_toml).expect("remove mail.toml");
	std::fs::create_dir(&mail_toml).expect("create dir at mail.toml");

	let result = prepare(dir.path(), DEFAULT_PORT_BASE);
	let err = match result {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for a directory at mail.toml, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains("mail.toml"),
		"error must name mail.toml, got: {rendered}"
	);

	let accounts_after = std::fs::read(&accounts_path).expect("read accounts.toml after");
	assert!(
		accounts_before == accounts_after,
		"accounts.toml must be byte-for-byte identical when prepare fails"
	);
}

/// Pin: a `mail.toml` whose mode is `0644` propagates as an error and the
/// credential files stay byte-for-byte intact. `Config::load`'s
/// `check_permissions` rejects any file with group/world bits set as
/// `InsecurePermissions`; that variant is an operator-fixable state on
/// an otherwise valid file (the same shape as `Read`), so `prepare`
/// returns the error and does not regenerate the credential pair.
/// Regenerating would silently replace working credentials behind the
/// operator's back, which is the regression this test pins. The mode
/// check is on `st_mode`, not on who runs the test, so the assertion
/// holds as root.
#[cfg(unix)]
#[test]
fn world_readable_mail_toml_propagates_and_does_not_wipe_credentials() {
	use std::os::unix::fs::PermissionsExt;

	let dir = fresh_dir("world-readable-mail");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let accounts_path = dir.path().join("data").join("accounts.toml");
	let mail_before = std::fs::read(&mail_toml).expect("read mail.toml before");
	let accounts_before = std::fs::read(&accounts_path).expect("read accounts.toml before");

	// chmod 0644: world-readable. Config::load rejects this as
	// InsecurePermissions because the world-readable bit is set.
	std::fs::set_permissions(&mail_toml, std::fs::Permissions::from_mode(0o644))
		.expect("chmod 0644");

	let result = prepare(dir.path(), DEFAULT_PORT_BASE);
	let err = match result {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for a world-readable mail.toml, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains("mail.toml"),
		"error must name mail.toml, got: {rendered}"
	);

	let mail_after = std::fs::read(&mail_toml).expect("read mail.toml after");
	assert!(
		mail_before == mail_after,
		"mail.toml must be byte-for-byte identical when prepare fails"
	);
	let accounts_after = std::fs::read(&accounts_path).expect("read accounts.toml after");
	assert!(
		accounts_before == accounts_after,
		"accounts.toml must be byte-for-byte identical when prepare fails"
	);
}

/// Pin: a `mail.toml` whose `[api] token_hash` is `${UNSET_VAR}` returns
/// `Err` from `prepare`, the error names `mail.toml`, and both files
/// are byte-for-byte intact. The rule is: the file is on disk, the
/// operator can fix it, do not regenerate.
#[test]
fn unset_env_var_in_token_hash_returns_unusable_error() {
	let dir = fresh_dir("unset-env");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let accounts_path = dir.path().join("data").join("accounts.toml");

	// Mint a surely-unset variable name at run time so the test does
	// not depend on the operator's environment.
	let var_name = format!(
		"EPISTLE_LOCAL_TEST_UNSET_{}",
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.expect("clock")
			.as_nanos()
	);
	let original = std::fs::read_to_string(&mail_toml).expect("re-read mail.toml");
	let patched = original.replace("[api]", &format!("[api]\nunset_var = \"${{{var_name}}}\""));
	std::fs::write(&mail_toml, patched).expect("patch mail.toml");

	// Capture "before" snapshots AFTER the patch but BEFORE `prepare`
	// so the byte-for-byte invariant is checked against what the test
	// itself left on disk, not against the file the harness wrote.
	let mail_before = std::fs::read(&mail_toml).expect("read mail.toml before prepare");
	let accounts_before = std::fs::read(&accounts_path).expect("read accounts.toml before prepare");

	let err = match prepare(dir.path(), DEFAULT_PORT_BASE) {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for an unset env var, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains("mail.toml"),
		"error must name mail.toml, got: {rendered}"
	);
	assert!(
		rendered.contains(&var_name),
		"error must name the unset variable, got: {rendered}"
	);
	assert!(
		rendered.contains("Fix it"),
		"error must carry the standard remedy, got: {rendered}"
	);

	let mail_after = std::fs::read(&mail_toml).expect("read mail.toml after");
	let accounts_after = std::fs::read(&accounts_path).expect("read accounts.toml after");
	assert!(
		mail_before == mail_after,
		"mail.toml must be byte-for-byte identical when prepare fails"
	);
	assert!(
		accounts_before == accounts_after,
		"accounts.toml must be byte-for-byte identical when prepare fails"
	);
}

/// Pin: a `mail.toml` that is not valid TOML returns `Err` from
/// `prepare`, the error names `mail.toml`, the standard remedy text is
/// present, and both files are byte-for-byte intact.
#[test]
fn invalid_toml_mail_toml_returns_unusable_error() {
	let dir = fresh_dir("invalid-toml-mail");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let accounts_path = dir.path().join("data").join("accounts.toml");

	std::fs::write(
		&mail_toml,
		b"hostname = \"mail.local.test\"\nthis is not = ][ valid\n",
	)
	.expect("write invalid TOML");

	let mail_before = std::fs::read(&mail_toml).expect("read mail.toml before prepare");
	let accounts_before = std::fs::read(&accounts_path).expect("read accounts.toml before prepare");

	let err = match prepare(dir.path(), DEFAULT_PORT_BASE) {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for an invalid mail.toml, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains("mail.toml"),
		"error must name mail.toml, got: {rendered}"
	);
	assert!(
		rendered.contains("Fix it"),
		"error must carry the standard remedy, got: {rendered}"
	);

	let mail_after = std::fs::read(&mail_toml).expect("read mail.toml after");
	let accounts_after = std::fs::read(&accounts_path).expect("read accounts.toml after");
	assert!(
		mail_before == mail_after,
		"mail.toml must be byte-for-byte identical when prepare fails"
	);
	assert!(
		accounts_before == accounts_after,
		"accounts.toml must be byte-for-byte identical when prepare fails"
	);
}

/// Pin: a `mail.toml` whose `data_dir` is a relative path is treated
/// as an unusable file: the loader names `data_dir` in the diagnostic
/// (the field the operator has to fix), not a generic
/// "load_local_config called for a non-Loaded outcome" placeholder that
/// hid the underlying `ConfigError::Invalid` message. Built `prepare`
/// always emits an absolute `data_dir`, so the test calls the loader
/// directly with a hand-crafted `mail.toml` carrying `data_dir = "data"`.
#[test]
fn relative_data_dir_loader_returns_diagnostic_that_names_data_dir() {
	let dir = fresh_dir("relative-data-dir");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let original = std::fs::read_to_string(&mail_toml).expect("read mail.toml");
	let patched = original.replace(
		&format!("data_dir = \"{}\"", dir.path().join("data").display()),
		"data_dir = \"data\"",
	);
	std::fs::write(&mail_toml, patched).expect("write relative data_dir");

	// `load_for_test` returns the `Config` whose `Debug` carries the
	// `api.token_hash`. `expect_err` on the unexpected success would
	// Debug-print that struct into the CI log. Use a match that names
	// the outcome without ever carrying the value.
	let err = match load_for_test(&mail_toml) {
		Ok(_) => panic!("relative data_dir is an error, got Ok"),
		Err(error) => error,
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains("mail.toml"),
		"error must name mail.toml, got: {rendered}"
	);
	assert!(
		rendered.contains("data_dir"),
		"error must name data_dir, got: {rendered}"
	);
	assert!(
		rendered.contains("Fix it"),
		"error must carry the standard remedy, got: {rendered}"
	);
}

/// Pin: when `mail.toml` is unusable, `prepare` returns `Err` and
/// neither the certificate nor the DKIM key is regenerated. The
/// evaluation order is: `ensure_dir` -> `write_marker` -> fault point
/// -> evaluate credential pair outcome -> (only on `Missing` or
/// `Loaded`) create the data directory, regenerate cert/key if
/// needed, regenerate dkim if needed, regenerate the credential pair
/// if needed. A `mail.toml` that exists but cannot be used is an
/// operator-fixable error; an error run that regenerated the cert /
/// key / dkim in the meantime would leave the directory in a state a
/// later fix-up run could not recognise (a freshly-regenerated
/// `cert.pem` next to a broken `mail.toml` and a missing `key.pem`).
///
/// The setup exploits the cert/key pairing: a first `prepare` lays
/// out a valid directory, the test corrupts `mail.toml` (invalid
/// TOML) and deletes `key.pem`. If the cert step runs before the
/// credential-pair check, the cert step regenerates the pair (one
/// piece missing -> both regenerated) and `key.pem` reappears. The
/// new ordering returns `Err` first, before the cert step runs.
/// `cert.pem` is byte-identical to the first run because no
/// regeneration happened; `key.pem` is still absent because no
/// regeneration happened; `mail.toml` is still the broken bytes the
/// test wrote, not the original.
#[cfg(unix)]
#[test]
fn invalid_mail_toml_does_not_regenerate_certificate_or_dkim() {
	let dir = fresh_dir("invalid-mail-no-cert-regen");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let cert_path = dir.path().join("cert.pem");
	let key_path = dir.path().join("key.pem");
	let dkim_path = dir.path().join("dkim.pem");

	let cert_before = std::fs::read(&cert_path).expect("read cert.pem before");
	let dkim_before = std::fs::read(&dkim_path).expect("read dkim.pem before");

	// Corrupt `mail.toml` with non-empty bytes that are not valid
	// TOML. `Config::load` fails with a parse error and `prepare`
	// must propagate the `Unusable` outcome without touching the
	// cert / key / dkim files.
	std::fs::write(&mail_toml, b"this is not TOML = ][ at all")
		.expect("write invalid TOML to mail.toml");

	// Delete `key.pem` so the cert step would regenerate the pair
	// if the credential-pair check were reordered after it.
	std::fs::remove_file(&key_path).expect("remove key.pem");

	let err = match prepare(dir.path(), DEFAULT_PORT_BASE) {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for an invalid mail.toml, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains("mail.toml"),
		"error must name mail.toml, got: {rendered}"
	);

	// `key.pem` must still be absent: the cert step never ran, so
	// it was not regenerated. The first prepare left `key.pem` on
	// disk; the test removed it; nothing in the failed `prepare`
	// put it back.
	assert!(
		!key_path.exists(),
		"key.pem must STILL be absent: the credential-pair check ran before the cert step, so the cert step did not run, so the pair was not regenerated"
	);

	// `cert.pem` must be byte-identical to the file the first
	// `prepare` wrote: nothing regenerated it. The PEM cert
	// contains the public key, so an `assert_eq!` on the byte
	// arrays would Debug-print the full PEM on mismatch and dump
	// the key material into the CI log. A boolean check with a
	// length-only message preserves the diagnosis without ever
	// carrying the bytes.
	let cert_after = std::fs::read(&cert_path).expect("read cert.pem after");
	assert!(
		cert_before == cert_after,
		"cert.pem must be byte-identical to the first run (lengths {} and {}); \
		 the credential-pair check ran before the cert step, so the cert step did not run",
		cert_before.len(),
		cert_after.len(),
	);

	// `dkim.pem` must be byte-identical for the same reason.
	// `dkim.pem` carries the DKIM signing private key, so an
	// `assert_eq!` on the byte arrays would Debug-print the full
	// PEM on mismatch and dump the key into the CI log.
	let dkim_after = std::fs::read(&dkim_path).expect("read dkim.pem after");
	assert!(
		dkim_before == dkim_after,
		"dkim.pem must be byte-identical to the first run: the credential-pair check ran before the dkim step, so the dkim step did not run"
	);

	// The data directory must still be the one the first `prepare`
	// created (its mtime is unchanged), and the broken `mail.toml`
	// must still be the bytes the test wrote.
	let mail_after = std::fs::read(&mail_toml).expect("read mail.toml after");
	assert_eq!(
		mail_after, b"this is not TOML = ][ at all",
		"mail.toml must be the broken bytes the test wrote (the failed prepare must not have rewritten it)"
	);
}
