//! Tests for interrupted initialization and marker ordering.

use super::test_support::{fresh_dir, local_error_name};
use super::{DEFAULT_PORT_BASE, LocalError, layout, prepare};

/// Pin: a directory that holds the marker, certificate, key, DKIM key
/// and `mail.toml`, but no `accounts.toml`, is still treated as a partial
/// state and `prepare` writes the missing file and mints a password.
/// Leaving such a partial directory looking initialised while the runtime
/// had no account to authenticate with is exactly what this guard
/// exists to prevent.
#[test]
fn partial_init_after_mail_toml_completes_accounts_toml() {
	let dir = fresh_dir("partial-after-mail-toml");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	// Drop only `accounts.toml`. The marker, mail.toml and the rest of
	// the artifacts stay: the fixture is a mid-`prepare` interruption,
	// captured at the account-write boundary.
	let marker = dir.path().join(".epistle-local");
	let accounts_path = dir.path().join("data").join("accounts.toml");
	std::fs::remove_file(&accounts_path).expect("remove accounts.toml");

	let second = prepare(dir.path(), DEFAULT_PORT_BASE).expect("retry completes");
	assert!(
		second.password.is_some(),
		"missing accounts.toml forces regeneration of the credential pair, so a password is minted"
	);
	assert!(
		accounts_path.exists(),
		"retry must write accounts.toml so the runtime can authenticate"
	);
	assert!(
		marker.exists(),
		"retry must re-mark the directory once it is complete"
	);
}

/// Pin: a directory where `cert.pem` already exists from a partial write
/// is completed by `prepare` without `AlreadyExists`. An unconditional
/// exclusive `write_with_mode(cert.pem, ...)` would fail with
/// `AlreadyExists` on the existing file and leave the operator with no
/// documented recovery. Per-artifact skip-if-exists is the contract.
#[test]
fn partial_init_after_cert_does_not_collide_with_existing_cert() {
	let dir = fresh_dir("partial-after-cert");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	// Drop everything except `cert.pem`. The marker stays (the
	// directory is "ours"): the retry must rebuild the missing files
	// without colliding with the cert that already survived the first
	// crash.
	std::fs::remove_file(dir.path().join("key.pem")).expect("remove key");
	std::fs::remove_file(dir.path().join("dkim.pem")).expect("remove dkim");
	std::fs::remove_file(dir.path().join("mail.toml")).expect("remove mail.toml");
	std::fs::remove_file(dir.path().join("data").join("accounts.toml"))
		.expect("remove accounts.toml");

	let _second = prepare(dir.path(), DEFAULT_PORT_BASE).expect("retry completes after cert");
	assert!(
		dir.path().join("cert.pem").exists(),
		"the existing cert must survive a retry"
	);
	assert!(
		dir.path().join("key.pem").exists(),
		"the missing key must be regenerated when cert survived"
	);
	assert!(
		dir.path().join("mail.toml").exists(),
		"mail.toml must be written to bring the directory back to a usable state"
	);
}

/// Pin: an interrupted first run that left the marker, certificate and
/// key on disk is recoverable: a second `prepare` accepts the partial
/// directory, rebuilds every missing artifact (DKIM, `mail.toml`,
/// `accounts.toml`), and returns `Ok`. This is the recovery path the
/// `prepare` function exists for: a partial directory that still has
/// the trust anchor and one or more artifacts left from a previous run.
/// The test calls the same helpers `prepare` calls (in the same order,
/// up to and including the certificate step), then runs the full
/// `prepare` and asserts every artifact is on disk afterwards.
#[test]
fn partial_init_with_marker_written_first_recovers_from_interruption_after_cert() {
	let dir = fresh_dir("partial-marker-first");
	let cert_path = dir.path().join("cert.pem");
	let key_path = dir.path().join("key.pem");
	let marker_path = dir.path().join(".epistle-local");

	// Step into `prepare` and stop after the certificate has been
	// generated but before DKIM, mail.toml and accounts.toml have been
	// written.
	layout::ensure_dir(dir.path()).expect("ensure_dir creates the directory");
	layout::write_marker(&marker_path).expect("write marker");
	layout::generate_certificate(&cert_path, &key_path).expect("write certificate");

	assert!(
		marker_path.exists(),
		"simulated interruption must have left the marker on disk"
	);
	assert!(
		cert_path.exists() && key_path.exists(),
		"simulated interruption must have left the certificate pair on disk"
	);
	assert!(
		!dir.path().join("mail.toml").exists(),
		"the simulated interruption must happen BEFORE mail.toml is written"
	);
	assert!(
		!dir.path().join("data").join("accounts.toml").exists(),
		"the simulated interruption must happen BEFORE accounts.toml is written"
	);

	// The second `prepare` must recover the partial directory. The
	// marker is present, so `ensure_dir` accepts; the per-artifact scan
	// rebuilds everything that is missing.
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("recovery completes");

	for name in [
		".epistle-local",
		"cert.pem",
		"key.pem",
		"dkim.pem",
		"mail.toml",
	] {
		assert!(
			dir.path().join(name).exists(),
			"recovery must leave {name} on disk"
		);
	}
	assert!(
		dir.path().join("data").join("accounts.toml").exists(),
		"recovery must leave accounts.toml on disk"
	);
}

/// Pin: the same interruption but with the marker step skipped (the
/// marker is written last) leaves a directory the next `prepare`
/// REFUSES with `NotEmpty`. This is the failure mode the marker-first
/// ordering exists to remove: a partial directory that `ensure_dir`
/// cannot tell apart from an unrelated one.
#[test]
fn partial_init_with_marker_written_last_after_cert_is_refused() {
	let dir = fresh_dir("partial-marker-last");
	let cert_path = dir.path().join("cert.pem");
	let key_path = dir.path().join("key.pem");

	// Same steps as the recovery test, minus the marker step. The
	// directory holds the certificate pair but no marker, which looks
	// identical to "this directory was not created by `epistle local`".
	layout::ensure_dir(dir.path()).expect("ensure_dir creates the directory");
	layout::generate_certificate(&cert_path, &key_path).expect("write certificate");

	let second = prepare(dir.path(), DEFAULT_PORT_BASE);
	match second {
		Err(LocalError::NotEmpty(path)) => {
			assert_eq!(
				path,
				dir.path(),
				"the refusal must name the directory itself"
			);
		}
		Err(other) => {
			panic!(
				"partial state without marker must be refused with NotEmpty, got {}",
				local_error_name(&other)
			)
		}
		Ok(_) => panic!("partial state without marker must be refused, prepare returned Ok"),
	}

	// The certificate survived the refusal: nothing was written or
	// removed on the rejection path.
	assert!(
		cert_path.exists(),
		"refusal must leave the existing files alone"
	);
}

/// Pin: a `prepare` whose first step after the marker fails (driven
/// by the test fault point) writes the marker BEFORE the failure is
/// recorded, so the directory is left in a state a later `prepare`
/// will accept. The marker is the trust anchor and is the first thing
/// `prepare` writes; a failure on any step must NOT roll it back,
/// because a later run reads the marker to recognise the directory
/// as ours.
///
/// The fault is injected through the test-only
/// `FaultAfterMarkerGuard`, which arms a flag the `prepare` function
/// consults immediately after the marker step (and before the data
/// directory is created). The guard clears the flag in `Drop`, so a
/// panicking assertion in this test cannot leak the flag into the
/// next test on the same thread. `ensure_dir` refuses a non-empty
/// unmarked directory, so an on-disk obstacle cannot be planted in a
/// fresh directory without pre-writing the marker, which is exactly
/// the post-condition the test is asserting, not a precondition the
/// test gets to inject for free. With the fault armed, `prepare`
/// errors at the marker-following step; the marker is on disk, no
/// data directory exists, and no artifact is.
///
/// After dropping the guard, a second `prepare` returns `Ok` with the
/// full layout: the marker was already on disk (so `ensure_dir` accepts
/// the directory), `data/` is missing (so the data directory is
/// created), `cert.pem` / `key.pem` are missing (so the certificate
/// step regenerates them), DKIM is missing (so DKIM is regenerated),
/// `mail.toml` is missing (so the credential pair is regenerated and
/// a password is minted). The recovery is what production sees when
/// an interrupted run is retried.
#[cfg(unix)]
#[test]
fn prepare_writes_marker_before_any_artifact_under_test_fault() {
	let dir = fresh_dir("marker-before-cert-fault");

	// Arm the fault; the guard clears it on drop.
	let guard = super::layout::FaultAfterMarkerGuard::arm();

	let result = prepare(dir.path(), DEFAULT_PORT_BASE);
	let err = match result {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err when the cert fault is armed, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains("fault_after_marker"),
		"error must name the synthetic fault, got: {rendered}"
	);

	// The marker is on disk after the failed prepare. This is the
	// post-condition the test pins: write_marker ran BEFORE the
	// post-marker fault fired.
	let marker = dir.path().join(".epistle-local");
	assert!(
		marker.exists(),
		"marker must be on disk after a failed prepare (got: {rendered})"
	);

	// The data directory must NOT exist after the failed prepare:
	// the fault fires before `create_with_mode(&data_dir, ...)` runs.
	assert!(
		!dir.path().join("data").exists(),
		"data/ must NOT have been created when the post-marker fault fired (got: {rendered})"
	);

	// No artifact is on disk after the failed prepare: the data
	// directory and the certificate step were the FIRST artifacts
	// and neither ran.
	let cert_path = dir.path().join("cert.pem");
	assert!(
		!cert_path.exists(),
		"cert.pem must NOT have been written when the post-marker fault fired"
	);
	assert!(
		!dir.path().join("key.pem").exists(),
		"key.pem must NOT have been written when the post-marker fault fired"
	);
	assert!(
		!dir.path().join("dkim.pem").exists(),
		"dkim.pem must NOT have been written when the post-marker fault fired"
	);
	assert!(
		!dir.path().join("mail.toml").exists(),
		"mail.toml must NOT have been written when the post-marker fault fired"
	);
	assert!(
		!dir.path().join("data").join("accounts.toml").exists(),
		"accounts.toml must NOT have been written when the post-marker fault fired"
	);

	// Drop the guard so the recovery `prepare` runs with the flag off.
	drop(guard);

	let second = prepare(dir.path(), DEFAULT_PORT_BASE).expect("recovery prepare succeeds");
	assert!(
		second.password.is_some(),
		"the recovery prepare must regenerate the credential pair, so a password is minted"
	);
	for name in [
		".epistle-local",
		"cert.pem",
		"key.pem",
		"dkim.pem",
		"mail.toml",
	] {
		assert!(
			dir.path().join(name).exists(),
			"recovery must leave {name} on disk"
		);
	}
	assert!(
		dir.path().join("data").exists(),
		"recovery must leave data/ on disk"
	);
	assert!(
		dir.path().join("data").join("accounts.toml").exists(),
		"recovery must leave accounts.toml on disk"
	);
}
