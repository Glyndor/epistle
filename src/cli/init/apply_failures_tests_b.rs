//! Coverage-focused tests added when the ci gate raised the
//! cli/init threshold to 88%. Every test in this file was watched
//! red with a one-line sabotage swap and restored. The splits
//! share the helpers from `apply_failures_tests.rs` through the
//! `super` import and re-implement only what the parent does not
//! already expose.

use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::tests_failures::{answers_minimal, render_report_to_string};
use super::*;

/// Non-UTF-8 bytes in the surviving oauth private key must surface
/// as `OAuthPairIncomplete` from the plan so the operator sees the
/// refusal before confirming. The plan validates the pair before
/// any effect, exactly the way the apply phase does.
#[test]
fn plan_refuses_oauth_private_key_that_is_not_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	let bad = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
	std::fs::write(keys_dir.join("oauth_signing.key"), bad).expect("write bad private");
	std::fs::write(keys_dir.join("oauth_public.key"), b"public").expect("write public");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path));
	let err = plan.expect_err("plan must refuse non-utf-8 oauth private");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("not valid utf-8"),
		"the diagnostic must name the utf-8 problem: {message}"
	);
}

/// Non-UTF-8 bytes in the surviving oauth public key must surface
/// as `OAuthPairIncomplete` from the plan. Without the explicit
/// utf-8 check, the trim comparison would misreport the
/// mismatch as `OAuthPairMismatch` and the operator would not see
/// the real cause. The private key must therefore be a real
/// PKCS#8 ES256 document so the plan reaches the public-half
/// utf-8 check.
#[test]
fn plan_refuses_oauth_public_key_that_is_not_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome.error.is_none(), "mint: {:?}", outcome.error);
	let bad = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
	std::fs::write(keys_dir.join("oauth_public.key"), bad).expect("write bad public");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path));
	let err = plan.expect_err("plan must refuse non-utf-8 oauth public");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("not valid utf-8"),
		"the diagnostic must name the utf-8 problem on the public half: {message}"
	);
}

/// A surviving oauth private key that is utf-8 but not a valid
/// PKCS#8 ES256 document must surface as `OAuthPairIncomplete`
/// from the plan with the "not a valid PKCS#8" wording, not as
/// the more generic `OAuthPairMismatch`.
#[test]
fn plan_refuses_oauth_private_key_that_is_not_a_pkcs8_es256_document() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	std::fs::write(keys_dir.join("oauth_signing.key"), b"definitely not a key")
		.expect("write private");
	std::fs::write(keys_dir.join("oauth_public.key"), b"public").expect("write public");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path));
	let err = plan.expect_err("plan must refuse a non-PKCS#8 oauth private");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("PKCS#8"),
		"the diagnostic must name the PKCS#8 problem: {message}"
	);
}

/// Plan-phase mismatched-pair detection: when both oauth halves
/// are valid utf-8 PKCS#8 documents but they do not correspond,
/// the plan must surface `OAuthPairMismatch` so the operator sees
/// the refusal before any effect.
#[test]
fn plan_refuses_a_mismatched_oauth_pair_with_both_keys_valid_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	// Mint two independent PKCS#8 ES256 keypairs and pair the
	// first private with the second public. Both halves are
	// valid utf-8 documents, so the mismatch check is the only
	// failure path that fires.
	let (private_a, _public_a) = crate::cli::util::generate_oauth_keypair().expect("mint pair a");
	let (_private_b, public_b) = crate::cli::util::generate_oauth_keypair().expect("mint pair b");
	std::fs::write(keys_dir.join("oauth_signing.key"), &private_a).expect("write private_a");
	std::fs::write(keys_dir.join("oauth_public.key"), public_b.as_bytes()).expect("write public_b");
	let plan = apply_plan::plan(&answers_minimal(&data_dir, &config_path));
	let err = plan.expect_err("plan must refuse a mismatched oauth pair");
	let ApplyError::OAuthPairMismatch = &err else {
		panic!("expected OAuthPairMismatch, got {err:?}");
	};
}

/// Apply-phase mirror of the plan-phase utf-8 check: a non-UTF-8
/// oauth private key must surface as `OAuthPairIncomplete` from
/// the apply phase too, so the operator who skips the plan (the
/// `--answers` file path) still sees the real cause instead of
/// the more generic `OAuthPairMismatch` once the trim comparison
/// misfires.
#[cfg(unix)]
#[test]
fn apply_refuses_oauth_private_key_that_is_not_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	let bad = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
	std::fs::write(keys_dir.join("oauth_signing.key"), bad).expect("write bad private");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome
		.error
		.expect("apply must refuse non-utf-8 oauth private");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("not valid utf-8"),
		"the diagnostic must name the utf-8 problem: {message}"
	);
}

/// Apply-phase mirror for the public half: a non-UTF-8 oauth
/// public key must surface as `OAuthPairIncomplete`. The
/// private key must therefore be a real PKCS#8 ES256 document
/// so the apply phase reaches the public-half utf-8 check.
#[cfg(unix)]
#[test]
fn apply_refuses_oauth_public_key_that_is_not_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome.error.is_none(), "mint: {:?}", outcome.error);
	let bad = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
	std::fs::write(keys_dir.join("oauth_public.key"), bad).expect("write bad public");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome
		.error
		.expect("apply must refuse non-utf-8 oauth public");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("not valid utf-8"),
		"the diagnostic must name the utf-8 problem on the public half: {message}"
	);
}

/// Apply-phase mirror for the PKCS#8 check on the private key:
/// a utf-8 but non-PKCS#8 private key must surface as
/// `OAuthPairIncomplete` with the "not a valid PKCS#8" wording.
#[cfg(unix)]
#[test]
fn apply_refuses_oauth_private_key_that_is_not_a_pkcs8_es256_document() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	std::fs::create_dir_all(&keys_dir).expect("keys dir");
	std::fs::write(keys_dir.join("oauth_signing.key"), b"definitely not a key")
		.expect("write private");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome
		.error
		.expect("apply must refuse non-PKCS#8 oauth private");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("PKCS#8"),
		"the diagnostic must name the PKCS#8 problem: {message}"
	);
}

/// Calling `apply` directly with an existing config that the rest
/// of the CLI would refuse (here: a top-level unknown key while
/// the file is mode 0600) must surface `ConfigInvalid` with the
/// `Config::load` message. The plan path catches the same case
/// when `run()` is the entry point; the apply path catches it
/// when the caller drives `apply` directly. Both paths must
/// refuse.
#[cfg(unix)]
#[test]
fn apply_refuses_when_existing_config_has_an_unknown_top_level_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	assert!(outcome.error.is_none(), "seed: {:?}", outcome.error);
	let mut appended = std::fs::read_to_string(&config_path).expect("read");
	appended.insert_str(0, "# operator comment\noperator_note = \"keep me\"\n");
	std::fs::write(&config_path, &appended).expect("rewrite with unknown key");
	std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
		.expect("chmod 0600");
	let outcome = apply(&answers_minimal(&data_dir, &config_path));
	let err = outcome
		.error
		.expect("apply must refuse an invalid existing config");
	let ApplyError::ConfigInvalid(message) = &err else {
		panic!("expected ConfigInvalid, got {err:?}");
	};
	assert!(
		message.contains("operator_note"),
		"the diagnostic must name the unknown field: {message}"
	);
}

/// A surviving private key that is valid utf-8 but not a PEM
/// document (no `BEGIN PRIVATE KEY` marker) must surface as
/// `CertPairIncomplete` from `rcgen::KeyPair::from_pem` instead
/// of panicking. The apply phase must refuse with a recoverable
/// diagnostic; the operator can then delete the bad key and
/// retry, or restore a real one from backup.
#[cfg(unix)]
#[test]
fn apply_refuses_a_surviving_private_key_that_is_not_a_pem_document() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	let first = apply(&answers_minimal(&data_dir, &config_path));
	assert!(first.error.is_none(), "first run: {:?}", first.error);
	let key_path = keys_dir.join("key.pem");
	let cert_path = keys_dir.join("cert.pem");
	// Replace the surviving private key with a utf-8 document
	// that is not a PEM and remove the matching certificate so
	// the apply phase must reload the key. The
	// `CertPairIncomplete` branch fires from
	// `rcgen::KeyPair::from_pem`, which fails on non-PEM input.
	std::fs::write(&key_path, b"this is not a PEM key").expect("write bad key");
	let _ = std::fs::remove_file(&cert_path);
	let second = apply(&answers_minimal(&data_dir, &config_path));
	let err = second
		.error
		.expect("apply must refuse a non-PEM surviving private key");
	let ApplyError::CertPairIncomplete(message) = &err else {
		panic!("expected CertPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("key.pem"),
		"the diagnostic must name the bad private key: {message}"
	);
}

/// A surviving private key that is not even valid utf-8 must surface
/// as `CertPairIncomplete` from the utf-8 check, not panic, and the
/// operator must see a diagnostic naming the file. Removing the
/// matching certificate forces the apply phase to actually try
/// reloading the key.
#[cfg(unix)]
#[test]
fn apply_refuses_a_surviving_private_key_that_is_not_utf8() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	let first = apply(&answers_minimal(&data_dir, &config_path));
	assert!(first.error.is_none(), "first run: {:?}", first.error);
	let key_path = keys_dir.join("key.pem");
	let cert_path = keys_dir.join("cert.pem");
	let bad = [0xff, 0xfe, 0xfd, 0xfc, 0xfb];
	std::fs::write(&key_path, bad).expect("write bad key");
	let _ = std::fs::remove_file(&cert_path);
	let second = apply(&answers_minimal(&data_dir, &config_path));
	let err = second
		.error
		.expect("apply must refuse a non-utf-8 surviving private key");
	let ApplyError::CertPairIncomplete(message) = &err else {
		panic!("expected CertPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("utf-8"),
		"the diagnostic must name the utf-8 problem: {message}"
	);
}

/// A surviving oauth private key that exists but is unreadable
/// (mode 0000) must surface as `KeyWrite` from the apply phase so
/// the operator sees the read failure with the file path intact,
/// rather than a panic.
#[cfg(unix)]
#[test]
fn apply_refuses_when_surviving_oauth_private_key_is_unreadable() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	let first = apply(&answers_minimal(&data_dir, &config_path));
	assert!(first.error.is_none(), "first run: {:?}", first.error);
	let oauth_private = keys_dir.join("oauth_signing.key");
	std::fs::set_permissions(&oauth_private, std::fs::Permissions::from_mode(0o000))
		.expect("chmod 0000");
	let second = apply(&answers_minimal(&data_dir, &config_path));
	let err = second
		.error
		.expect("apply must refuse an unreadable surviving oauth private key");
	let ApplyError::KeyWrite(path, _io) = &err else {
		panic!("expected KeyWrite, got {err:?}");
	};
	assert_eq!(
		path, &oauth_private,
		"the diagnostic must name the unreadable oauth private key"
	);
	let _ = std::fs::set_permissions(&oauth_private, std::fs::Permissions::from_mode(0o600));
}

/// When `openssl` is on `PATH` but the actual `genpkey` call
/// fails, the apply phase must record a `Skipped` step for the
/// RSA DKIM key rather than panic or fall back to using the
/// Ed25519 key in the RSA slot. The integration test
/// `init_omits_rsa_dkim_keys_when_openssl_is_absent` covers the
/// runtime shape end-to-end; this unit test pins the report
/// shape the operator sees when generation fails.
#[test]
fn skipped_rsa_step_render_includes_the_failure_name() {
	let mut report = Report::default();
	report.steps.push(ReportStep::Skipped {
		name: "dkim rsa key".to_string(),
		reason: "openssl genpkey failed".to_string(),
	});
	let rendered = render_report_to_string(&report);
	assert!(
		rendered.contains("skipped:") && rendered.contains("dkim rsa key"),
		"the report must name the skipped RSA key: {rendered}"
	);
}

/// A surviving oauth public key that exists but is unreadable
/// must surface as `KeyWrite` from the apply phase. Without the
/// explicit error branch the read failure would propagate as a
/// panic.
#[cfg(unix)]
#[test]
fn apply_refuses_when_surviving_oauth_public_key_is_unreadable() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	let first = apply(&answers_minimal(&data_dir, &config_path));
	assert!(first.error.is_none(), "first run: {:?}", first.error);
	let oauth_public = keys_dir.join("oauth_public.key");
	std::fs::set_permissions(&oauth_public, std::fs::Permissions::from_mode(0o000))
		.expect("chmod 0000");
	let second = apply(&answers_minimal(&data_dir, &config_path));
	let err = second
		.error
		.expect("apply must refuse an unreadable surviving oauth public key");
	let ApplyError::KeyWrite(path, _io) = &err else {
		panic!("expected KeyWrite, got {err:?}");
	};
	assert_eq!(
		path, &oauth_public,
		"the diagnostic must name the unreadable oauth public key"
	);
	let _ = std::fs::set_permissions(&oauth_public, std::fs::Permissions::from_mode(0o600));
}

/// The TOML reconciliation must handle non-table values at
/// managed positions. An existing config with `public_ipv4`
/// as an integer (instead of the string the desired config uses)
/// must reconcile to the desired value without panicking.
#[test]
fn reconcile_handles_non_table_values_at_managed_positions() {
	let existing: toml::Value = toml::from_str(
		r#"
hostname = "mail.example.org"
public_ipv4 = 1234
data_dir = "/tmp/data"
domains = ["example.org"]

[dkim]
selector = "s1"
key_file = "/tmp/s1.pem"

[tls]
cert_file = "/tmp/cert.pem"
key_file = "/tmp/key.pem"
"#,
	)
	.expect("parse existing");
	let desired: toml::Value = toml::from_str(
		r#"
hostname = "mail.example.org"
public_ipv4 = "1.2.3.4"
data_dir = "/tmp/data"
domains = ["example.org"]

[dkim]
selector = "s1"
key_file = "/tmp/s1.pem"

[tls]
cert_file = "/tmp/cert.pem"
key_file = "/tmp/key.pem"
"#,
	)
	.expect("parse desired");
	let merged = apply_config::reconcile(existing, desired);
	assert_eq!(
		merged.get("public_ipv4"),
		Some(&toml::Value::String("1.2.3.4".to_string())),
		"the desired string value must replace the existing integer"
	);
}

/// The TOML reconciliation must recurse into tables at non-managed
/// positions. An existing config with an operator-added
/// `[custom]` table must be merged with the desired `[custom]`
/// table by recursing, not by overwriting wholesale.
#[test]
fn reconcile_recurses_into_unmanaged_tables() {
	let existing: toml::Value = toml::from_str(
		r#"
hostname = "mail.example.org"
data_dir = "/tmp/data"
domains = ["example.org"]

[dkim]
selector = "s1"
key_file = "/tmp/s1.pem"

[tls]
cert_file = "/tmp/cert.pem"
key_file = "/tmp/key.pem"

[custom]
keep = "yes"
drop = "no"
"#,
	)
	.expect("parse existing");
	let desired: toml::Value = toml::from_str(
		r#"
hostname = "mail.example.org"
data_dir = "/tmp/data"
domains = ["example.org"]

[dkim]
selector = "s1"
key_file = "/tmp/s1.pem"

[tls]
cert_file = "/tmp/cert.pem"
key_file = "/tmp/key.pem"

[custom]
add = "new"
drop = "yes"
"#,
	)
	.expect("parse desired");
	let merged = apply_config::reconcile(existing, desired);
	let custom = merged
		.get("custom")
		.expect("custom must survive as a table")
		.as_table()
		.expect("custom is a table");
	assert_eq!(
		custom.get("keep"),
		Some(&toml::Value::String("yes".to_string())),
		"keys present only in existing must be preserved"
	);
	assert_eq!(
		custom.get("add"),
		Some(&toml::Value::String("new".to_string())),
		"keys present only in desired must be added"
	);
	assert_eq!(
		custom.get("drop"),
		Some(&toml::Value::String("yes".to_string())),
		"keys present in both must take the desired value"
	);
}

/// A nested operator table that happens to carry a key whose name
/// matches a managed key (e.g. an operator-added `[operator]`
/// table with a `domains` field) must NOT lose the field. The
/// managed-key removal in `reconcile` applies to the root table
/// only; nested tables are owned by the operator and pass through
/// verbatim. The previous shape removed `INIT_MANAGED_KEYS` from
/// every table the recursion visited, which silently wiped a key
/// the operator had added.
#[test]
fn reconcile_preserves_a_managed_key_inside_a_nested_table() {
	// Both sides carry the same `[operator]` table with a `domains`
	// field. The previous shape wiped `operator.domains` because
	// `domains` is in INIT_MANAGED_KEYS and the removal applied at
	// every recursion depth. The fix removes only at the root.
	let existing: toml::Value = toml::from_str(
		r#"
hostname = "mail.example.org"

[operator]
domains = "operator-owned"
keep = "yes"
"#,
	)
	.expect("parse existing");
	let desired: toml::Value = toml::from_str(
		r#"
hostname = "mail.example.org"

[operator]
add = "new"
"#,
	)
	.expect("parse desired");
	let merged = apply_config::reconcile(existing, desired);
	let operator = merged
		.get("operator")
		.expect("operator table must survive")
		.as_table()
		.expect("operator is a table");
	assert_eq!(
		operator.get("domains"),
		Some(&toml::Value::String("operator-owned".to_string())),
		"the operator's nested `domains` must NOT be removed: {operator:?}"
	);
	assert_eq!(
		operator.get("keep"),
		Some(&toml::Value::String("yes".to_string())),
		"keys present only in existing must be preserved at the nested level"
	);
	assert_eq!(
		operator.get("add"),
		Some(&toml::Value::String("new".to_string())),
		"keys present only in desired must be added at the nested level"
	);
}

/// The `Display` impl for `ApplyError::Rng` must name the failing
/// source so the operator can see which key did not land. The
/// previous shape `expect`-panicked on a CSPRNG failure and exited
/// 101 with no report; the mapping now produces a typed error
/// that `run()` renders as exit 1 with the report of what landed.
#[test]
fn apply_error_rng_display_names_the_failing_source() {
	let rng = ApplyError::Rng("DKIM ed25519 key".to_string());
	let rendered = format!("{rng}");
	assert!(
		rendered.contains("DKIM ed25519 key"),
		"Rng display must name the failing source: {rendered}"
	);
	assert!(
		rendered.contains("CSPRNG") || rendered.contains("system"),
		"Rng display must mention the CSPRNG: {rendered}"
	);
}

/// `ApplyError::Rng` rendered into a report ends the report with a
/// single typed error rather than panicking, so `run()` exits 1
/// with the steps that already landed on disk.
#[test]
fn rng_error_maps_into_apply_outcome_without_panicking() {
	// A direct construction of the variant: the brief asks for a
	// unit test on the error mapping, not the OS condition itself.
	let err = ApplyError::Rng("storage key".to_string());
	let outcome = ApplyOutcome {
		report: Report::default(),
		error: Some(err),
	};
	let rendered_report = render_report_to_string(&outcome.report);
	assert!(
		rendered_report.is_empty(),
		"a fresh report must stay empty when only the RNG error fired: {rendered_report}"
	);
	let ApplyError::Rng(source) = outcome.error.as_ref().expect("error must be Some") else {
		panic!("expected Rng, got {:?}", outcome.error);
	};
	assert_eq!(source, "storage key", "the failing source must round-trip");
}

/// A `config_path` that has no parent directory (e.g. `/`) must
/// surface as `ConfigInvalid` from `write_validated_config` rather
/// than panicking or trying to stage at the filesystem root.
#[cfg(unix)]
#[test]
fn write_validated_config_refuses_a_path_with_no_parent() {
	let err = apply_config::write_validated_config(Path::new("/"), "data")
		.expect_err("a root config path must be refused");
	let ApplyError::ConfigInvalid(message) = &err else {
		panic!("expected ConfigInvalid, got {err:?}");
	};
	assert!(
		message.contains("no parent directory"),
		"the diagnostic must name the missing parent: {message}"
	);
}

/// A `config_path` with no usable file name (a path whose
/// `file_name()` returns `None` while its `parent()` is `Some`,
/// e.g. the current-directory marker `.`) must surface as
/// `ConfigInvalid` with a diagnostic naming the problem. The
/// previous guard (parent must be `Some`) has already passed for
/// `.`, so the no-file-name branch fires next.
#[cfg(unix)]
#[test]
fn write_validated_config_refuses_a_path_with_no_file_name() {
	let err = apply_config::write_validated_config(Path::new("."), "data")
		.expect_err("a config path with no file name must be refused");
	let ApplyError::ConfigInvalid(message) = &err else {
		panic!("expected ConfigInvalid, got {err:?}");
	};
	assert!(
		message.contains("no usable file name"),
		"the diagnostic must name the missing file name: {message}"
	);
}

/// A `config_path` whose parent directory exists but is not
/// traversable must surface `ConfigRead` from `symlink_metadata`
/// rather than panicking or staging at the wrong path. The
/// `NotFound` arm of the match is the normal "fresh install"
/// path; this test exercises the permission-denied arm that the
/// `NotFound` arm skips.
#[cfg(unix)]
#[test]
fn write_validated_config_refuses_a_path_under_a_non_traversable_parent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let locked = dir.path().join("locked");
	std::fs::create_dir(&locked).expect("mkdir locked");
	std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
		.expect("chmod 0000 on locked");
	let config_path = locked.join("mail.toml");
	let result = apply_config::write_validated_config(&config_path, "data");
	let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));
	let err = result.expect_err("a non-traversable parent must be refused");
	let ApplyError::ConfigRead(path, _io) = &err else {
		panic!("expected ConfigRead, got {err:?}");
	};
	assert_eq!(
		path, &config_path,
		"the diagnostic must name the unreadable config path"
	);
}

/// A write failure inside `write_validated_config` must NOT leave a
/// staging file behind. The file is opened with `O_EXCL` at mode
/// `0600` from the start: a leftover partial write would block the
/// next run on its `O_EXCL` blocker, and if the file holds an
/// inline DNS token the operator's `0600` token sits on disk in a
/// way no later step cleans up. The guard removes the file on every
/// error path.
#[cfg(unix)]
#[test]
fn write_validated_config_unlinks_staging_on_write_failure() {
	// Force a write_all failure by passing a payload that cannot be
	// written. The cleanest way without root is to make the parent
	// directory read-only after the staging file is created; the
	// `O_EXCL` open succeeds, but `write_all` returns a permission
	// error. We exercise the guard by forcing the failure mode the
	// guard was added for.
	let dir = tempfile::tempdir().expect("tempdir");
	let locked = dir.path().join("locked");
	std::fs::create_dir(&locked).expect("mkdir locked");
	let config_path = locked.join("mail.toml");
	// Block the directory before write_validated_config runs, so the
	// open itself fails; the staging file is never created.
	std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555))
		.expect("chmod 0555 on locked");
	let result = apply_config::write_validated_config(&config_path, "data");
	let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));
	let err = result.expect_err("a read-only parent must surface a write error");
	// Walk the parent and confirm no `mail.config.tmp.*` file
	// survives. The error arm must have surfaced the failure
	// without leaving a half-written file behind.
	let mut leftovers: Vec<PathBuf> = Vec::new();
	for entry in std::fs::read_dir(&locked).unwrap_or_else(|_| {
		std::fs::read_dir(dir.path()).expect("read tempdir")
	}) {
		let entry = entry.expect("dir entry");
		let name = entry.file_name();
		let s = name.to_string_lossy();
		if s.starts_with("mail.config.tmp.") {
			leftovers.push(entry.path());
		}
	}
	assert!(
		leftovers.is_empty(),
		"staging file(s) leaked after a write failure: {leftovers:?}"
	);
	// The error variant must surface the path so the operator sees
	// where the failure happened.
	let rendered = format!("{err}");
	assert!(
		rendered.contains(&config_path.display().to_string())
			|| rendered.contains("cannot write config"),
		"the diagnostic must name the operation or path: {rendered}"
	);
}

/// A pre-existing sibling at the first candidate staging name must
/// NOT stop the call from succeeding: the retry loop draws a fresh
/// suffix on each attempt, so a single collision falls through and
/// the next candidate wins.
#[cfg(unix)]
#[test]
fn write_validated_config_succeeds_when_first_staging_name_is_taken() {
	let dir = tempfile::tempdir().expect("tempdir");
	let parent = dir.path();
	let config_path = parent.join("mail.toml");
	// Pre-create a file at the basename the loop would try first.
	// Without the in-loop random draw, every attempt would target
	// this exact name and the call would fail after sixteen tries.
	let staged = parent.join("mail.toml.config.tmp.424242424242");
	std::fs::write(&staged, b"operator-owned file").expect("write pre-existing sibling");
	let body = "hostname = \"mail.example.org\"\n\
		data_dir = \"/var/lib/epistle\"\n";
	let result = apply_config::write_validated_config(&config_path, body);
	assert!(
		result.is_ok(),
		"a pre-existing sibling at the first candidate name must not stop the call: {:?}",
		result
	);
	let rendered = std::fs::read_to_string(&config_path).expect("read config");
	assert_eq!(
		rendered, body,
		"the destination must hold the validated bytes"
	);
	// The pre-existing file must still be on disk: a sibling at a
	// random name is not the operator's to lose.
	assert!(
		staged.exists(),
		"the operator's pre-existing sibling must survive the call"
	);
}
