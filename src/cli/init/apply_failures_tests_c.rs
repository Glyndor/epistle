//! Tests for `apply_config` behaviour (the `reconcile` table merge
//! and the `write_validated_config` staging path) and for
//! report-shape assertions plus plan-phase refusals that do not
//! belong in the apply-phase refusal tests in
//! `apply_failures_tests_b.rs`. Lifted into a sibling because
//! `apply_failures_tests_b.rs` was at the per-file line limit and
//! the natural seam is the apply-config side of the apply phase.

use std::path::Path;

use super::tests_failures::{answers_minimal, render_report_to_string};
use super::*;

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

/// A `config_path` whose parent cannot be traversed must surface
/// `ConfigRead` from `symlink_metadata` rather than panicking or
/// staging at the wrong path. The condition is built out of a
/// filesystem shape the kernel refuses for every uid: a regular
/// file where the parent directory would be. `symlink_metadata`
/// on `<file>/mail.toml` then returns `ErrorKind::NotADirectory`
/// for root and non-root alike; relying on `chmod 0000` on a
/// directory would let the test pass for the wrong reason when
/// the binary runs as root (the Debian package build). The
/// `NotFound` arm of the match is the normal "fresh install"
/// path; this test exercises the non-`NotFound` arm that the
/// `NotFound` arm skips.
#[cfg(unix)]
#[test]
fn write_validated_config_refuses_a_path_under_a_non_traversable_parent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let locked = dir.path().join("locked");
	std::fs::write(&locked, b"a regular file, not a directory").expect("write locked");
	let config_path = locked.join("mail.toml");
	let result = apply_config::write_validated_config(&config_path, "data");
	let err = result.expect_err("a non-traversable parent must be refused");
	let ApplyError::ConfigRead(path, _io) = &err else {
		panic!("expected ConfigRead, got {err:?}");
	};
	assert_eq!(
		path, &config_path,
		"the diagnostic must name the unreadable config path"
	);
}

/// A `config_path` that already exists as a symlink to a real
/// file must surface as `ConfigSymlink` from `write_validated_config`
/// without ever opening the staging file. The plan phase runs the
/// same check, but the path can become a symlink between plan and
/// apply, so the writer keeps its own guard. Removing the check
/// from `write_validated_config` would let the writer follow the
/// symlink, rename the staging file to it, and silently overwrite
/// the operator's target file.
#[cfg(unix)]
#[test]
fn write_validated_config_refuses_a_symlinked_config_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let target = dir.path().join("managed.toml");
	let target_body = b"target: untouched by init\n";
	std::fs::write(&target, target_body).expect("write target");
	let config_path = dir.path().join("mail.toml");
	std::os::unix::fs::symlink(&target, &config_path).expect("create symlink");
	let err = apply_config::write_validated_config(&config_path, "body")
		.expect_err("a symlinked config path must be refused");
	let ApplyError::ConfigSymlink(path) = &err else {
		panic!("expected ConfigSymlink, got {err:?}");
	};
	assert_eq!(
		path, &config_path,
		"the diagnostic must name the symlinked config path"
	);
	// The symlink must still be a link, and the target must still
	// hold the operator's original bytes: the refusal fires before
	// any staging file is opened, so the operator's target file is
	// untouched.
	let meta = std::fs::symlink_metadata(&config_path).expect("symlink_metadata");
	assert!(
		meta.file_type().is_symlink(),
		"config_path must still be a symlink after the refusal"
	);
	let still = std::fs::read(&target).expect("read target");
	assert_eq!(
		still, target_body,
		"the symlink target must be unchanged on disk"
	);
}

/// A symlinked `config_path` must surface as `ConfigSymlink` from the
/// plan phase before any effect is taken. The plan is a preflight, not
/// a lock: the path can still become a symlink between plan and apply,
/// and `write_validated_config` keeps its own check as a safety net.
/// The integration test `init_refuses_a_symlinked_config_path` in
/// `tests/init_end_to_end_c.rs` drives the same shape through the
/// `run()` entry point and asserts exit 2 with no data_dir on disk;
/// this unit test pins the plan-phase refusal directly.
#[cfg(unix)]
#[test]
fn plan_refuses_a_symlinked_config_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let target = dir.path().join("managed.toml");
	std::fs::write(&target, b"target: untouched by init\n").expect("write target");
	std::os::unix::fs::symlink(&target, &config_path).expect("create symlink");
	let err = apply_plan::plan(&answers_minimal(&data_dir, &config_path))
		.expect_err("plan must refuse a symlinked config_path");
	let ApplyError::ConfigSymlink(path) = &err else {
		panic!("expected ConfigSymlink, got {err:?}");
	};
	assert_eq!(
		path, &config_path,
		"the diagnostic must name the symlinked config path"
	);
}

/// A `config_path` that points at an existing directory must surface
/// as `ApplyError::ConfigNotAFile` from the plan before any effect.
/// Without the check, the apply phase would write every key, then the
/// staging step would fail with `Is a directory` after each step has
/// already landed on disk. The plan is the right place to surface
/// the refusal so the run exits 2 with no `data_dir` on disk.
#[cfg(unix)]
#[test]
fn plan_refuses_a_config_path_that_is_an_existing_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let etc = dir.path().join("etc");
	std::fs::create_dir(&etc).expect("mkdir etc");
	let err = apply_plan::plan(&answers_minimal(&data_dir, &etc))
		.expect_err("plan must refuse a config_path that is a directory");
	let ApplyError::ConfigNotAFile(path) = &err else {
		panic!("expected ConfigNotAFile, got {err:?}");
	};
	assert_eq!(
		path, &etc,
		"the diagnostic must name the directory config_path"
	);
}
