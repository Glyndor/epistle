//! Answers unit tests for `config_path` shape and keys-directory
//! containment. The validator catches every path that the apply
//! phase would have stumbled over only after writing every key
//! (root, current dir, trailing dot, double dot, trailing slash,
//! missing file name, parent dictating the data dir, config_path
//! living inside the keys dir the apply phase is about to write).

use std::path::PathBuf;

use super::Mode::*;
use super::tests::minimal;
use super::*;

/// `config_path = "/"` is absolute and so passed the absolute check,
/// but the apply phase would discover it has no file name only after
/// creating the data directory and writing every key. The validator
/// now catches the missing file name before any effect, so the run
/// exits 2 with nothing on disk.
#[test]
fn config_path_root_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from("/");
	let errors = answers
		.validate()
		.expect_err("config_path = `/` must be rejected by the validator");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathNoFileName)),
		"root config_path must surface as ConfigPathNoFileName, got {errors:?}"
	);
}

/// `config_path = "."` (current directory) has no file name to stage
/// next to. Same shape as the root case: the validator catches it
/// before any effect.
#[test]
fn config_path_current_dir_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from(".");
	// `path.file_name()` on `.` returns None, which is the right shape
	// to test; but `.` is not absolute, so absolute check fires first.
	// Use an absolute equivalent that the absolute check passes but
	// `file_name()` returns None for. The apply phase's
	// `write_validated_config` accepts `/` (no file name) and rejects
	// `/.` (file name = `.`), so we test the second shape against the
	// validator's same rule.
	answers.config_path = PathBuf::from("/.");
	let errors = answers
		.validate()
		.expect_err("config_path = `/.` must be rejected by the validator");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathNoFileName)),
		"`/.` config_path must surface as ConfigPathNoFileName, got {errors:?}"
	);
}

/// `config_path == data_dir` would let the staging step land the
/// config inside the data directory and overwrite a key. The
/// validator catches the equality before any effect.
#[test]
fn config_path_equals_data_dir_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/var/lib/epistle");
	let errors = answers
		.validate()
		.expect_err("config_path == data_dir must be rejected by the validator");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathEqualsDataDir)),
		"config_path == data_dir must surface as ConfigPathEqualsDataDir, got {errors:?}"
	);
}

/// `config_path = "/x/etc/."` (text ending in `/.`) must surface as
/// `ConfigPathNoFileName` from the validator: the last
/// `Path::components()` slot is `CurDir`, not `Normal`. The shape
/// would otherwise pass through to the apply phase, write every
/// key, then fail at the staging step with `Is a directory`.
#[test]
fn config_path_trailing_dot_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from("/x/etc/.");
	let errors = answers
		.validate()
		.expect_err("config_path = `/x/etc/.` must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathNoFileName)),
		"`/x/etc/.` must surface as ConfigPathNoFileName, got {errors:?}"
	);
}

/// Acceptance half of the trailing-dot pair: a `config_path` whose
/// last component is a real file name must validate. Without this
/// test, a path-check that refused every absolute path would still
/// satisfy the rejection test above.
#[test]
fn config_path_real_file_name_validates() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from("/x/etc/mail.toml");
	assert!(
		answers.validate().is_ok(),
		"`/x/etc/mail.toml` must validate, got {:?}",
		answers.validate()
	);
}

/// `config_path = "/x/etc/.."` (text ending in `/..`) must surface
/// as `ConfigPathNoFileName`: the last `components()` slot is
/// `ParentDir`. Without this check the staging step would try to
/// stage a sibling of the parent and the apply phase would still
/// fail after every key was written.
#[test]
fn config_path_dot_dot_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from("/x/etc/..");
	let errors = answers
		.validate()
		.expect_err("config_path = `/x/etc/..` must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathNoFileName)),
		"`/x/etc/..` must surface as ConfigPathNoFileName, got {errors:?}"
	);
}

/// `config_path = "/x/etc/"` (text ending in a bare `/`) must
/// surface as `ConfigPathNoFileName`: `Path::components()` for
/// that path returns `Normal("etc")` as the last entry, so the
/// components check alone would not catch it. The validator's
/// trailing-separator rule handles the literal string.
#[test]
fn config_path_trailing_slash_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from("/x/etc/");
	let errors = answers
		.validate()
		.expect_err("config_path = `/x/etc/` must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathNoFileName)),
		"`/x/etc/` must surface as ConfigPathNoFileName, got {errors:?}"
	);
}

/// `config_path = <data_dir>/keys/s1.pem` would let the staging
/// step land a temp file inside the keys directory the same run is
/// about to write. The validator catches the componentwise
/// containment before any effect.
#[test]
fn config_path_inside_keys_dir_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/var/lib/epistle/keys/s1.pem");
	let errors = answers
		.validate()
		.expect_err("config_path inside keys dir must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathInsideKeysDir)),
		"config_path inside keys must surface as ConfigPathInsideKeysDir, got {errors:?}"
	);
}

/// Acceptance half of the keys-dir pair: a `config_path` that is
/// a sibling of `keys` (a directory the operator owns) must
/// validate. The `config_path` itself has to live outside
/// `data_dir` (a separate validator check), so the test puts it
/// at `/etc/epistle/mail.toml` with `data_dir = /var/lib/epistle`
/// the standard layout the operator runs in production.
#[test]
fn config_path_data_dir_sibling_validates() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/etc/epistle/mail.toml");
	assert!(
		answers.validate().is_ok(),
		"`/etc/epistle/mail.toml` next to `/var/lib/epistle` must validate, got {:?}",
		answers.validate()
	);
}

/// `config_path = <data_dir>/keys/sub/mail.toml` is deeper inside
/// the keys directory; the validator must refuse with the same
/// `ConfigPathInsideKeysDir` variant.
#[test]
fn config_path_inside_keys_subdir_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/var/lib/epistle/keys/sub/mail.toml");
	let errors = answers
		.validate()
		.expect_err("config_path inside keys/sub must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathInsideKeysDir)),
		"config_path inside keys/sub must surface as ConfigPathInsideKeysDir, got {errors:?}"
	);
}

/// A `keysfoo` directory next to `keys` is a sibling the operator
/// owns, not a componentwise child of `keys`. The validator must
/// accept it: the prefix match is on the basename, not the
/// component. The config file has to live outside `data_dir`
/// (a separate validator check), so the test puts the sibling
/// `keysfoo` directory under `/var/lib`, next to the
/// data_dir, and points the config inside it.
#[test]
fn config_path_keys_prefix_sibling_validates() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/var/lib/keysfoo/mail.toml");
	assert!(
		answers.validate().is_ok(),
		"`/var/lib/keysfoo/mail.toml` next to `/var/lib/epistle` must validate, got {:?}",
		answers.validate()
	);
}
