//! Test-only helpers shared across the three `local/` test files. The
//! module is `pub(super)` so a test in any sibling file sees the same
//! constants and constructors.

use std::path::Path;

use super::DOMAIN;

/// A fresh temporary directory under `/tmp`, prefixed so a `git clean`
/// leaves a clue. The directory is removed when the `TempDir` is dropped.
pub(super) fn fresh_dir(tag: &str) -> tempfile::TempDir {
	tempfile::Builder::new()
		.prefix(&format!("epistle-local-{tag}-"))
		.tempdir()
		.expect("tempdir")
}

/// Build a `Config` from an existing `mail.toml`, the way `prepare`
/// does after writing the file, without ever binding listeners.
pub(super) fn load_for_test(path: &Path) -> Result<crate::config::Config, super::LocalError> {
	super::config::load_local_config(path)
}

/// Drive `load_accounts_outcome` for tests that need to pin the
/// outcome on a hand-crafted data directory (e.g. one whose parent is
/// a regular file, so the stat call returns `ENOTDIR` and the test
/// can exercise the metadata-error arm).
pub(super) fn load_accounts_outcome_for_test(
	data_dir: &Path,
) -> Result<super::config::AccountsOutcome, super::LocalError> {
	super::config::load_accounts_outcome(data_dir)
}

/// Re-export `LISTENERS` so tests can name the offsets without copying
/// the table.
pub(super) const LISTENERS_FOR_TEST: &[(crate::config::ListenerKind, u16)] =
	super::config::LISTENERS;

/// Re-export `AccountStore::open` so the layout test can assert
/// `Config::load` + `validate` accept the generated `mail.toml`.
pub(super) fn open_store_for_test(
	data_dir: &Path,
) -> Result<crate::directory_store::AccountStore, crate::directory_store::StoreError> {
	crate::directory_store::AccountStore::open(
		data_dir,
		vec![DOMAIN.to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
}

/// The variant name of a `LocalError`, for the assertion messages
/// that must not print the full Debug. The `DkimKey` and
/// `Certificate` variants carry reason strings, not the secrets
/// themselves, but the panic message has to be a CI log, and
/// printing the full Debug makes the line wider than the
/// diagnosis needs. The match is exhaustive on purpose: a new
/// variant added to `LocalError` breaks this file at compile time,
/// so the next caller cannot fall through and print the whole
/// struct.
pub(super) fn local_error_name(error: &super::LocalError) -> &'static str {
	match error {
		super::LocalError::PortOutOfRange(_) => "PortOutOfRange",
		super::LocalError::CsprngUnavailable => "CsprngUnavailable",
		super::LocalError::DkimKey(_) => "DkimKey",
		super::LocalError::Certificate(_) => "Certificate",
		super::LocalError::Account(_) => "Account",
		super::LocalError::NotEmpty(_) => "NotEmpty",
		super::LocalError::Io(_) => "Io",
	}
}
