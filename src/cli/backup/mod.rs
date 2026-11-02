//! The `epistle backup` and `epistle restore` subcommands.
//!
//! `create` builds the archive, `restore` lays one down again, and
//! `collect` decides what goes into one. The dump (and replay) of the
//! database lives in `db_dump` to keep each file under the per-file
//! 500-code-line cap; the test modules live in each owner's `tests/`
//! directory, with leaves by topic so each compile unit stays small.

mod collect;
mod create;
mod db_dump;
mod keys_note;
mod restore;
mod restore_files;
mod restore_signals;
mod tar_format;

// `restore_files` reads this through `super`.
use db_dump::DATABASE_SQL_NAME;

pub(super) use create::run;
#[allow(unused_imports)]
pub(super) use create::run_with;
#[allow(unused_imports)]
pub(in crate::cli) use restore::refuse_unsafe_targets;
pub(super) use restore::run_restore;
#[allow(unused_imports)]
pub(super) use restore::run_restore_with;
pub(in crate::cli) use restore::{RestoreSummary, run_restore_reporting};

// The test files reach all of this through `use super::*;`, as they did
// when the whole module was one file.
#[cfg(test)]
#[allow(unused_imports)]
use {
	crate::cli::term::live::{Steps, quiet},
	crate::config::{BlobBackendConfig, Config},
	collect::{collect_files, warn_externally_referenced},
	restore_files::{check_files, lay_files, load_failure_state},
	std::io::Write,
	std::os::unix::fs::PermissionsExt,
	std::path::{Path, PathBuf},
	std::process::ExitCode,
};

/// Build the gzip-compressed archive; see [`tar_format`].
pub(in crate::cli) fn tar_gz(entries: &[(String, u32, Vec<u8>)]) -> std::io::Result<Vec<u8>> {
	tar_format::tar_gz(entries)
}

// The database dump/load code is split out into `db_dump` (the
// sibling module at the top of this file) so each compile unit
// stays under the per-file 500-line cap. Re-export the items the
// existing tests reach for so the test files' `use super::*;`
// glob keeps working unchanged.
#[allow(unused_imports)]
pub(crate) use db_dump::CapturedOutput;
#[allow(unused_imports)]
pub(super) use db_dump::collect_dump;
#[allow(unused_imports)]
pub(super) use db_dump::container_cp_into_spec;
#[allow(unused_imports)]
pub(super) use db_dump::container_pg_dump_spec;
#[allow(unused_imports)]
pub(super) use db_dump::container_psql_load_spec;
#[allow(unused_imports)]
pub(super) use db_dump::host_pg_dump_spec;
#[allow(unused_imports)]
pub(super) use db_dump::host_psql_load_spec;
#[allow(unused_imports)]
pub(super) use db_dump::load_dump;
#[allow(unused_imports)]
pub(super) use db_dump::load_dump_container;
#[allow(unused_imports)]
pub(super) use db_dump::pg_dump_spec;
#[allow(unused_imports)]
pub(super) use db_dump::psql_load_spec;
#[allow(unused_imports)]
pub(super) use db_dump::run_command_capturing_stdout;
// Test-only re-exports: the existing test files use `use super::*;`
// to reach `BackupError`, `CommandSpec`, and `split_url_password`.
// `pub(crate)` is the widest visibility a child of a non-public
// module can give; the test files are grandchildren of `crate::cli`
// and the re-export must reach them.
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use db_dump::{BackupError, CommandSpec, split_url_password};

#[cfg(test)]
mod tests;
