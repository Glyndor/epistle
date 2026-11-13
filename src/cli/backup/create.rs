//! The `epistle backup` subcommand: build the entries, write the tar.gz and
//! emit the warnings.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use super::collect::{collect_files, warn_externally_referenced};
use super::db_dump::{self, DATABASE_SQL_NAME, collect_dump_with};
use super::{keys_note, tar_gz};
use crate::cli::term::live::{Steps, quiet};
use crate::config::Config;

/// Run the `backup` subcommand. Builds the entries, writes the tar.gz, emits
/// warnings. A configured database whose dump cannot be taken is a hard
/// error: an archive without the database is worse than no archive, because
/// the operator only finds out at restore time that the accounts and the
/// antispam state are gone.
pub(in crate::cli) fn run(
	config: &Config,
	out: &mut impl Write,
	warnings: &mut impl Write,
) -> ExitCode {
	run_with(config, out, warnings, &db_dump::default_program_resolver)
}

/// Same as [`run`] with a custom program resolver. Tests use the
/// resolver to point `pg_dump` and `psql` at a stub in a tempdir
/// without touching the process `PATH`; production callers pass the
/// default, which is a no-op.
pub(in crate::cli) fn run_with(
	config: &Config,
	out: &mut impl Write,
	warnings: &mut impl Write,
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> ExitCode {
	// A rotation in progress changes the stores and keeps its new secrets on
	// disk; the backup waits for it rather than catching it half way. The
	// lock lives in the rotation's directory, which only a rotation creates:
	// a backup writes nothing into the data directory. A rotation that starts
	// for the first time during a backup is not waited for, and its secrets
	// stay out of the archive all the same (`collect::archived_from_rotation`).
	let _rotation = if config.data_dir.join("rotate").is_dir() {
		match crate::cli::rotate::lock(&config.data_dir) {
			Ok(Some(lock)) => Some(lock),
			Ok(None) => {
				crate::cli::style::error(
					"an `epistle rotate` is running on this server; back up once it has finished",
				);
				return ExitCode::FAILURE;
			}
			Err(error) => {
				crate::cli::style::error(error);
				return ExitCode::FAILURE;
			}
		}
	} else {
		None
	};
	let mut steps = Steps::start(&["files", "database", "archive"], false);
	steps.begin("files");
	let mut entries = match collect_files(&config.data_dir) {
		Ok(entries) => entries,
		Err(error) => {
			steps.fail();
			crate::cli::style::error(format_args!("reading data dir: {error}"));
			return ExitCode::FAILURE;
		}
	};
	steps.done();
	if let Some(db) = &config.database {
		steps.begin("database");
		let dump = match collect_dump_with(db, &config.data_dir, resolver) {
			Ok(dump) => dump,
			Err(error) => {
				steps.fail();
				crate::cli::style::error(format_args!("database dump: {error}"));
				return ExitCode::FAILURE;
			}
		};
		entries.push((DATABASE_SQL_NAME.to_string(), 0o644, dump));
		steps.done();
	}
	steps.begin("archive");
	let archive = match tar_gz(&entries) {
		Ok(archive) => archive,
		Err(error) => {
			steps.fail();
			crate::cli::style::error(format_args!("building archive: {error}"));
			return ExitCode::FAILURE;
		}
	};
	if quiet(|| out.write_all(&archive).and_then(|()| out.flush())).is_err() {
		return ExitCode::FAILURE;
	}
	steps.done();
	warn_externally_referenced(config, &entries.len(), warnings);
	keys_note::after_backup(&config.data_dir, warnings);
	let summary = format!("backed up {} files for this instance", entries.len());
	if steps.is_live() {
		steps.conclude(true, &summary);
	} else {
		eprintln!("{summary}");
	}
	ExitCode::SUCCESS
}
