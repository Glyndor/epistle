//! Take the dump and replay it, choosing between the host tools and the `db`
//! service of the compose stack.

use std::path::{Path, PathBuf};

use crate::cli::backup::restore_signals::stop_if_arrived;
use crate::cli::init::compose_file_path;
use crate::config::Database;

use super::{
	BackupError, CommandSpec, container_pg_dump_spec, container_psql_load_spec,
	default_program_resolver, ensure_stack_database, host_pg_dump_spec, host_psql_load_spec,
	load_dump_container_with, output_ends_with_pg_dump_complete, run_command_capturing_stdout_with,
};

/// Take the `pg_dump` and produce the bytes that go into the archive. The
/// caller has already decided the host vs container branch; the branch is
/// keyed on whether `compose_file_path(data_dir)` exists.
#[allow(dead_code)]
pub(crate) fn collect_dump(db: &Database, data_dir: &Path) -> Result<Vec<u8>, BackupError> {
	collect_dump_with(db, data_dir, &default_program_resolver)
}

/// Same as [`collect_dump`] with a custom program resolver. The resolver
/// decides what absolute path `argv[0]` resolves to, which is the only
/// way to swap the binary in a parallel-test environment without
/// racing other tests that share the process `PATH`.
///
/// The exit status is read before stdout is accepted. A dump tool that
/// printed the head of the SQL and then errored (a dropped connection, a
/// mid-stream error, any non-zero exit) did not produce a dump, so the
/// partial bytes are refused even when stdout is non-empty: a truncated
/// archive that lands in the backups directory and reads as good is worse
/// than no archive at all, because the operator only finds out at restore
/// time that the database is missing rows.
///
/// On a clean run the stdout is also checked for the closing marker
/// pg_dump writes at the end of a successful run
/// (`-- PostgreSQL database dump complete`). A capture that lost the tail
/// of the dump (a `podman exec` pipe closing on the operator's end, a
/// host filesystem out of space, a stub that `printf`'d some bytes and
/// exited zero) returns 0 and would pass the status gate otherwise; the
/// marker gate is what catches them.
pub(crate) fn collect_dump_with(
	db: &Database,
	data_dir: &Path,
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<Vec<u8>, BackupError> {
	let spec = pg_dump_spec(db, data_dir)?;
	run_command_capturing_stdout_with(&spec, resolver).and_then(|output| {
		if !output.status_ok {
			return Err(BackupError::CommandFailed {
				stderr: output.stderr.trim().to_string(),
				code: output.code,
			});
		}
		if output.stdout.is_empty() {
			return Err(BackupError::EmptyOutput);
		}
		if !output_ends_with_pg_dump_complete(&output.stdout) {
			return Err(BackupError::TruncatedDump);
		}
		Ok(output.stdout)
	})
}

/// Run the SQL bytes from the archive into the configured database.
#[allow(dead_code)]
pub(crate) fn load_dump(db: &Database, data_dir: &Path, sql: &[u8]) -> Result<(), BackupError> {
	load_dump_with(db, data_dir, sql, &default_program_resolver)
}

/// Same as [`load_dump`] with a custom program resolver.
pub(crate) fn load_dump_with(
	db: &Database,
	data_dir: &Path,
	sql: &[u8],
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<(), BackupError> {
	if compose_file_path(data_dir).exists() {
		ensure_stack_database(db)?;
		load_dump_container_with(&compose_file_path(data_dir), sql, resolver)
	} else {
		let spec = host_psql_load_spec(db, sql)?;
		stop_if_arrived()?;
		run_command_capturing_stdout_with(&spec, resolver).and_then(|output| {
			if output.status_ok {
				Ok(())
			} else {
				Err(BackupError::CommandFailed {
					stderr: output.stderr.trim().to_string(),
					code: output.code,
				})
			}
		})
	}
}

/// Build the command spec for taking the `pg_dump`. The host path shells
/// out to `pg_dump` directly; the container path runs `pg_dump` inside the
/// `db` service with `podup -f <compose> exec -T db`. The two paths share
/// the same invariant: the password never appears in argv, only in the
/// environment (`PGPASSWORD` on the host or loaded from the mounted
/// secret by `sh -c` inside the container). The image entrypoint uses
/// `POSTGRES_PASSWORD_FILE` at initialization; libpq does not read it.
pub(crate) fn pg_dump_spec(db: &Database, data_dir: &Path) -> Result<CommandSpec, BackupError> {
	let compose = compose_file_path(data_dir);
	if compose.exists() {
		ensure_stack_database(db)?;
		container_pg_dump_spec(&compose)
	} else {
		host_pg_dump_spec(db)
	}
}

/// Build the command spec for loading the SQL archive into the database.
/// The host path runs `psql` directly with the SQL on stdin; the
/// container path `podup cp`s the SQL into the `db` service (because
/// `podup exec` does not forward stdin) and then runs `psql -f` against
/// the copied path. `in_container_path` names the SQL file inside the
/// `db` service when the container path is selected; the host path
/// ignores it.
#[allow(dead_code)]
pub(crate) fn psql_load_spec(
	db: &Database,
	data_dir: &Path,
	sql: &[u8],
	in_container_path: &str,
) -> Result<CommandSpec, BackupError> {
	let compose = compose_file_path(data_dir);
	if compose.exists() {
		ensure_stack_database(db)?;
		container_psql_load_spec(&compose, in_container_path, sql)
	} else {
		host_psql_load_spec(db, sql)
	}
}
