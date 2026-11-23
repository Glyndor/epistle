//! The container half of the database commands: the `podup exec` invocations
//! that dump the database inside the `db` service and replay a dump into it.
//! It lives in its own file to keep `db_dump.rs` under the per-file code-line
//! cap.

use std::path::{Path, PathBuf};

use crate::cli::init::{DATABASE_NAME, DATABASE_PASSWORD_FILE, DATABASE_USER};

use super::super::restore_signals::stop_if_arrived;
use super::{
	BackupError, CommandSpec, default_program_resolver, run_command_capturing_stdout_with,
};

/// The container-side `pg_dump` invocation. The shell reads the mounted
/// secret into `PGPASSWORD` inside `db`, then executes the client against
/// the Unix socket. Only fixed compose constants enter the shell script;
/// the secret value never reaches the host environment or argv.
pub(crate) fn container_pg_dump_spec(compose: &Path) -> Result<CommandSpec, BackupError> {
	db_sh_spec(
		compose,
		format!(
			r#"PGPASSWORD="$(cat '{DATABASE_PASSWORD_FILE}')" exec pg_dump -Fp --clean --if-exists --no-owner --no-privileges -h '/var/run/postgresql' -U '{DATABASE_USER}' -d '{DATABASE_NAME}'"#
		),
	)
}

/// A `podup -f <compose> exec -T db sh -c <script>` call. It runs as the
/// container's own user (`postgres`), the only one that can read the mounted
/// password.
fn db_sh_spec(compose: &Path, script: String) -> Result<CommandSpec, BackupError> {
	if !compose.exists() {
		return Err(BackupError::ComposeFileMissing(compose.to_path_buf()));
	}
	let mut argv = vec![
		"podup".to_string(),
		"-f".to_string(),
		compose.to_string_lossy().into_owned(),
		"exec".to_string(),
		"-T".to_string(),
	];
	argv.extend(["db", "sh", "-c"].map(String::from));
	argv.push(script);
	Ok(CommandSpec::new(argv))
}

/// The SQL as the transaction the replay runs: `BEGIN;`, the dump, `COMMIT;`.
///
/// `psql -1` would open and close the transaction itself, but it commits at
/// the end of whatever it was given. A stream that stops at a statement
/// boundary (the sender died after a whole statement) then commits as if it
/// were the dump, with exit status 0. With the transaction written into the
/// stream, a stream that stops early never reaches `COMMIT;` and the server
/// rolls the work back when the connection ends. The dump is `pg_dump -Fp`
/// output, which has no transaction statements of its own.
pub(super) fn transaction(sql: &[u8]) -> Vec<u8> {
	let mut payload = Vec::with_capacity(sql.len() + 16);
	payload.extend_from_slice(b"BEGIN;\n");
	payload.extend_from_slice(sql);
	payload.extend_from_slice(b"\nCOMMIT;\n");
	payload
}

/// The container-side `psql` invocation. `podup exec -T` hands its stdin to
/// the process in the container (podup 6.0.0; earlier releases did not), so
/// the SQL is the standard input of `psql -f -` and is never written to a file
/// on the host or inside `db`: it holds the credential hashes of every
/// account.
///
/// A shell reads the secret into `PGPASSWORD` and execs `psql`. It runs as the
/// container user, because the password is mounted readable by that user
/// alone (mode 0400, and the container drops every capability, so root cannot
/// read it either). `ON_ERROR_STOP` makes the first failing statement end
/// `psql` with status 3, and the open transaction is rolled back with the
/// connection. `exec` lets a `SIGTERM` sent to the process in the container
/// reach `psql` itself.
pub(crate) fn container_psql_load_spec(
	compose: &Path,
	sql: &[u8],
) -> Result<CommandSpec, BackupError> {
	Ok(db_sh_spec(
		compose,
		format!(
			r#"PGPASSWORD="$(cat '{DATABASE_PASSWORD_FILE}')" exec psql -v ON_ERROR_STOP=1 -X -f - -h '/var/run/postgresql' -U '{DATABASE_USER}' -d '{DATABASE_NAME}'"#
		),
	)?
	.with_stdin(transaction(sql)))
}

/// Load the SQL into the database through the container path.
#[allow(dead_code)]
pub(crate) fn load_dump_container(compose: &Path, sql: &[u8]) -> Result<(), BackupError> {
	load_dump_container_with(compose, sql, &default_program_resolver)
}

/// Whether `psql` confirmed the commit: the last line it printed is the
/// `COMMIT` command tag. A run that exits 0 without it did not commit, which
/// is what a stream cut short looks like from outside.
pub(super) fn confirmed_commit(stdout: &[u8]) -> bool {
	String::from_utf8_lossy(stdout)
		.lines()
		.rev()
		.map(str::trim)
		.find(|line| !line.is_empty())
		== Some("COMMIT")
}

/// Same as [`load_dump_container`] with a custom program resolver, which is
/// how the tests put a stub where `podup` would be.
///
/// Nothing is staged: the SQL goes to `podup exec` on its standard input. The
/// restore succeeds only when `psql` exits 0 **and** printed the `COMMIT`
/// tag, so an input that did not arrive whole is an error even though the
/// server rolled it back without one.
pub(super) fn load_dump_container_with(
	compose: &Path,
	sql: &[u8],
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<(), BackupError> {
	// A held stop signal ends the restore here, before anything is loaded and
	// never once `psql` has started.
	stop_if_arrived()?;
	let output =
		run_command_capturing_stdout_with(&container_psql_load_spec(compose, sql)?, resolver)?;
	if !output.status_ok {
		// `psql` committed and the exec failed after it (podup lost the
		// connection while relaying the end): the dump is in the database,
		// whatever the exit status says.
		if confirmed_commit(&output.stdout) {
			return Err(BackupError::FailedAfterCommit {
				stderr: output.stderr.trim().to_string(),
			});
		}
		return Err(BackupError::CommandFailed {
			stderr: output.stderr.trim().to_string(),
			code: output.code,
		});
	}
	if !confirmed_commit(&output.stdout) {
		return Err(BackupError::NotCommitted);
	}
	Ok(())
}
