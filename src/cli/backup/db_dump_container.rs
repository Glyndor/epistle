//! The container half of the database commands: the `podup exec` invocations
//! that dump and replay the database inside the `db` service, and the staged
//! copy of the SQL a restore hands to it. It lives in its own file to keep
//! `db_dump.rs` under the per-file code-line cap.

use std::path::{Path, PathBuf};

use crate::cli::init::{DATABASE_NAME, DATABASE_PASSWORD_FILE, DATABASE_USER};

use super::db_dump_host_temp::RestoreHostTemp;
use super::{
	BackupError, CommandSpec, default_program_resolver, run_command_capturing_stdout_with,
};

/// The container-side `pg_dump` invocation. The shell reads the mounted
/// secret into `PGPASSWORD` inside `db`, then executes the client against
/// the Unix socket. Only fixed compose constants enter the shell script;
/// the secret value never reaches the host environment or argv.
pub(crate) fn container_pg_dump_spec(compose: &Path) -> Result<CommandSpec, BackupError> {
	if !compose.exists() {
		return Err(BackupError::ComposeFileMissing(compose.to_path_buf()));
	}
	let compose_str = compose.to_string_lossy().into_owned();
	let script = format!(
		r#"PGPASSWORD="$(cat '{DATABASE_PASSWORD_FILE}')" exec pg_dump -Fp --clean --if-exists --no-owner --no-privileges -h '/var/run/postgresql' -U '{DATABASE_USER}' -d '{DATABASE_NAME}'"#
	);
	let spec = CommandSpec::new(vec![
		"podup".to_string(),
		"-f".to_string(),
		compose_str,
		"exec".to_string(),
		"-T".to_string(),
		"db".to_string(),
		"sh".to_string(),
		"-c".to_string(),
		script,
	]);
	Ok(spec)
}

/// The container-side `psql` invocation. `podup exec` does not forward
/// stdin (measured against `podup 5.10.13`), so the SQL is copied in
/// first through `podup cp <host> <svc>:<in_container_path>`, and then a
/// shell reads the secret into `PGPASSWORD` and execs `psql -1 -f` against
/// that path, after forcing the file to `0600`: it holds the credential
/// hashes of every account, and the mode `podup cp` leaves is not something
/// to assume. The shell runs as the user that owns the copy (`podman cp`
/// into a container leaves it owned by the container user, measured), so
/// the `chmod` is allowed; if it ever is not, the replay stops before
/// `psql` reads anything. The transaction and `ON_ERROR_STOP` make replay atomic when
/// a SQL statement fails. The shell uses `exec psql` so a `SIGTERM` sent
/// to the container's exec process (an operator hitting Ctrl-C, a
/// timeout, an aborted `podman exec`) reaches `psql` itself and aborts
/// the transaction. Cleanup of the in-container copy lives in
/// [`container_rm_temp_spec`] (host-side, since the wrapper shell is
/// gone), invoked from [`load_dump_container_with`] on both success and
/// error.
pub(crate) fn container_psql_load_spec(
	compose: &Path,
	in_container_path: &str,
	_sql: &[u8],
) -> Result<CommandSpec, BackupError> {
	if !compose.exists() {
		return Err(BackupError::ComposeFileMissing(compose.to_path_buf()));
	}
	let compose_str = compose.to_string_lossy().into_owned();
	let script = format!(
		r#"chmod 600 '{path}' && PGPASSWORD="$(cat '{DATABASE_PASSWORD_FILE}')" exec psql -v ON_ERROR_STOP=1 -1 -X -f '{path}' -h '/var/run/postgresql' -U '{DATABASE_USER}' -d '{DATABASE_NAME}'"#,
		path = in_container_path,
	);
	let spec = CommandSpec::new(vec![
		"podup".to_string(),
		"-f".to_string(),
		compose_str,
		"exec".to_string(),
		"-T".to_string(),
		"db".to_string(),
		"sh".to_string(),
		"-c".to_string(),
		script,
	]);
	Ok(spec)
}

/// `podup -f <compose> exec -T db sh -c "rm -f <in_container_path>"`.
/// Removes the staged SQL file from the `db` service after the restore
/// returns, whether the replay succeeded or failed. Must run from the
/// host (`podup exec`) because the in-container shell that exec'd
/// `psql` is no longer around to trap a `rm -f` on its own exit.
pub(crate) fn container_rm_temp_spec(
	compose: &Path,
	in_container_path: &str,
) -> Result<CommandSpec, BackupError> {
	if !compose.exists() {
		return Err(BackupError::ComposeFileMissing(compose.to_path_buf()));
	}
	let compose_str = compose.to_string_lossy().into_owned();
	let script = format!(r#"rm -f '{path}'"#, path = in_container_path);
	let spec = CommandSpec::new(vec![
		"podup".to_string(),
		"-f".to_string(),
		compose_str,
		"exec".to_string(),
		"-T".to_string(),
		"db".to_string(),
		"sh".to_string(),
		"-c".to_string(),
		script,
	]);
	Ok(spec)
}

/// Load the SQL into the database through the container path. The
/// `podup cp` happens in `copy_sql_into_container`, then the `psql`
/// exec is run. The two-step is exposed as one function so the caller
/// stays linear.
#[allow(dead_code)]
pub(crate) fn load_dump_container(compose: &Path, sql: &[u8]) -> Result<(), BackupError> {
	load_dump_container_with(compose, sql, &default_program_resolver)
}

/// Same as [`load_dump_container`] with a custom program resolver. The
/// host-temp write happens before any spawn, so it stays unchanged
/// between the production path and the test path.
///
/// The SQL is staged to a host temp file created `0600` under a name unique
/// to this call, so nothing but its owner can read the credential hashes it
/// carries and two simultaneous restores cannot clobber each other. The
/// [`RestoreHostTemp`] guard removes it on every exit path, including the
/// error path and a panic. Inside the container the file lands on a name
/// derived from the same unique file name, is forced to `0600` by the
/// replay shell before `psql` reads it (it sits in the `/tmp` tmpfs of the
/// `db` service, which is private to that container), and is
/// removed by a host-side `podup exec` once the replay completes (success
/// or error); see
/// [`container_psql_load_spec`] and [`container_rm_temp_spec`].
pub(super) fn load_dump_container_with(
	compose: &Path,
	sql: &[u8],
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<(), BackupError> {
	let mut host_temp = RestoreHostTemp::create()?;
	host_temp.write_all(sql)?;
	let in_container_path = format!("/tmp/{}", host_temp.file_name());
	let result = (|| -> Result<(), BackupError> {
		let cp = container_cp_into_spec(compose, host_temp.path(), &in_container_path)?;
		run_command_capturing_stdout_with(&cp, resolver).and_then(|output| {
			if output.status_ok {
				Ok(())
			} else {
				Err(BackupError::CommandFailed {
					stderr: output.stderr.trim().to_string(),
					code: output.code,
				})
			}
		})?;
		let psql = container_psql_load_spec(compose, &in_container_path, sql)?;
		run_command_capturing_stdout_with(&psql, resolver).and_then(|output| {
			if output.status_ok {
				Ok(())
			} else {
				Err(BackupError::CommandFailed {
					stderr: output.stderr.trim().to_string(),
					code: output.code,
				})
			}
		})
	})();
	// Drop runs even when the closure returned `Err`, removing the host
	// temp. The in-container file is removed by the host-side `podup exec`
	// below regardless of the replay outcome: with `exec psql` in the
	// replay shell, the wrapper shell is replaced by psql and any trap
	// would never fire on the psql exit path. The cleanup is best-effort:
	// a leftover `rm -f` failure does not override the restore outcome.
	if let Ok(cleanup) = container_rm_temp_spec(compose, &in_container_path) {
		let _ = run_command_capturing_stdout_with(&cleanup, resolver);
	}
	drop(host_temp);
	result
}

/// `podup -f <compose> cp <host> db:/tmp/...`, copy the SQL file from
/// the host temp path into the `db` container. podup's `cp` requires the
/// target to be writable inside the container; `/tmp` is the conventional
/// scratch path in the `db` service (the compose also binds a tmpfs on
/// `/tmp` for exactly this kind of use).
pub(crate) fn container_cp_into_spec(
	compose: &Path,
	host_path: &Path,
	container_path: &str,
) -> Result<CommandSpec, BackupError> {
	if !compose.exists() {
		return Err(BackupError::ComposeFileMissing(compose.to_path_buf()));
	}
	let compose_str = compose.to_string_lossy().into_owned();
	let host_str = host_path.to_string_lossy().into_owned();
	let dest = format!("db:{container_path}");
	let spec = CommandSpec::new(vec![
		"podup".to_string(),
		"-f".to_string(),
		compose_str,
		"cp".to_string(),
		host_str,
		dest,
	]);
	Ok(spec)
}
