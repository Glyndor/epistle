//! The container half of the database commands: the `podup exec` invocations
//! that dump and replay the database inside the `db` service, and the staged
//! copy of the SQL a restore hands to it. It lives in its own file to keep
//! `db_dump.rs` under the per-file code-line cap.

use std::path::{Path, PathBuf};

use crate::cli::init::{DATABASE_NAME, DATABASE_PASSWORD_FILE, DATABASE_USER};

use super::db_dump_host_temp::{RestoreHostTemp, SQL_FILE_NAME};
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

/// A `podup -f <compose> exec -T db sh -c <script>` call, run as the
/// container's own user (`postgres`).
fn db_sh_spec(compose: &Path, script: String) -> Result<CommandSpec, BackupError> {
	if !compose.exists() {
		return Err(BackupError::ComposeFileMissing(compose.to_path_buf()));
	}
	Ok(CommandSpec::new(vec![
		"podup".to_string(),
		"-f".to_string(),
		compose.to_string_lossy().into_owned(),
		"exec".to_string(),
		"-T".to_string(),
		"db".to_string(),
		"sh".to_string(),
		"-c".to_string(),
		script,
	]))
}

/// The container-side `psql` invocation. `podup exec` does not forward
/// stdin (measured against `podup 5.10.13` and still true of 5.14.0, where a
/// script's non-terminal stdin is never attached), so the SQL is copied in
/// first through `podup cp <host> <svc>:<in_container_path>`, and then a
/// shell reads the secret into `PGPASSWORD` and execs `psql -1 -f` against
/// that path. The file holds the credential hashes of every account, and
/// neither its owner nor its mode after `podup cp` can be relied on (podman
/// 5.4 leaves the host owner and a umask mode; later ones leave the
/// container user), so the replay does not try to change them: the copy
/// sits in a directory made `0700` by the container user
/// ([`container_mkdir_spec`]), which keeps everyone else out whatever the
/// file looks like. The transaction and `ON_ERROR_STOP` make replay atomic
/// when a SQL statement fails. The shell uses `exec psql` so a `SIGTERM`
/// sent to the container's exec process (an operator hitting Ctrl-C, a
/// timeout, an aborted `podman exec`) reaches `psql` itself and aborts the
/// transaction. Cleanup of the in-container copy lives in
/// [`container_rm_temp_spec`] (host-side, since the wrapper shell is gone),
/// invoked from [`load_dump_container_with`] on both success and error.
pub(crate) fn container_psql_load_spec(
	compose: &Path,
	in_container_path: &str,
	_sql: &[u8],
) -> Result<CommandSpec, BackupError> {
	db_sh_spec(
		compose,
		format!(
			r#"PGPASSWORD="$(cat '{DATABASE_PASSWORD_FILE}')" exec psql -v ON_ERROR_STOP=1 -1 -X -f '{path}' -h '/var/run/postgresql' -U '{DATABASE_USER}' -d '{DATABASE_NAME}'"#,
			path = in_container_path,
		),
	)
}

/// `podup -f <compose> exec -T db sh -c "mkdir -m 700 <dir>"`. Makes the
/// private directory the SQL copy lands in. It runs as the container user,
/// who therefore owns the directory and can later remove whatever `podup
/// cp` put in it, whoever that file ends up owned by. `mkdir` fails if the
/// name exists, so a directory somebody else made is never reused.
pub(crate) fn container_mkdir_spec(
	compose: &Path,
	in_container_dir: &str,
) -> Result<CommandSpec, BackupError> {
	db_sh_spec(compose, format!("mkdir -m 700 '{in_container_dir}'"))
}

/// `podup -f <compose> exec -T db sh -c "rm -rf <dir>"`. Removes the
/// private directory with the staged SQL from the `db` service after the
/// restore returns, whether the replay succeeded or failed. The container
/// user owns the directory, so it may remove the file in it even when `podup
/// cp` left the file owned by somebody else, which a `rm` of the bare file
/// in the sticky `/tmp` could not. Must run from the host (`podup exec`)
/// because the in-container shell that exec'd `psql` is no longer around to
/// trap a removal on its own exit.
pub(crate) fn container_rm_temp_spec(
	compose: &Path,
	in_container_dir: &str,
) -> Result<CommandSpec, BackupError> {
	db_sh_spec(compose, format!("rm -rf '{in_container_dir}'"))
}

/// Load the SQL into the database through the container path. The
/// `podup cp` happens in `copy_sql_into_container`, then the `psql`
/// exec is run. The two-step is exposed as one function so the caller
/// stays linear.
#[allow(dead_code)]
pub(crate) fn load_dump_container(compose: &Path, sql: &[u8]) -> Result<(), BackupError> {
	load_dump_container_with(compose, sql, &default_program_resolver)
}

/// Run one `podup` call and turn a non-zero exit into a [`BackupError`].
fn run_checked(
	spec: &CommandSpec,
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<(), BackupError> {
	let output = run_command_capturing_stdout_with(spec, resolver)?;
	if output.status_ok {
		Ok(())
	} else {
		Err(BackupError::CommandFailed {
			stderr: output.stderr.trim().to_string(),
			code: output.code,
		})
	}
}

/// What a restore could not remove, in words an operator can act on, or
/// `None` when nothing is left. `container` is the outcome of the removal in
/// the `db` service, `host` the one on the host. The dump holds the
/// credential hashes of every account, so each line says where it still is.
pub(super) fn leftover_note(
	container: Result<(), BackupError>,
	container_dir: &str,
	host: Result<(), String>,
) -> Option<String> {
	let mut parts = Vec::new();
	if let Err(error) = container {
		let why = match error {
			BackupError::CommandFailed { stderr, .. } if !stderr.is_empty() => stderr,
			other => format!("{other:?}"),
		};
		parts.push(format!(
			"{container_dir} in the db container ({why}); remove it with `podup exec -T db rm -rf '{container_dir}'`, or restart db, since /tmp there is a tmpfs"
		));
	}
	if let Err(place) = host {
		parts.push(format!("{place}; remove it by hand"));
	}
	(!parts.is_empty()).then(|| {
		format!(
			"the SQL dump, which holds account credential hashes, was left at {}",
			parts.join(" and at ")
		)
	})
}

/// Same as [`load_dump_container`] with a custom program resolver. The
/// host-temp write happens before any spawn, so it stays unchanged
/// between the production path and the test path.
///
/// The SQL is staged to a host file created `0600` inside a directory
/// created `0700`, under a name unique to this call, so nothing but its owner
/// can read the credential hashes it carries and two simultaneous restores
/// cannot clobber each other. The [`RestoreHostTemp`] guard removes it on
/// every exit path, including the error path and a panic. Inside the
/// container the file lands in a `0700` directory of the same unique name in
/// the `/tmp` tmpfs of the `db` service (private to that container), and the
/// directory is removed by a host-side `podup exec` once the replay completes
/// (success or error); see [`container_mkdir_spec`],
/// [`container_psql_load_spec`] and [`container_rm_temp_spec`]. When a removal
/// fails the error (or, if the replay worked, a warning) says what was left
/// and where.
pub(super) fn load_dump_container_with(
	compose: &Path,
	sql: &[u8],
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<(), BackupError> {
	let mut host_temp = RestoreHostTemp::create()?;
	host_temp.write_all(sql)?;
	let in_container_dir = format!("/tmp/{}", host_temp.file_name());
	let in_container_path = format!("{in_container_dir}/{SQL_FILE_NAME}");
	let result = (|| -> Result<(), BackupError> {
		run_checked(&container_mkdir_spec(compose, &in_container_dir)?, resolver)?;
		let cp = container_cp_into_spec(compose, host_temp.path(), &in_container_path)?;
		run_checked(&cp, resolver)?;
		run_checked(
			&container_psql_load_spec(compose, &in_container_path, sql)?,
			resolver,
		)
	})();
	// The removals run even when the replay failed: with `exec psql` in the
	// replay shell, the wrapper shell is replaced by psql and any trap would
	// never fire on the psql exit path.
	let container = container_rm_temp_spec(compose, &in_container_dir)
		.and_then(|cleanup| run_checked(&cleanup, resolver));
	let host = host_temp.remove();
	drop(host_temp);
	match (result, leftover_note(container, &in_container_dir, host)) {
		(Ok(()), None) => Ok(()),
		(Ok(()), Some(note)) => {
			crate::cli::style::warn(note);
			Ok(())
		}
		(Err(BackupError::CommandFailed { stderr, code }), Some(note)) => {
			Err(BackupError::CommandFailed {
				stderr: format!("{stderr}; {note}"),
				code,
			})
		}
		(Err(error), _) => Err(error),
	}
}

/// `podup -f <compose> cp <host> db:/tmp/...`, copy the SQL file from
/// the host temp path into the `db` container. podup's `cp` requires the
/// target to be writable inside the container; the private directory made
/// in the `/tmp` tmpfs of the `db` service is.
pub(crate) fn container_cp_into_spec(
	compose: &Path,
	host_path: &Path,
	container_path: &str,
) -> Result<CommandSpec, BackupError> {
	if !compose.exists() {
		return Err(BackupError::ComposeFileMissing(compose.to_path_buf()));
	}
	Ok(CommandSpec::new(vec![
		"podup".to_string(),
		"-f".to_string(),
		compose.to_string_lossy().into_owned(),
		"cp".to_string(),
		host_path.to_string_lossy().into_owned(),
		format!("db:{container_path}"),
	]))
}
