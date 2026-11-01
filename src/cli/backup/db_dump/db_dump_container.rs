//! The container half of the database commands: the `podup exec` invocations
//! that dump and replay the database inside the `db` service, and the staged
//! copy of the SQL a restore hands to it. It lives in its own file to keep
//! `db_dump.rs` under the per-file code-line cap.

use std::path::{Path, PathBuf};

use crate::cli::init::{DATABASE_NAME, DATABASE_PASSWORD_FILE, DATABASE_USER};

use super::super::restore_signals::stop_if_arrived;
use super::db_dump_host_temp::{PREFIX, RestoreHostTemp, SQL_FILE_NAME, process_alive, staged_pid};
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

/// A `podup -f <compose> exec -T [-u root] db sh -c <script>` call. `root`
/// runs it as root in the container, which owns the staging directory and the
/// copy in it; otherwise it runs as the container's own user (`postgres`),
/// the only one that can read the mounted password.
fn db_sh_spec(compose: &Path, script: String, root: bool) -> Result<CommandSpec, BackupError> {
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
	if root {
		argv.extend(["-u".to_string(), "root".to_string()]);
	}
	argv.extend(["db", "sh", "-c"].map(String::from));
	argv.push(script);
	Ok(CommandSpec::new(argv))
}

/// The container-side `psql` invocation. `podup exec` does not forward
/// stdin before 5.15.0 (measured against `podup 5.10.13` and still true of
/// 5.14.0, where a script's non-terminal stdin is never attached), so the SQL is copied in
/// first through `podup cp <host> <svc>:<in_container_path>`, and then a
/// shell reads the secret into `PGPASSWORD` and execs `psql -1 -f` against
/// that path. It runs as the container user, because the password is mounted
/// readable by that user alone (mode 0400, and the container drops every
/// capability, so root cannot read it either). That user has to be able to
/// read the copy: `podup cp` keeps the mode (`0644`) and the numeric owner of
/// the host file, and that owner is nobody in the container, so the mode set
/// on the host before the copy is what lets it. The transaction
/// and `ON_ERROR_STOP` make replay atomic when a SQL statement fails. The
/// shell uses `exec psql` so a `SIGTERM` sent to the container's exec process
/// (an operator hitting Ctrl-C, a timeout, an aborted `podman exec`) reaches
/// `psql` itself and aborts the transaction. Cleanup of the in-container copy
/// lives in [`container_rm_temp_spec`] (host-side, since the wrapper shell is
/// gone), invoked from [`load_dump_container_with`] on both success and error.
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
		false,
	)
}

/// `podup -f <compose> exec -T -u root db sh -c "mkdir -m 711 <dir>"`. Makes
/// the staging directory the SQL copy lands in. Root makes it, so root owns
/// it and can remove it whoever the copy ends up belonging to, which the
/// container user could not do for a file that is not its own. The mode lets
/// the container user in to read the one file it is told about and nobody
/// list the directory. `mkdir` fails if the name exists, so a directory
/// somebody else made is never reused.
pub(crate) fn container_mkdir_spec(
	compose: &Path,
	in_container_dir: &str,
) -> Result<CommandSpec, BackupError> {
	db_sh_spec(compose, format!("mkdir -m 711 '{in_container_dir}'"), true)
}

/// `podup -f <compose> exec -T -u root db sh -c "rm -rf <dir>"`. Removes the
/// staging directory with the SQL from the `db` service after the restore
/// returns, whether the replay succeeded or failed. Root owns the directory,
/// so it may remove the file in it whoever owns that. Must run from the host
/// (`podup exec`) because the in-container shell that exec'd `psql` is no
/// longer around to trap a removal on its own exit.
pub(crate) fn container_rm_temp_spec(
	compose: &Path,
	in_container_dir: &str,
) -> Result<CommandSpec, BackupError> {
	db_sh_spec(compose, format!("rm -rf '{in_container_dir}'"), true)
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
			"{container_dir} in the db container ({why}); remove it with `podup exec -T -u root db rm -rf '{container_dir}'`, or restart db, since /tmp there is a tmpfs"
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
/// The SQL is staged to a host file made `0644` inside a directory
/// created `0700`, under a name unique to this call, so nothing but its owner
/// can enter the directory to read the credential hashes it carries (the module
/// comment of the host temp says why the file itself is `0644`) and two simultaneous restores
/// cannot clobber each other. The [`RestoreHostTemp`] guard removes it on
/// every exit path, including the error path and a panic. Inside the
/// container the file lands in a directory of the same unique name in the
/// `/tmp` tmpfs of the `db` service (private to that container), and the
/// directory is removed by a host-side `podup exec` once the replay completes
/// (success or error), unless it was never made. See [`container_mkdir_spec`],
/// [`container_psql_load_spec`] and [`container_rm_temp_spec`]. When a removal fails the error (or, if the
/// replay worked, a warning) says what was left and where. A restore killed by
/// a signal cannot clean up after itself, so the next one removes what it left
/// in the container ([`sweep_container`]).
pub(super) fn load_dump_container_with(
	compose: &Path,
	sql: &[u8],
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<(), BackupError> {
	sweep_container(compose, resolver);
	let mut host_temp = RestoreHostTemp::create()?;
	host_temp.write_all(sql)?;
	let in_container_dir = format!("/tmp/{}", host_temp.file_name()?);
	let in_container_path = format!("{in_container_dir}/{SQL_FILE_NAME}");
	let mut made = false;
	// A held stop signal ends the restore at the next of these checks, before
	// anything else is staged and never once `psql` has started.
	let result = (|| -> Result<(), BackupError> {
		stop_if_arrived()?;
		run_checked(&container_mkdir_spec(compose, &in_container_dir)?, resolver)?;
		made = true;
		stop_if_arrived()?;
		let cp = container_cp_into_spec(compose, host_temp.path(), &in_container_path)?;
		run_checked(&cp, resolver)?;
		stop_if_arrived()?;
		run_checked(
			&container_psql_load_spec(compose, &in_container_path, sql)?,
			resolver,
		)
	})();
	// The removals run even when the replay failed: with `exec psql` in the
	// replay shell, the wrapper shell is replaced by psql and any trap would
	// never fire on the psql exit path. Nothing is removed in the container
	// when its directory was never made: the name is not ours then.
	let container = if made {
		container_rm_temp_spec(compose, &in_container_dir)
			.and_then(|cleanup| run_checked(&cleanup, resolver))
	} else {
		Ok(())
	};
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

/// Remove the staging directories that a restore killed by a signal left in
/// the `db` container, which no guard could remove. A directory counts only if
/// its name carries the id of a process that is gone, so a restore running
/// now keeps its own. Each removal is reported with its path; a database that
/// is not running, or a listing that fails, is not an error here, since the
/// restore that follows says what is wrong.
fn sweep_container(compose: &Path, resolver: &dyn Fn(&str) -> Option<PathBuf>) {
	let Ok(list) = db_sh_spec(compose, "ls -1 /tmp".to_string(), true) else {
		return;
	};
	let Ok(output) = run_command_capturing_stdout_with(&list, resolver) else {
		return;
	};
	if !output.status_ok {
		return;
	}
	for name in String::from_utf8_lossy(&output.stdout).lines() {
		let abandoned = name.starts_with(PREFIX)
			&& name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
			&& staged_pid(name).is_some_and(|pid| !process_alive(pid));
		if !abandoned {
			continue;
		}
		let dir = format!("/tmp/{name}");
		let removed =
			container_rm_temp_spec(compose, &dir).and_then(|spec| run_checked(&spec, resolver));
		match removed {
			Ok(()) => crate::cli::style::warn(format!(
				"removed {dir} from the db container: an earlier restore was interrupted and left a copy of the SQL dump there"
			)),
			Err(_) => crate::cli::style::warn(format!(
				"{dir} in the db container holds a copy of the SQL dump an interrupted restore left; remove it with `podup exec -T -u root db rm -rf '{dir}'`"
			)),
		}
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
