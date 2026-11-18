//! Why a backup or restore step on the database failed, worded so the message
//! never carries the password or the SQL bytes.

use std::path::PathBuf;

use crate::cli::backup::restore_signals::signal_name;

/// Why a backup or restore step on the database could not be completed. The
/// variant names the concrete cause: the binary is missing, the connection
/// refused, the binary exited non-zero, or the produced SQL is empty. Every
/// variant renders without a password or a SQL fragment; a `Display` of the
/// error does not leak the secret the operator typed into `password_file`.
#[derive(Debug)]
pub enum BackupError {
	/// The host-side `pg_dump` (or `psql`) binary is not on `PATH`. The host
	/// path is the only branch this surfaces: the container path is `podup
	/// exec`, which fails with its own stderr text on a missing image.
	BinaryMissing(String),
	/// The spawned process started but exited non-zero. Carries the captured
	/// stderr (already trimmed) and the exit status; the host and the
	/// container paths feed this variant.
	CommandFailed {
		/// The trim of the child's stderr; the password is never on this
		/// surface (the password is in `PGPASSWORD`, not argv).
		stderr: String,
		/// The exit code the child reported; `None` when the child was
		/// killed by a signal.
		code: Option<i32>,
	},
	/// The dump file the command produced is empty. PostgreSQL writes the
	/// schema with `CREATE TABLE` even on an empty database, so an empty
	/// payload is a clear sign the dump was cut short: the connection
	/// dropped, the timeout fired, or the binary was wrong.
	EmptyOutput,
	/// The dump tool exited with status 0 but its output is missing the
	/// closing marker pg_dump writes on a successful run. The capture
	/// itself may have failed (a dropped `podman exec` pipe, a truncated
	/// file on a shared mount), or pg_dump was substituted by something
	/// that does not emit the marker. Either way, the bytes are not a
	/// complete dump and would only be discovered as missing rows at
	/// restore time, so the run refuses the archive.
	TruncatedDump,
	/// The compose file is missing for the container path. Reported only
	/// when a database is configured and the call site chose the container
	/// path because the file existed at decision time and disappeared by
	/// execution time. The companion `data_dir` is reported so the
	/// operator can verify what was expected.
	ComposeFileMissing(PathBuf),
	/// The SQL copy `podup cp` produces ended up empty (the copy itself
	/// failed silently). The path inside the container is reported so the
	/// operator can re-run `podup exec -T db ls <path>` to confirm.
	#[allow(dead_code)]
	ContainerFileMissing(PathBuf),
	/// A held stop signal (the number) came before the restore wrote the
	/// database or the files, so it stopped without writing either.
	Interrupted(i32),
	/// A compose stack is present but `[database] url` is not the stack's own
	/// database, so the stack's dump and replay would act on a different
	/// database from the configured one.
	DatabaseNotInStack,
}

impl std::fmt::Display for BackupError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			BackupError::BinaryMissing(binary) => {
				write!(
					f,
					"{binary} was not found on PATH; install postgresql-client (or the matching server package) so the backup can read the database"
				)
			}
			BackupError::CommandFailed { stderr, code } => match code {
				Some(code) => write!(f, "the dump tool exited with status {code}: {stderr}"),
				None => write!(f, "the dump tool was killed by a signal: {stderr}"),
			},
			BackupError::EmptyOutput => write!(
				f,
				"the dump tool produced no output; the connection may have dropped mid-stream or the database is empty and the tool refused to dump it"
			),
			BackupError::TruncatedDump => write!(
				f,
				"the dump tool exited cleanly but its output does not end with the pg_dump closing marker; the dump was cut short (truncated pipe, partial copy) and was refused"
			),
			BackupError::ComposeFileMissing(path) => write!(
				f,
				"compose file {} was expected (the container stack path was selected) but is gone; run `epistle init` to lay it down again",
				path.display()
			),
			BackupError::ContainerFileMissing(path) => write!(
				f,
				"the SQL file copied into the container at {} is missing; podup cp reported success but the file is not visible to the exec'd psql",
				path.display()
			),
			BackupError::Interrupted(signal) => write!(
				f,
				"stopped by {} before the database or the files were written",
				signal_name(*signal)
			),
			BackupError::DatabaseNotInStack => write!(
				f,
				"a compose stack is present, but [database] url is not the stack's database (postgres://epistle@%2Frun%2Fpostgresql/epistle), so the backup and the restore would act on the stack's database instead of the configured one; point url at the stack, or move the compose directory away if the database is external"
			),
		}
	}
}

impl std::error::Error for BackupError {}
