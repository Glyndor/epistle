//! The database half of `epistle backup` and `epistle restore`.
//!
//! This module owns:
//!
//! - [`BackupError`] and its `Display` impl. The variants name the
//!   concrete failure cause (binary missing, command failed, empty
//!   output, compose file missing) and never carry the password or
//!   the SQL bytes themselves; an operator looking at the error
//!   does not see the secret they typed into `password_file`.
//! - [`CommandSpec`], the pure data struct that captures one process
//!   invocation (argv, environment additions, stdin payload). The
//!   tests inspect it for the password-leak invariant; the runtime
//!   hands it to `Command::new`.
//! - The host-side spec builders ([`host_pg_dump_spec`],
//!   [`host_psql_load_spec`]) and the container-side ones
//!   ([`container_pg_dump_spec`], [`container_psql_load_spec`],
//!   [`container_cp_into_spec`]). The two halves share the
//!   invariant that the password never appears in argv; the host
//!   path uses `PGPASSWORD` env, and the container shell reads the
//!   mounted secret into `PGPASSWORD` before executing the client.
//! - The actual spawn-and-capture path. A `program_resolver` lets
//!   the test path point at a stub in a tempdir without mutating
//!   the process `PATH` (which would race other parallel tests).
//!
//! The split keeps `mod.rs` focused on the archive builder and
//! the data_dir walk; the database code here is the only place
//! that needs to know about `podup exec`, `pg_dump`, and
//! `psql`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cli::init::compose_file_path;
use crate::config::Database;

#[path = "db_dump_container.rs"]
mod db_dump_container;
#[path = "db_dump_host_temp.rs"]
mod db_dump_host_temp;
#[path = "db_dump_marker.rs"]
mod db_dump_marker;

use db_dump_container::load_dump_container_with;
pub(crate) use db_dump_container::{
	container_cp_into_spec, container_pg_dump_spec, container_psql_load_spec, load_dump_container,
};
#[cfg(test)]
use db_dump_container::{container_rm_temp_spec, leftover_note};
#[cfg(test)]
use db_dump_host_temp::{RestoreHostTemp, SQL_FILE_NAME};
pub(in crate::cli::backup) use db_dump_marker::output_ends_with_pg_dump_complete;

#[cfg(test)]
#[path = "db_dump_tests_debug.rs"]
mod tests_debug;

#[cfg(test)]
#[path = "db_dump_tests_clean.rs"]
mod tests_clean;

#[cfg(test)]
#[path = "db_dump_tests_a4_status.rs"]
mod tests_a4_status;

#[cfg(test)]
#[path = "db_dump_tests_a4_tempfile.rs"]
mod tests_a4_tempfile;

#[cfg(test)]
#[path = "db_dump_tests_staging.rs"]
mod tests_staging;

#[cfg(test)]
#[path = "db_dump_tests_signal.rs"]
mod tests_signal;

/// The path of `database.sql` inside the backup archive.
pub(crate) const DATABASE_SQL_NAME: &str = "database.sql";

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
				super::restore_signals::signal_name(*signal)
			),
		}
	}
}

impl std::error::Error for BackupError {}

/// A process invocation as a list of arguments and environment additions.
/// Kept as plain data so the tests can inspect what would be run without
/// spawning anything. Host passwords live in `env`; container passwords
/// are loaded by the container shell and never reach the host process.
/// `argv` is what the kernel would publish through `/proc/<pid>/cmdline`,
/// so a test that walks `argv` and finds the secret anywhere there is a
/// regression we want to catch.
#[derive(Clone, PartialEq, Eq)]
pub struct CommandSpec {
	argv: Vec<String>,
	env: Vec<(String, String)>,
	stdin_payload: Option<Vec<u8>>,
}

impl std::fmt::Debug for CommandSpec {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let env: Vec<_> = self
			.env
			.iter()
			.map(|(key, _)| (key, "<redacted>"))
			.collect();
		f.debug_struct("CommandSpec")
			.field("argv", &self.argv)
			.field("env", &env)
			.field("stdin_len", &self.stdin_payload.as_ref().map(Vec::len))
			.finish()
	}
}

impl CommandSpec {
	fn new(argv: Vec<String>) -> Self {
		Self {
			argv,
			env: Vec::new(),
			stdin_payload: None,
		}
	}

	fn with_env(mut self, key: &str, value: &str) -> Self {
		self.env.push((key.to_string(), value.to_string()));
		self
	}

	fn with_stdin(mut self, payload: Vec<u8>) -> Self {
		self.stdin_payload = Some(payload);
		self
	}

	/// The argv the kernel would publish through `/proc/<pid>/cmdline`. The
	/// test on the password-leak path walks this slice; the runtime path
	/// hands it to `Command::new(argv[0]).args(&argv[1..])`.
	pub(super) fn argv(&self) -> &[String] {
		&self.argv
	}

	/// The environment additions the spec applies to the inherited
	/// environment. Inherited values are passed through; only the
	/// additions in this list are guaranteed visible.
	pub(super) fn env(&self) -> &[(String, String)] {
		&self.env
	}

	/// The bytes piped to the child's stdin when the spec is run, if any.
	pub(super) fn stdin_payload(&self) -> Option<&[u8]> {
		self.stdin_payload.as_deref()
	}
}

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
		load_dump_container_with(&compose_file_path(data_dir), sql, resolver)
	} else {
		let spec = host_psql_load_spec(db, sql)?;
		super::restore_signals::stop_if_arrived()?;
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
		container_psql_load_spec(&compose, in_container_path, sql)
	} else {
		host_psql_load_spec(db, sql)
	}
}

/// The host-side `pg_dump` invocation. Reads the URL, strips the password
/// if it is in userinfo, and sets `PGPASSWORD` from the URL or from
/// `password_file` (the latter only when the file is readable; the
/// validator already ran, so an unreadable file here surfaces as a
/// password-file I/O error). The argv is `pg_dump <url-without-password>`
/// plus the format flags; the secret never sits in argv.
pub(crate) fn host_pg_dump_spec(db: &Database) -> Result<CommandSpec, BackupError> {
	let (url_without_password, url_password) = split_url_password(&db.url);
	let password = match url_password {
		Some(p) => Some(p),
		None => read_password_from_file(db)?,
	};
	let mut spec = CommandSpec::new(vec![
		"pg_dump".to_string(),
		"-Fp".to_string(),
		"--clean".to_string(),
		"--if-exists".to_string(),
		"--no-owner".to_string(),
		"--no-privileges".to_string(),
		url_without_password,
	]);
	if let Some(password) = password {
		spec = spec.with_env("PGPASSWORD", &password);
	}
	Ok(spec)
}

/// The host-side `psql` invocation for replay. The SQL is fed on stdin
/// because `psql` reads it that way without a temp file. The password is
/// applied through `PGPASSWORD` exactly as `pg_dump` does.
pub(crate) fn host_psql_load_spec(db: &Database, sql: &[u8]) -> Result<CommandSpec, BackupError> {
	let (url_without_password, url_password) = split_url_password(&db.url);
	let from_file = url_password.is_none();
	let password = match url_password {
		Some(p) => Some(p),
		None => read_password_from_file(db)?,
	};
	let mut argv = vec![
		"psql".to_string(),
		"-v".to_string(),
		"ON_ERROR_STOP=1".to_string(),
		"-1".to_string(),
		"-X".to_string(),
	];
	// When the password comes from `password_file`, psql would otherwise
	// prompt on the missing-password URL; pass `--no-password` so it
	// reads `PGPASSWORD` and falls through. With the URL carrying the
	// password already, psql parses it itself and we leave the flag off.
	if from_file && password.is_some() {
		argv.push("--no-password".to_string());
	}
	argv.push(url_without_password);
	let mut spec = CommandSpec::new(argv).with_stdin(sql.to_vec());
	if let Some(password) = password {
		spec = spec.with_env("PGPASSWORD", &password);
	}
	Ok(spec)
}

/// The output of a child process: stdout, stderr and a flag for the exit
/// status. The flag is set from the raw status; the integer code is kept
/// alongside it for the error path so the message can name it.
pub(crate) struct CapturedOutput {
	stdout: Vec<u8>,
	stderr: String,
	status_ok: bool,
	code: Option<i32>,
}

impl CapturedOutput {
	fn from_status(output: std::process::Output) -> Self {
		Self {
			stdout: output.stdout,
			stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
			status_ok: output.status.success(),
			code: output.status.code(),
		}
	}
}

/// Spawn the spec as a child process, capture its stdout and stderr, and
/// return the captured output. The child's stdin is fed
/// `spec.stdin_payload()` when one is set. A missing binary surfaces as
/// `BackupError::BinaryMissing`; everything else is `BackupError::CommandFailed`
/// with the child's stderr attached.
///
/// `program_resolver` maps the spec's `argv[0]` to the actual path the
/// child is spawned as. Production passes the default resolver, which
/// uses the literal `argv[0]` and lets `Command::new` resolve through
/// `PATH` exactly as `std::process::Command` always has. Tests pass a
/// resolver that returns an absolute path to a stub in a tempdir, which
/// is the only way to swap the binary under test without racing other
/// parallel tests that share the process-wide `PATH`.
#[allow(dead_code)]
pub(crate) fn run_command_capturing_stdout(
	spec: &CommandSpec,
) -> Result<CapturedOutput, BackupError> {
	run_command_capturing_stdout_with(spec, &default_program_resolver)
}

/// Same as [`run_command_capturing_stdout`], but with an injected
/// resolver. The resolver is a function pointer, not a trait object,
/// because the function is called once per spawn and the overhead of
/// dynamic dispatch is wasted on a hot loop. Two test paths use it:
/// the `pg_dump`/`psql` stubs that the host-path tests install in
/// tempdirs, and the `podup` shim that the container-path tests
/// install the same way.
fn run_command_capturing_stdout_with(
	spec: &CommandSpec,
	resolver: &dyn Fn(&str) -> Option<PathBuf>,
) -> Result<CapturedOutput, BackupError> {
	let Some((program, args)) = spec.argv().split_first() else {
		return Err(BackupError::CommandFailed {
			stderr: "command spec has no argv".to_string(),
			code: None,
		});
	};
	let resolved = resolver(program).unwrap_or_else(|| PathBuf::from(program));
	let mut command = Command::new(&resolved);
	command.args(args);
	for (key, value) in spec.env() {
		command.env(key, value);
	}
	if spec.stdin_payload().is_some() {
		command.stdin(Stdio::piped());
	} else {
		command.stdin(Stdio::null());
	}
	command.stdout(Stdio::piped());
	command.stderr(Stdio::piped());
	if super::restore_signals::spawn_apart() {
		std::os::unix::process::CommandExt::process_group(&mut command, 0);
	}
	let mut child = match command.spawn() {
		Ok(child) => child,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			return Err(BackupError::BinaryMissing(program.clone()));
		}
		Err(error) => {
			return Err(BackupError::CommandFailed {
				stderr: format!("cannot spawn {program}: {error}"),
				code: None,
			});
		}
	};
	// The payload goes in on its own thread while the output is drained: a
	// child that answers before it has read everything (a large dump, a
	// `psql` that prints as it goes) would otherwise fill its stdout pipe
	// while this thread is still blocked writing its stdin.
	let output = std::thread::scope(|scope| {
		if let Some(payload) = spec.stdin_payload()
			&& let Some(mut stdin) = child.stdin.take()
		{
			scope.spawn(move || {
				let _ = stdin.write_all(payload);
			});
		}
		child.wait_with_output()
	});
	let output = match output {
		Ok(output) => output,
		Err(error) => {
			return Err(BackupError::CommandFailed {
				stderr: format!("waiting on {program} failed: {error}"),
				code: None,
			});
		}
	};
	Ok(CapturedOutput::from_status(output))
}

/// Resolve a spec's program name to the path that `Command::new` should
/// actually use. Production runs leave this as the default, which keeps
/// the same `PATH` resolution behaviour `std::process::Command` has had
/// since the start; tests override the resolver to point at a stub
/// in a tempdir.
pub(crate) fn default_program_resolver(program: &str) -> Option<PathBuf> {
	if std::path::Path::new(program).components().count() > 1 {
		Some(PathBuf::from(program))
	} else {
		None
	}
}

/// Read the password from `[database] password_file` when set. Returns
/// `None` when the field is unset. The read goes through
/// `crate::db::read_password_file_contents`, the same helper the pool
/// constructor and `Config::validate_database` use; reusing it keeps
/// the trailing-line-ending strip and the empty-secret refusal in one
/// place, so a path that passes the validator and the connect call
/// passes this one too.
fn read_password_from_file(db: &Database) -> Result<Option<String>, BackupError> {
	let Some(path) = &db.password_file else {
		return Ok(None);
	};
	match crate::db::read_password_file_contents(path) {
		Ok(password) => Ok(Some(password)),
		Err(kind) => Err(BackupError::CommandFailed {
			stderr: format!("[database] password_file {}: {kind}", path.display()),
			code: None,
		}),
	}
}

/// Split a libpq URL into the URL-without-password and the password
/// itself. The percent-decoded password is returned next to the
/// password-less URL so the caller can apply it through `PGPASSWORD`.
/// The userinfo form (`postgres://user:pass@host/db`) and the
/// query-parameter form (`postgres://?password=pass`) are both
/// handled. Other query parameters are preserved so a `sslmode=require`
/// or `application_name=epistle` survives the round-trip. A URL that
/// does not parse is returned unchanged with no password; the caller's
/// spawn will surface the URL error.
pub fn split_url_password(url: &str) -> (String, Option<String>) {
	let Ok(mut parsed) = url::Url::parse(url) else {
		return (url.to_string(), None);
	};
	let userinfo_password = parsed.password().map(|encoded| {
		percent_encoding::percent_decode_str(encoded)
			.decode_utf8_lossy()
			.into_owned()
	});
	if userinfo_password.is_some() {
		let _ = parsed.set_password(None);
	}
	let query_password = {
		let mut kept: Vec<(String, String)> = Vec::new();
		let mut password: Option<String> = None;
		for (key, value) in parsed.query_pairs() {
			if key == "password" {
				password = Some(value.into_owned());
			} else {
				kept.push((key.into_owned(), value.into_owned()));
			}
		}
		if password.is_some() {
			parsed.query_pairs_mut().clear();
			for (key, value) in &kept {
				parsed.query_pairs_mut().append_pair(key, value);
			}
		}
		password
	};
	let password = userinfo_password.or(query_password);
	(parsed.to_string(), password)
}
