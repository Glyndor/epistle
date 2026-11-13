//! Spawn a [`CommandSpec`] as a child process and capture what it printed.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::cli::backup::restore_signals::spawn_apart;

use super::{BackupError, CommandSpec};

/// The output of a child process: stdout, stderr and a flag for the exit
/// status. The flag is set from the raw status; the integer code is kept
/// alongside it for the error path so the message can name it.
pub(crate) struct CapturedOutput {
	pub(super) stdout: Vec<u8>,
	pub(super) stderr: String,
	pub(super) status_ok: bool,
	pub(super) code: Option<i32>,
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
pub(super) fn run_command_capturing_stdout_with(
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
	if spawn_apart() {
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
