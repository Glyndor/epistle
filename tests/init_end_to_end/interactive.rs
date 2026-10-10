//! Interactive-assistant scenarios: the prompt loop and the
//! confirmation prompt. The assistant surfaces a truncated
//! read mid-questions as a typed assistant error and `mod::run`
//! maps it to exit code 2; the operator confirms with `n` (or an
//! empty line, the default) and the run exits 0 with nothing on
//! disk.

#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::process::{Command, Stdio};

#[cfg(unix)]
use super::helpers::{binary, data_dir_is_clean};

/// Feed enough answers for the assistant to reach the data_dir
/// question and then close stdin: the assistant must surface the
/// truncated read as an error, mod::run must map it to exit code 2,
/// and nothing may have been written to disk.
#[cfg(unix)]
#[test]
fn interactive_run_exits_2_when_stdin_eofs_mid_questions() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut cmd = Command::new(binary());
	cmd.arg("init");
	cmd.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let mut child = cmd.spawn().expect("spawn epistle");
	child
		.stdin
		.take()
		.expect("stdin pipe")
		.write_all(
			b"manual\n\
			  mail.example.org\n\
			  example.org\n\n\
			  \n\
			  \n",
		)
		.expect("write stdin");
	let output = child.wait_with_output().expect("wait epistle");
	assert_eq!(
		output.status.code(),
		Some(2),
		"EOF mid-questions must surface as exit code 2; got {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	data_dir_is_clean(dir.path());
}

/// The assistant fills the answers, the operator answers "n" to
/// "Continue? [y/N]", and `epistle init` must exit 0 with nothing
/// on disk. The default answer (empty) takes the same path.
#[cfg(unix)]
#[test]
fn interactive_run_exits_0_when_user_declines_confirmation() {
	for answer in ["n", ""] {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut cmd = Command::new(binary());
		cmd.arg("init");
		cmd.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped());
		let mut child = cmd.spawn().expect("spawn epistle");
		child
			.stdin
			.take()
			.expect("stdin pipe")
			.write_all(
				format!(
					"manual\n\
					 mail.example.org\n\
					 example.org\n\n\
					 \n\
					 \n\
					 /tmp/{name}/data\n\
					 /tmp/{name}/etc/mail.toml\n\
					 \n\
					 \n\
					 \n\
					 \n\
					 \n\
					 \n\
					 \n\
					 \n\
					 {answer}\n",
					name = dir.path().file_name().unwrap().to_string_lossy(),
					answer = answer,
				)
				.as_bytes(),
			)
			.expect("write stdin");
		let output = child.wait_with_output().expect("wait epistle");
		assert_eq!(
			output.status.code(),
			Some(0),
			"answer {:?} to Continue? must surface as exit code 0; got {:?}; stderr: {}",
			answer,
			output.status,
			String::from_utf8_lossy(&output.stderr)
		);
		data_dir_is_clean(dir.path());
	}
}
