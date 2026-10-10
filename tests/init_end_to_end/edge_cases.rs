//! Failure paths in the answer / config validation: an answers
//! file that disables a service but gets three independent
//! mistakes (hostname collision, private IPv4, relative data
//! dir) must exit 2 with every problem reported and no parent
//! directory created. The plan phase must exit 2 on an
//! unparseable existing config (nothing was touched). The
//! apply phase must tolerate a missing `openssl` by skipping
//! the RSA DKIM key step instead of failing outright.

use std::path::Path;
#[cfg(unix)]
use std::process::{Command, Stdio};

#[cfg(unix)]
use super::helpers::{binary, write_answers};

/// An answers file with three independent mistakes (hostname equal
/// to a domain, a private `public_ipv4`, and a relative `data_dir`)
/// must exit 2 with every problem reported in the same stderr
/// stream and no parent directory created.
#[cfg(unix)]
#[test]
fn invalid_answers_reports_every_problem_and_creates_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_path = dir.path().join("etc").join("mail.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"example.org\"\n\
		 domains = [\"example.org\"]\n\
		 public_ipv4 = \"10.0.0.1\"\n\
		 data_dir = \"relative/path\"\n\
		 config_path = \"{}\"\n\n\
		 [services]\n\
		 database = false\n",
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap()]);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("apply");
	assert_eq!(
		output.status.code(),
		Some(2),
		"invalid answers must exit 2; got {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	// hostname equals a domain, public_ipv4 is private, data_dir is relative.
	assert!(
		stderr.contains("hostname") && stderr.contains("domains"),
		"hostname/domain collision must be reported; stderr: {stderr}"
	);
	assert!(
		stderr.contains("public_ipv4"),
		"private public_ipv4 must be reported; stderr: {stderr}"
	);
	assert!(
		stderr.contains("data_dir") && stderr.contains("absolute"),
		"relative data_dir must be reported; stderr: {stderr}"
	);
	assert!(
		!config_path.parent().unwrap().exists(),
		"config parent must not be created on validation failure"
	);
}

/// The answers file is valid and validates fine, but an existing
/// config on disk is unparseable TOML. The plan step surfaces the
/// read failure with exit code 2: nothing was touched, and exit 2
/// now widens to mean exactly that (invalid answers or a
/// precondition that stopped the run before any effect).
#[test]
fn init_exits_two_when_plan_fails_on_an_unparseable_existing_config() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	std::fs::create_dir_all(config_path.parent().unwrap()).expect("mkdir etc");
	std::fs::write(&config_path, "this is not = valid TOML\tbroken\n")
		.expect("write unparseable config");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod");
	}
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\n\
		 [services]\n\
		 database = false\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap()]);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert_eq!(
		output.status.code(),
		Some(2),
		"plan failure must surface as exit code 2 (nothing was touched); got {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("read"),
		"plan failure must name the read operation: {stderr}"
	);
	assert!(
		!data_dir.exists(),
		"plan failure must not create the data_dir: {}",
		data_dir.display()
	);
}

/// With PATH pointing at an empty directory, the apply phase must
/// NOT fail just because openssl is missing. The RSA DKIM key step
/// goes through its skip branch and the rest of the apply runs.
#[cfg(unix)]
#[test]
fn init_skips_the_rsa_dkim_step_when_openssl_is_absent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let empty_path = dir.path().join("empty-bin");
	std::fs::create_dir(&empty_path).expect("mkdir empty-bin");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\n\
		 [services]\n\
		 database = false\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap()]);
	cmd.env("PATH", &empty_path);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(
		output.status.success(),
		"apply must succeed even without openssl; exit: {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("skipped:") && stderr.contains("dkim rsa key"),
		"report must record the RSA key as skipped; stderr: {stderr}"
	);
	assert!(
		!Path::new(&data_dir.join("keys").join("s2.pem")).exists(),
		"s2.pem must not be written when openssl is absent"
	);
}
