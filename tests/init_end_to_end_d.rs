//! End-to-end integration tests for findings 11, 12 and 13 of the
//! outside review of the binary:
//!
//! - 11: the identical-config shortcut must validate the existing
//!   config through `Config::load` before claiming it is identical,
//!   so an operator with an existing config that `config-check`
//!   would refuse (loose permissions, an unknown top-level key, a
//!   missing `${VAR}` reference) cannot get a green run from
//!   `epistle init` while `epistle config-check` and `epistle serve`
//!   would reject the same file;
//!
//! - 12: a Unicode hostname passes `Answers::validate` but panics
//!   in the certificate builder with `InvalidAsn1String`. The
//!   shared validator must refuse U-labels and surface the required
//!   ASCII spelling before any effect, exactly the way `services.api`
//!   is refused today;
//!
//! - 13: the interactive assistant must repeat a semantically
//!   invalid answer (a public IPv4 from the loopback range, a
//!   relative data path, a duplicate domain, a wrong-family IP)
//!   the same way it already repeats a syntactically broken one,
//!   instead of collecting every error at the end.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn binary() -> &'static Path {
	Path::new(env!("CARGO_BIN_EXE_epistle"))
}

fn write_answers(dir: &Path, name: &str, body: &str) -> PathBuf {
	let path = dir.join(name);
	std::fs::write(&path, body).expect("write answers");
	path
}

fn manual_answers(_dir: &Path, data_dir: &Path, config_path: &Path, hostname: &str) -> String {
	format!(
		"mode = \"manual\"\n\
		 hostname = \"{hostname}\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
		data_dir.display(),
		config_path.display(),
	)
}

/// Finding 11 (permissions): when the existing config has been
/// loosened to mode 0644 by an operator, `epistle init` must NOT
/// claim it is identical and exit 0, because `config-check` would
/// reject the same file. The apply phase must refuse and surface
/// the validation failure instead of regenerating keys or
/// silently rewriting the file.
#[cfg(unix)]
#[test]
fn init_refuses_when_existing_config_has_insecure_permissions() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let body = manual_answers(dir.path(), &data_dir, &config_path, "mail.example.org");
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let first = {
		let mut cmd = Command::new(binary());
		cmd.args(["init", "--answers", answers.to_str().unwrap()]);
		cmd.stdin(Stdio::null())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped());
		cmd.output().expect("spawn epistle")
	};
	assert!(
		first.status.success(),
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&first.stderr)
	);
	// Operator loosens the file to mode 0644 after the first run.
	let s1_path = data_dir.join("keys").join("s1.pem");
	let before_s1_mtime = std::fs::metadata(&s1_path)
		.expect("stat s1.pem")
		.modified()
		.expect("mtime");
	std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o644))
		.expect("chmod 0644");
	let second = {
		let mut cmd = Command::new(binary());
		cmd.args(["init", "--answers", answers.to_str().unwrap()]);
		cmd.stdin(Stdio::null())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped());
		cmd.output().expect("spawn epistle")
	};
	assert_eq!(
		second.status.code(),
		Some(2),
		"init must exit 2 on an existing invalid config (nothing was touched; the plan phase surfaces the refusal before any effect); stderr: {}",
		String::from_utf8_lossy(&second.stderr)
	);
	let stderr = String::from_utf8_lossy(&second.stderr);
	assert!(
		stderr.contains("group/world-accessible"),
		"stderr must name the permissions problem: {stderr}"
	);
	assert!(
		!stderr.contains("identical, not touched"),
		"the plan must NOT call the invalid config identical: {stderr}"
	);
	// The mtime of every secret on disk must be unchanged from
	// the first run: refusing an invalid existing config must not
	// silently regenerate keys.
	let after_s1_mtime = std::fs::metadata(&s1_path)
		.expect("stat s1.pem")
		.modified()
		.expect("mtime");
	assert_eq!(
		after_s1_mtime, before_s1_mtime,
		"s1.pem must not have been rewritten when the existing config is invalid"
	);
}

/// Finding 11 (unknown key): when the existing config carries a
/// top-level key the schema rejects with `deny_unknown_fields`,
/// `epistle init` must NOT silently rewrite the file and strip the
/// operator's addition. config-check refuses this file; init must
/// refuse with a clear diagnostic instead of writing a config that
/// passes `config-check` only because the rewrite hid the operator's
/// intent.
#[cfg(unix)]
#[test]
fn init_refuses_when_existing_config_has_an_unknown_top_level_key() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let body = manual_answers(dir.path(), &data_dir, &config_path, "mail.example.org");
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let first = {
		let mut cmd = Command::new(binary());
		cmd.args(["init", "--answers", answers.to_str().unwrap()]);
		cmd.stdin(Stdio::null())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped());
		cmd.output().expect("spawn epistle")
	};
	assert!(
		first.status.success(),
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&first.stderr)
	);
	// Insert a comment and an unknown top-level key at the very
	// top of the file while keeping the file mode 0600. The TOML
	// parser strips the comment, so the parsed value of the
	// existing file equals the desired value (the unknown key is
	// preserved by `reconcile`), and the identity shortcut returns
	// `Identical`. `config-check` would reject the same file
	// because of `operator_note`.
	let existing_text = std::fs::read_to_string(&config_path).expect("read");
	let mut new_text = String::from("# operator comment\noperator_note = \"keep me\"\n");
	new_text.push_str(&existing_text);
	std::fs::write(&config_path, &new_text).expect("rewrite with unknown key");
	std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
		.expect("chmod 0600");
	let second = {
		let mut cmd = Command::new(binary());
		cmd.args(["init", "--answers", answers.to_str().unwrap()]);
		cmd.stdin(Stdio::null())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped());
		cmd.output().expect("spawn epistle")
	};
	assert_eq!(
		second.status.code(),
		Some(2),
		"init must exit 2 on an existing invalid config (nothing was touched; the plan phase surfaces the refusal before any effect); stderr: {}",
		String::from_utf8_lossy(&second.stderr)
	);
	let stderr = String::from_utf8_lossy(&second.stderr);
	assert!(
		stderr.contains("operator_note"),
		"stderr must name the unknown field: {stderr}"
	);
	let on_disk = std::fs::read_to_string(&config_path).expect("read after");
	assert!(
		on_disk.contains("operator_note"),
		"the unknown field must NOT have been silently stripped: {on_disk}"
	);
}

/// Finding 12: a Unicode hostname passes `Answers::validate` but
/// the certificate builder rejects the value with
/// `InvalidAsn1String` and `epistle init` panics with exit 101.
/// The shared validator already computes the ASCII A-label; the
/// fix is to carry that A-label into the certificate parameters
/// and the generated config so nothing on disk ever carries a
/// U-label.
#[cfg(unix)]
#[test]
fn init_carries_the_a_label_of_a_unicode_hostname_into_the_config() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let body = manual_answers(
		dir.path(),
		&data_dir,
		&config_path,
		"mail.bücher.example.org",
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let output = {
		let mut cmd = Command::new(binary());
		cmd.args(["init", "--answers", answers.to_str().unwrap()]);
		cmd.stdin(Stdio::null())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped());
		cmd.output().expect("spawn epistle")
	};
	assert_eq!(
		output.status.code(),
		Some(0),
		"a Unicode hostname must normalise to its A-label, not panic; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let on_disk = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		on_disk.contains("xn--bcher-kva.example.org"),
		"the A-label must be written into the config: {on_disk}"
	);
	assert!(
		!on_disk.contains("bücher"),
		"no U-label may reach the config file: {on_disk}"
	);
}

/// Finding 12: a Unicode domain in the `domains` array must be
/// normalised the same way. The config file carries the A-label
/// the rest of the CLI expects.
#[cfg(unix)]
#[test]
fn init_carries_the_a_label_of_a_unicode_domain_into_the_config() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"bücher.example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let output = {
		let mut cmd = Command::new(binary());
		cmd.args(["init", "--answers", answers.to_str().unwrap()]);
		cmd.stdin(Stdio::null())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped());
		cmd.output().expect("spawn epistle")
	};
	assert_eq!(
		output.status.code(),
		Some(0),
		"a Unicode domain must normalise to its A-label, not panic; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let on_disk = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		on_disk.contains("xn--bcher-kva.example.org"),
		"the A-label must be written into the config: {on_disk}"
	);
	assert!(
		!on_disk.contains("bücher"),
		"no U-label may reach the config file: {on_disk}"
	);
}

/// Finding 13: the interactive assistant must re-ask the public-IP
/// question after the operator types a loopback IPv4 (which is
/// syntactically valid as a v4 address but semantically wrong for
/// a public IP). The completed answers must contain the correction
/// the operator gave on the second attempt.
#[cfg(unix)]
#[test]
fn assistant_reprompts_on_a_semantically_invalid_public_ipv4() {
	use std::io::Write;
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	// The interactive assistant walks the questions in order:
	// mode, hostname, domains (terminated by blank), public IPv4,
	// public IPv6, data dir, config path, then the six
	// services + confirmation. The first IPv4 answer is the
	// loopback (semantically wrong); the second is 8.8.8.8
	// (accepted). The completed run must exit 0 and the data
	// dir must exist with a real public IPv4 in the config.
	let input = "manual\n\
		mail.example.org\n\
		example.org\n\
		\n\
		127.0.0.1\n\
		8.8.8.8\n\
		\n\
		{dd}\n\
		{cp}\n\
		y\n\
		y\n\
		n\n\
		n\n\
		n\n\
		n\n\
		y\n";
	let input = input
		.replace("{dd}", &data_dir.display().to_string())
		.replace("{cp}", &config_path.display().to_string());
	let mut child = Command::new(binary())
		.arg("init")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("spawn epistle");
	child
		.stdin
		.as_mut()
		.expect("stdin")
		.write_all(input.as_bytes())
		.expect("write interactive input");
	let output = child.wait_with_output().expect("wait epistle");
	assert_eq!(
		output.status.code(),
		Some(0),
		"assistant must complete the interview after a corrected public IPv4; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let on_disk = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		on_disk.contains("8.8.8.8"),
		"the corrected public IPv4 must be in the config: {on_disk}"
	);
	assert!(
		!on_disk.contains("127.0.0.1"),
		"the bad public IPv4 must NOT have been written: {on_disk}"
	);
}
