//! End-to-end integration tests for the warnings `epistle init`
//! emits to stderr when the answers file or the on-disk state warrant
//! one. Lives in a sibling so `init_end_to_end.rs` stays under the
//! per-file line limit.
//!
//! Each test asserts an outcome the operator can observe on stderr:
//! the warning text must name the field, the mode (when relevant), or
//! the missing tool, and the test must not change the on-disk state it
//! warns about (e.g. must not silently tighten an existing directory).

use std::path::Path;
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn binary() -> &'static Path {
	Path::new(env!("CARGO_BIN_EXE_epistle"))
}

fn write_answers(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
	let path = dir.join(name);
	std::fs::write(&path, body).expect("write answers");
	path
}

#[cfg(unix)]
#[test]
fn init_warns_about_an_inline_dns_token() {
	// The answers file uses an inline `token` for the DNS provider; the
	// validator accepts it with a warning that the operator must see
	// on stderr before any apply work happens.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let body = format!(
		"mode = \"automatic\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\
		 [dns]\n\
		 provider = \"cloudflare\"\n\
		 zone = \"example.org\"\n\
		 token = \"inline-value\"\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap(), "--dry-run"]);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(
		output.status.success(),
		"dry-run exit: {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("dns.token") && stderr.contains("inline"),
		"inline-token warning must name the field and call it inline; stderr: {stderr}"
	);
}

#[cfg(unix)]
#[test]
fn init_warns_when_imap_and_submission_are_both_false() {
	// Both listeners off means the server accepts mail nobody can
	// read; the validator surfaces a non-fatal warning.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\
		 [services]\n\
		 imap = false\n\
		 submission = false\n\
		 pop3 = false\n\
		 managesieve = false\n\
		 webdav = false\n\
		 api = false\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap(), "--dry-run"]);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(
		output.status.success(),
		"dry-run exit: {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("services") && stderr.contains("read"),
		"services-off warning must name the field and mention reading; stderr: {stderr}"
	);
}

#[cfg(unix)]
#[test]
fn init_warns_about_an_existing_data_dir_with_loose_permissions() {
	// The data_dir already exists with a mode wider than 0700; init
	// must surface a warning that names the actual mode instead of
	// silently tightening the operator's directory. The warning lives
	// in the apply phase, so this test must drive a real apply (no
	// --dry-run), not just the plan.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir(&data_dir).expect("mkdir data");
	std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755))
		.expect("chmod 0755");
	let config_path = dir.path().join("mail.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
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
	assert!(
		output.status.success(),
		"apply exit: {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("data_dir") && stderr.contains("0755"),
		"loose-mode warning must name data_dir and the mode; stderr: {stderr}"
	);
	// The mode of the operator's existing directory must not change:
	// init warned about it instead of tightening it silently.
	let mode = std::fs::metadata(&data_dir)
		.expect("stat data_dir")
		.permissions()
		.mode()
		& 0o777;
	assert_eq!(
		mode, 0o755,
		"existing data_dir mode must not change after the warning; got {:o}",
		mode
	);
}

#[cfg(unix)]
#[test]
fn init_mentions_openssl_when_it_is_not_on_path() {
	// Point PATH at an empty directory so the binary cannot find
	// `openssl`; the apply phase must report the gap rather than
	// silently dropping the rsa key step.
	let dir = tempfile::tempdir().expect("tempdir");
	let empty_path = dir.path().join("empty-bin");
	std::fs::create_dir(&empty_path).expect("mkdir empty-bin");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap(), "--dry-run"]);
	cmd.env("PATH", &empty_path);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(
		output.status.success(),
		"dry-run exit: {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("openssl") && stderr.contains("not on PATH"),
		"missing openssl must be surfaced in the plan/report; stderr: {stderr}"
	);
}
