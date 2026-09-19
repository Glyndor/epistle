//! End-to-end integration test for `epistle init`: spawns the real
//! binary against a fresh tempdir whose `config_path` parent does
//! not exist, drives `--dry-run`, apply, `config-check`, and a second
//! apply; then runs an invalid-answers scenario where every problem
//! is collected and reported together with no parent directory
//! created.

use std::io::Write;
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

fn make_answers_body(data_dir: &Path, config_path: &Path) -> String {
	format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 public_ipv4 = \"8.8.8.8\"\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
		data_dir.display(),
		config_path.display(),
	)
}

fn openssl_on_path() -> bool {
	Command::new("openssl")
		.arg("version")
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.status()
		.map(|status| status.success())
		.unwrap_or(false)
}

fn plan_paths(stderr: &str) -> Vec<String> {
	let mut paths = Vec::new();
	for line in stderr.lines() {
		let Some(idx) = line.find("generate ") else {
			continue;
		};
		let rest = &line[idx + "generate ".len()..];
		// The pair step renders as "generate <cert> (and <key>)"; pull
		// both paths out so the test can match them as a set.
		if let Some(and_idx) = rest.find(" (and ") {
			let cert = rest[..and_idx].trim();
			let key_part = &rest[and_idx + " (and ".len()..];
			let key = key_part.trim_end_matches(')').trim();
			paths.push(cert.to_string());
			paths.push(key.to_string());
		} else {
			paths.push(rest.trim().to_string());
		}
	}
	paths
}

#[cfg(unix)]
fn sha256_of(path: &Path) -> Vec<u8> {
	let bytes = std::fs::read(path).expect("read");
	ring::digest::digest(&ring::digest::SHA256, &bytes)
		.as_ref()
		.to_vec()
}

#[cfg(unix)]
fn mtime(path: &Path) -> std::time::SystemTime {
	std::fs::metadata(path)
		.expect("metadata")
		.modified()
		.expect("mtime")
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
	use std::os::unix::fs::PermissionsExt;
	std::fs::metadata(path)
		.expect("metadata")
		.permissions()
		.mode()
		& 0o777
}

#[test]
fn dry_run_writes_nothing_to_a_fresh_tempdir() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	let answers = write_answers(
		dir.path(),
		"answers.toml",
		&make_answers_body(&data_dir, &config_path),
	);
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap(), "--dry-run"]);
	cmd.stdin(Stdio::null());
	cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(output.status.success(), "dry-run exit: {:?}", output.status);
	assert!(
		output.stdout.is_empty(),
		"dry-run wrote to stdout: {:?}",
		String::from_utf8_lossy(&output.stdout)
	);
	let mut entries: Vec<PathBuf> = std::fs::read_dir(dir.path())
		.expect("read_dir")
		.map(|entry| entry.expect("entry").path())
		.collect();
	entries.retain(|path| path != &answers);
	entries.sort();
	assert_eq!(
		entries,
		Vec::<PathBuf>::new(),
		"dry-run must leave only the answers file behind; entries: {entries:?}"
	);
}

#[cfg(unix)]
#[test]
fn apply_creates_every_file_with_the_right_mode_and_config_check_passes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	let answers = write_answers(
		dir.path(),
		"answers.toml",
		&make_answers_body(&data_dir, &config_path),
	);
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap()]);
	cmd.stdin(Stdio::null());
	cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(output.status.success(), "apply exit: {:?}", output.status);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		output.stdout.is_empty(),
		"apply wrote to stdout: {:?}",
		String::from_utf8_lossy(&output.stdout)
	);

	// Mode: data_dir 0700, data/keys 0700, every key 0600,
	// config 0600, config parent 0750.
	assert_eq!(mode(&data_dir), 0o700, "data_dir mode");
	assert_eq!(mode(&data_dir.join("keys")), 0o700, "data/keys mode");
	assert_eq!(
		mode(config_path.parent().unwrap()),
		0o750,
		"config parent mode"
	);
	assert_eq!(mode(&config_path), 0o600, "config mode");

	// The set of files under data/keys/ must equal exactly the set of
	// paths the plan listed as `generate`. The plan includes s2.pem
	// only when openssl is on PATH.
	let keys_dir = data_dir.join("keys");
	let mut on_disk: Vec<String> = std::fs::read_dir(&keys_dir)
		.expect("read keys")
		.map(|entry| entry.expect("entry").path().display().to_string())
		.collect();
	on_disk.sort();
	let mut listed = plan_paths(&stderr);
	listed.sort();
	let mut expected: Vec<String> = listed
		.iter()
		.filter(|path| path.starts_with(&keys_dir.display().to_string()))
		.cloned()
		.collect();
	expected.sort();
	if !openssl_on_path() {
		expected.retain(|p| !p.ends_with("/s2.pem"));
	}
	assert_eq!(
		on_disk, expected,
		"data/keys files must equal the plan's generate paths; on_disk = {on_disk:?}, plan = {expected:?}"
	);

	for path in &on_disk {
		assert_eq!(mode(Path::new(path)), 0o600, "{path} mode");
	}

	// config-check on the written config must exit 0.
	let mut cmd = Command::new(binary());
	cmd.args(["config-check", "--config", config_path.to_str().unwrap()]);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("spawn epistle");
	assert!(
		output.status.success(),
		"config-check exit: {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	assert!(
		String::from_utf8_lossy(&output.stdout).contains("configuration is valid"),
		"config-check stdout: {:?}",
		String::from_utf8_lossy(&output.stdout)
	);
}

#[cfg(unix)]
#[test]
fn second_apply_is_a_noop_on_disk_and_uses_reuse_identical() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	let answers = write_answers(
		dir.path(),
		"answers.toml",
		&make_answers_body(&data_dir, &config_path),
	);
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap()]);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("first apply");
	assert!(output.status.success());

	let mut hashes = Vec::new();
	let mut mtimes = Vec::new();
	for entry in std::fs::read_dir(data_dir.join("keys")).expect("read keys") {
		let entry = entry.expect("entry");
		let path = entry.path();
		hashes.push((path.clone(), sha256_of(&path)));
		mtimes.push((path.clone(), mtime(&path)));
	}
	hashes.push((config_path.clone(), sha256_of(&config_path)));
	mtimes.push((config_path.clone(), mtime(&config_path)));

	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap()]);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("second apply");
	assert!(
		output.status.success(),
		"second apply exit: {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		output.stdout.is_empty(),
		"second apply wrote to stdout: {:?}",
		String::from_utf8_lossy(&output.stdout)
	);

	for (path, expected_hash) in &hashes {
		assert_eq!(
			&sha256_of(path),
			expected_hash,
			"sha256 changed for {}",
			path.display()
		);
	}
	for (path, expected_mtime) in &mtimes {
		assert_eq!(
			mtime(path),
			*expected_mtime,
			"mtime changed for {}",
			path.display()
		);
	}

	// Every key step and the config step must say reuse / identical.
	// None must say generate.
	assert!(
		stderr.contains("reuse") && stderr.contains("identical"),
		"second apply must reuse every key and leave the config identical; stderr: {stderr}"
	);
	assert!(
		!stderr.contains("generate "),
		"second apply must not regenerate anything; stderr: {stderr}"
	);
}

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
		 config_path = \"{}\"\n",
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

#[cfg(unix)]
fn data_dir_is_clean(dir: &Path) {
	// The operator sees a single confirmation prompt when every
	// answer is valid; if the interactive run aborted before writing
	// anything, the data_dir (and its keys) must not exist.
	let data_dir = dir.join("data");
	assert!(
		!data_dir.exists(),
		"data_dir must not be created when the interactive run aborted: {}",
		data_dir.display()
	);
}

#[cfg(unix)]
#[test]
fn interactive_run_exits_2_when_stdin_eofs_mid_questions() {
	// Feed enough answers for the assistant to reach the data_dir
	// question and then close stdin: the assistant must surface the
	// truncated read as an error, mod::run must map it to exit code 2,
	// and nothing may have been written to disk.
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

#[cfg(unix)]
#[test]
fn interactive_run_exits_0_when_user_declines_confirmation() {
	// The assistant fills the answers, the operator answers "n" to
	// "Continue? [y/N]", and `epistle init` must exit 0 with nothing
	// on disk. The default answer (empty) takes the same path.
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
					 /tmp/{name}/mail.toml\n\
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

#[cfg(unix)]
#[test]
fn init_skips_the_rsa_dkim_step_when_openssl_is_absent() {
	// With PATH pointing at an empty directory, the apply phase must
	// NOT fail just because openssl is missing. The RSA DKIM key step
	// goes through its skip branch and the rest of the apply runs.
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
		!data_dir.join("keys").join("s2.pem").exists(),
		"s2.pem must not be written when openssl is absent"
	);
}

#[test]
fn init_exits_one_when_plan_fails_on_an_unparseable_existing_config() {
	// The answers file is valid and validates fine, but an existing
	// config on disk is unparseable TOML. The plan step surfaces the
	// read failure with exit code 1; no keys land on disk because
	// the apply phase never runs.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
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
	assert_eq!(
		output.status.code(),
		Some(1),
		"plan failure must surface as exit code 1; got {:?}; stderr: {}",
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
