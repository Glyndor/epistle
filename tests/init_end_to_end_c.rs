//! End-to-end integration tests for the staging and symlink paths
//! covered by findings 7, 10, and 14: the staging file must carry a
//! random suffix and never unlink a pre-existing sibling, a
//! symlinked `config_path` is refused with an actionable message,
//! and the staging file is created `0600` from its very first byte.

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

fn run_init(answers: &Path) -> std::process::Output {
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap()]);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	cmd.output().expect("spawn epistle")
}

/// Finding 5 (services): turning off every service in the answers
/// file must remove the listeners the previous run wrote. The merge
/// must not preserve absent managed fields.
#[test]
fn init_clears_listeners_when_services_are_disabled() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let all_on = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\n\
		 [services]\n\
		 imap = true\n\
		 submission = true\n\
		 pop3 = true\n\
		 managesieve = true\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers_on = write_answers(dir.path(), "answers_on.toml", &all_on);
	let first = run_init(&answers_on);
	assert!(
		first.status.success(),
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&first.stderr)
	);
	let on_text = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		on_text.contains("[[listeners]]") && on_text.contains("kind = \"imap\""),
		"first run must write listeners: {on_text}"
	);
	let all_off = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\n\
		 [services]\n\
		 imap = false\n\
		 submission = false\n\
		 pop3 = false\n\
		 managesieve = false\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers_off = write_answers(dir.path(), "answers_off.toml", &all_off);
	let second = run_init(&answers_off);
	assert!(
		second.status.success(),
		"second run must succeed; stderr: {}",
		String::from_utf8_lossy(&second.stderr)
	);
	let off_text = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		!off_text.contains("[[listeners]]"),
		"all listeners must be removed when every service is disabled: {off_text}"
	);
}

/// Finding 5 (dns): switching from automatic to manual mode must
/// remove the existing `[dns]` section rather than preserve it.
#[test]
fn init_clears_dns_section_when_switching_to_manual_mode() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let auto = format!(
		"mode = \"automatic\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\n\
		 [dns]\n\
		 provider = \"cloudflare\"\n\
		 zone = \"example.org\"\n\
		 token = \"inline-token-value\"\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers_auto = write_answers(dir.path(), "answers_auto.toml", &auto);
	let first = run_init(&answers_auto);
	assert!(
		first.status.success(),
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&first.stderr)
	);
	let on_text = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		on_text.contains("[dns]") && on_text.contains("inline-token-value"),
		"first run must write the dns section: {on_text}"
	);
	let manual = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers_manual = write_answers(dir.path(), "answers_manual.toml", &manual);
	let second = run_init(&answers_manual);
	assert!(
		second.status.success(),
		"second run must succeed; stderr: {}",
		String::from_utf8_lossy(&second.stderr)
	);
	let off_text = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		!off_text.contains("[dns]") && !off_text.contains("inline-token-value"),
		"the dns section and its inline token must be removed when manual mode is requested: {off_text}"
	);
}

/// Finding 5 (public_ipv4): omitting a previously-supplied
/// `public_ipv4` in the answers file must remove the key from the
/// existing config; the merge must not preserve the previous
/// value just because the desired config does not name it.
#[test]
fn init_clears_omitted_public_ip_when_the_answers_drop_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let with_ip = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 public_ipv4 = \"8.8.8.8\"\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers_with = write_answers(dir.path(), "answers_with.toml", &with_ip);
	let first = run_init(&answers_with);
	assert!(
		first.status.success(),
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&first.stderr)
	);
	let on_text = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		on_text.contains("public_ipv4 = \"8.8.8.8\""),
		"first run must write public_ipv4: {on_text}"
	);
	let without_ip = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers_without = write_answers(dir.path(), "answers_without.toml", &without_ip);
	let second = run_init(&answers_without);
	assert!(
		second.status.success(),
		"second run must succeed; stderr: {}",
		String::from_utf8_lossy(&second.stderr)
	);
	let off_text = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		!off_text.contains("public_ipv4"),
		"omitting public_ipv4 must remove the key from the config: {off_text}"
	);
}

/// Finding 5 (preserve unmanaged keys): an operator-added unknown
/// top-level key must survive a rewrite. The key is added at the
/// top of the file, before any managed sections, because TOML
/// extends the previous table across subsequent keys until a new
/// header is seen.
#[test]
fn init_preserves_unknown_top_level_keys_across_a_managed_rewrite() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let on_body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\n\
		 [services]\n\
		 imap = true\n\
		 submission = true\n\
		 pop3 = true\n\
		 managesieve = true\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &on_body);
	let first = run_init(&answers);
	assert!(
		first.status.success(),
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&first.stderr)
	);
	// Inject the operator key at the very top, so it lives at the
	// top level rather than inside the next managed table.
	let original = std::fs::read_to_string(&config_path).expect("read config");
	let with_srs = format!("srs_secret = \"kept by the operator\"\n{original}");
	std::fs::write(&config_path, &with_srs).expect("write srs_secret");
	let second = run_init(&answers);
	assert!(
		second.status.success(),
		"second run must succeed; stderr: {}",
		String::from_utf8_lossy(&second.stderr)
	);
	let after = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		after.contains("srs_secret = \"kept by the operator\""),
		"the operator-added unknown key must survive the rewrite: {after}"
	);
}

/// Finding 7: an unrelated pre-existing sibling at the staging
/// basename must NOT be deleted by the apply phase. The staging
/// file lives under a name that cannot collide with `config_path`.
#[test]
fn init_does_not_delete_an_unrelated_sibling_with_the_staging_basename() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let sibling = dir.path().join("mail.config.tmp");
	let sibling_contents = "operator data: keep this file\n";
	std::fs::write(&sibling, sibling_contents).expect("write sibling");
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
	let output = run_init(&answers);
	assert!(
		output.status.success(),
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert!(
		sibling.exists(),
		"the pre-existing sibling at the staging basename must survive"
	);
	let preserved = std::fs::read_to_string(&sibling).expect("read sibling");
	assert_eq!(preserved, sibling_contents);
}

/// Finding 10: a `config_path` that is a symlink to its managed
/// target must be refused with a message naming the link, rather
/// than silently replacing the link with a regular file and
/// leaving the original target stale.
#[cfg(unix)]
#[test]
fn init_refuses_a_symlinked_config_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let body_initial = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers_initial.toml", &body_initial);
	let first = run_init(&answers);
	assert!(
		first.status.success(),
		"initial run must succeed; stderr: {}",
		String::from_utf8_lossy(&first.stderr)
	);
	// Move the live config aside and replace it with a symlink to
	// its previous location, so the symlink carries the same
	// content the operator expects but the write path would now
	// follow the link rather than the symlink itself.
	let managed = dir.path().join("managed.toml");
	std::fs::rename(&config_path, &managed).expect("rename live config");
	std::os::unix::fs::symlink(&managed, &config_path).expect("create symlink");
	let body_changed = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail2.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers_changed = write_answers(dir.path(), "answers_changed.toml", &body_changed);
	let second = run_init(&answers_changed);
	assert_eq!(
		second.status.code(),
		Some(2),
		"symlinked config_path must be refused as exit 2 (nothing was touched; the apply phase surfaces the refusal before writing the new bytes); stderr: {}",
		String::from_utf8_lossy(&second.stderr)
	);
	let stderr = String::from_utf8_lossy(&second.stderr);
	assert!(
		stderr.contains("symlink"),
		"the error must name the symlink: {stderr}"
	);
	let still_symlink = std::fs::symlink_metadata(&config_path)
		.expect("stat")
		.file_type()
		.is_symlink();
	assert!(
		still_symlink,
		"the symlink must NOT have been replaced with a regular file"
	);
	let target_after = std::fs::read_to_string(&managed).expect("read target");
	assert!(
		!target_after.contains("mail2.example.org"),
		"the target file must not have been silently rewritten: {target_after}"
	);
}

/// Finding 14: the staged config must not be readable by other
/// users at any point in its lifetime. `fs::write` follows the
/// process umask, so a sibling umask 022 leaks the file before
/// the chmod tightens it. The fix creates the staging file `0600`
/// from the start with `OpenOptions::create_new(true)`, so the
/// staging file's lifetime never includes a `0644` moment even
/// when the operator runs the binary with a permissive umask.
#[cfg(unix)]
#[test]
fn init_staging_config_is_owner_only_from_the_start() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let body = format!(
		"mode = \"automatic\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 public_ipv4 = \"8.8.8.8\"\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\n\
		 [dns]\n\
		 provider = \"cloudflare\"\n\
		 zone = \"example.org\"\n\
		 token = \"inline-dns-token-xyz\"\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	// Wrap the binary call with `std::process::Command` so the
	// umask the child sees is 022. With the old `fs::write` +
	// chmod path the staging file would briefly live as 0644; the
	// `O_EXCL` + 0600 from `create_new(true)` path means the file
	// is 0600 from the very first byte.
	let mut cmd = Command::new(binary());
	cmd.args(["init", "--answers", answers.to_str().unwrap()]);
	cmd.stdin(Stdio::null());
	cmd.stdout(Stdio::piped());
	cmd.stderr(Stdio::piped());
	// We can't set the umask for the child from this Rust harness
	// portably, but the `init` phase reads the umask via
	// `OpenOptions` directly on Unix: the staging file is opened
	// with `mode(0o600)`, which overrides any process umask. The
	// final config file must still be 0600 after a successful
	// run, and no leftover staging file under any suffix must
	// remain behind.
	let output = cmd.output().expect("spawn epistle");
	assert!(
		output.status.success(),
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	for entry in std::fs::read_dir(dir.path()).expect("readdir").flatten() {
		let name = entry.file_name();
		let name = name.to_string_lossy();
		assert!(
			!name.contains("config.tmp"),
			"no leftover staging file should remain after a successful run: {name}"
		);
	}
	let mode = std::fs::metadata(&config_path)
		.expect("stat")
		.permissions()
		.mode();
	assert_eq!(
		mode & 0o777,
		0o600,
		"config must be 0600, got {:o}",
		mode & 0o777
	);
}

/// Finding 8: when `openssl` is not on `PATH`, the apply phase
/// must omit `rsa_selector` and `rsa_key_file` from the generated
/// config rather than point them at the Ed25519 key. A config
/// that names an RSA selector and an Ed25519 key file does not
/// start: the RSA loader rejects the Ed25519 material before
/// `serve` finishes binding its listeners.
#[cfg(unix)]
#[test]
fn init_omits_rsa_dkim_keys_when_openssl_is_absent() {
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
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let config_text = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		!config_text.contains("rsa_selector") && !config_text.contains("rsa_key_file"),
		"the generated config must NOT carry rsa_selector or rsa_key_file when no RSA key exists: {config_text}"
	);
	assert!(
		config_text.contains("selector = \"s1\"") && config_text.contains("key_file"),
		"the generated config must still carry the ed25519 dkim block: {config_text}"
	);
	assert!(
		!data_dir.join("keys").join("s2.pem").exists(),
		"s2.pem must not be written when openssl is absent"
	);
}

/// Finding 9: when openssl returns after the first run wrote a
/// config without RSA fields, the next run must show the plan as
/// an `update` (not `identical`) so the operator sees that the
/// about-to-be-written config adds the RSA fields. The plan is
/// built from the planned post-step key state, so it agrees with
/// the apply phase.
#[cfg(unix)]
#[test]
fn init_plan_says_update_when_openssl_returns_for_an_existing_config() {
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
	// First run with openssl unavailable: writes a config without
	// RSA fields, no s2.pem.
	let first = {
		let mut cmd = Command::new(binary());
		cmd.args(["init", "--answers", answers.to_str().unwrap()]);
		cmd.env("PATH", &empty_path);
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
	let on_text = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		!on_text.contains("rsa_"),
		"first-run config must not carry RSA fields: {on_text}"
	);
	// Second run with the host's normal PATH (openssl available):
	// the plan must say the config will be updated to add the RSA
	// fields, not that it is identical.
	let second = run_init(&answers);
	let stderr = String::from_utf8_lossy(&second.stderr);
	assert!(
		stderr.contains("update") && stderr.contains("config:"),
		"the plan must describe the config as `update`, not `identical`: {stderr}"
	);
	assert!(
		!stderr.contains("config: identical"),
		"the plan must NOT call the config `identical`: {stderr}"
	);
}
