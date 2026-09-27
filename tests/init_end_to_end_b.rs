//! End-to-end integration tests for the early findings an outside
//! review of the binary raised: api service refusal (1), key-write
//! failure propagation (2), OAuth pair handling (3), TLS pair
//! handling (4), and managed-key reconciliation (5). The staging
//! path, symlink refusal, and staging permission tests live in
//! `init_end_to_end_c.rs` so this file stays under the per-file
//! line limit.

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

/// Finding 1: `services.api = true` must be refused in the shared
/// answers validator before any side effect, with a message naming
/// the `[api]` section the operator has to fill in by hand.
#[test]
fn init_refuses_api_service_in_answers_before_writing_keys() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\n\
		 [services]\n\
		 imap = true\n\
		 submission = true\n\
		 api = true\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let output = run_init(&answers);
	assert_eq!(
		output.status.code(),
		Some(2),
		"api=true must be a validation rejection (exit 2); got {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("api") && stderr.contains("[api]"),
		"the rejection must tell the operator to edit [api] by hand: {stderr}"
	);
	assert!(
		!data_dir.exists(),
		"refusing api=true must not create the data_dir"
	);
}

/// Finding 1 (dry-run parity): the same answers refused by apply must
/// also be refused by `--dry-run`, before any plan or report is
/// printed.
#[test]
fn dry_run_refuses_api_service_in_answers() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\n\
		 [services]\n\
		 imap = true\n\
		 submission = true\n\
		 api = true\n",
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
	assert_eq!(
		output.status.code(),
		Some(2),
		"dry-run must also refuse api=true: exit {:?}",
		output.status
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("api"),
		"the dry-run rejection must name the api service: {stderr}"
	);
	assert!(!stderr.contains("plan:"));
}

/// Finding 2: a write failure on a later key file must surface as
/// exit 1 (not a panic with exit 101) and the rendered report must
/// list the keys that already landed before the obstruction, so the
/// operator can recover the partial tree.
#[cfg(unix)]
#[test]
fn init_exits_one_when_a_later_key_write_fails_and_prints_partial_report() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let keys_dir = data_dir.join("keys");
	// `storage::write_secret` stages to a sibling `.secret.tmp`; a
	// directory at that exact path makes the storage-key write fail
	// with `AlreadyExists` once the ed25519 and RSA keys have
	// already landed.
	std::fs::create_dir_all(keys_dir.join("storage.secret.tmp")).expect("blocker dir");
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
	assert_eq!(
		output.status.code(),
		Some(1),
		"obstructed key write must surface as exit 1 (no panic); got {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("report:"),
		"the rendered report must appear even on failure: {stderr}"
	);
	assert!(
		stderr.contains("s1.pem"),
		"the report must list the dkim ed25519 key that landed: {stderr}"
	);
	assert!(
		stderr.contains("s2.pem"),
		"the report must list the dkim rsa key that landed: {stderr}"
	);
	// `storage.key` may appear in the error message but never on a
	// `wrote:` line: the report must not claim a successful write.
	assert!(
		!stderr
			.lines()
			.any(|line| line.contains("wrote:") && line.contains("storage.key")),
		"the report must NOT claim a successful storage-key write: {stderr}"
	);
	assert!(
		stderr.contains("cannot write"),
		"the error must name the failing key path: {stderr}"
	);
}

/// Finding 3 (binary): after a successful first run, deleting only
/// the public half of the OAuth pair must NOT leave the operator
/// with a successful second run. The plan and the apply phase must
/// agree on the same recovery message and the run must exit 1 with
/// no fresh private key written.
#[test]
fn init_refuses_when_only_oauth_public_survives() {
	let dir = tempfile::tempdir().expect("tempdir");
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
	let first = run_init(&answers);
	assert!(
		first.status.success(),
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&first.stderr)
	);
	let public_bytes =
		std::fs::read(data_dir.join("keys").join("oauth_public.key")).expect("read public");
	std::fs::remove_file(data_dir.join("keys").join("oauth_signing.key")).expect("rm private");
	let second = run_init(&answers);
	assert_eq!(
		second.status.code(),
		Some(2),
		"second run must surface the incomplete pair as exit 2 (nothing was touched; the plan phase surfaces the refusal before any effect); stderr: {}",
		String::from_utf8_lossy(&second.stderr)
	);
	let stderr = String::from_utf8_lossy(&second.stderr);
	assert!(
		stderr.contains("oauth_signing.key") && stderr.contains("missing"),
		"the error must name the missing private key: {stderr}"
	);
	assert!(
		!data_dir.join("keys").join("oauth_signing.key").exists(),
		"a fresh private key must NOT have been written"
	);
	let public_after =
		std::fs::read(data_dir.join("keys").join("oauth_public.key")).expect("read public");
	assert_eq!(
		public_bytes, public_after,
		"public key bytes must be untouched"
	);
}

/// Finding 3 (binary, pair derivation): with only the private half
/// present, the second run must derive the matching public half
/// from the existing private key, leaving the private bytes
/// untouched and the public bytes matching the first run.
#[test]
fn init_derives_missing_oauth_public_from_existing_private() {
	let dir = tempfile::tempdir().expect("tempdir");
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
	let first = run_init(&answers);
	assert!(
		first.status.success(),
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&first.stderr)
	);
	let private_bytes =
		std::fs::read(data_dir.join("keys").join("oauth_signing.key")).expect("read private");
	let public_bytes =
		std::fs::read(data_dir.join("keys").join("oauth_public.key")).expect("read public");
	std::fs::remove_file(data_dir.join("keys").join("oauth_public.key")).expect("rm public");
	let second = run_init(&answers);
	assert!(
		second.status.success(),
		"second run must succeed; stderr: {}",
		String::from_utf8_lossy(&second.stderr)
	);
	let private_after =
		std::fs::read(data_dir.join("keys").join("oauth_signing.key")).expect("read private");
	let public_after =
		std::fs::read(data_dir.join("keys").join("oauth_public.key")).expect("read public");
	assert_eq!(
		private_bytes, private_after,
		"the private key must not be regenerated"
	);
	assert_eq!(
		public_bytes, public_after,
		"the derived public key must match the one the first run wrote"
	);
}

/// Finding 4 (binary): when only `key.pem` survives a partial
/// recovery, the second run must rebuild `cert.pem` from the
/// existing private key without regenerating it, and the plan must
/// describe the asymmetric state so the operator sees what will
/// happen before confirming.
#[test]
fn init_rebuilds_cert_from_existing_key_when_only_key_survives() {
	let dir = tempfile::tempdir().expect("tempdir");
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
	let first = run_init(&answers);
	assert!(
		first.status.success(),
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&first.stderr)
	);
	let key_path = data_dir.join("keys").join("key.pem");
	let cert_path = data_dir.join("keys").join("cert.pem");
	let key_before = std::fs::read(&key_path).expect("read key");
	std::fs::remove_file(&cert_path).expect("rm cert");
	let second = run_init(&answers);
	assert!(
		second.status.success(),
		"second run must succeed; stderr: {}",
		String::from_utf8_lossy(&second.stderr)
	);
	let stderr = String::from_utf8_lossy(&second.stderr);
	assert!(
		stderr.contains("reuse") && stderr.contains("key.pem") && stderr.contains("generate"),
		"the plan must describe reuse+generate for the asymmetric pair: {stderr}"
	);
	let key_after = std::fs::read(&key_path).expect("read key");
	assert_eq!(
		key_before, key_after,
		"the existing private key must not be regenerated"
	);
	assert!(
		cert_path.exists(),
		"a replacement cert must have been written"
	);
}

/// Finding 4 (binary, cert only): when only `cert.pem` survives,
/// the run must exit 2 with a recoverable diagnostic and the
/// surviving cert bytes must remain untouched. The plan phase
/// surfaces the refusal before any effect.
#[test]
fn init_refuses_when_only_self_signed_cert_survives() {
	let dir = tempfile::tempdir().expect("tempdir");
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
	let first = run_init(&answers);
	assert!(
		first.status.success(),
		"first run must succeed; stderr: {}",
		String::from_utf8_lossy(&first.stderr)
	);
	let key_path = data_dir.join("keys").join("key.pem");
	let cert_path = data_dir.join("keys").join("cert.pem");
	let cert_before = std::fs::read(&cert_path).expect("read cert");
	std::fs::remove_file(&key_path).expect("rm key");
	let second = run_init(&answers);
	assert_eq!(
		second.status.code(),
		Some(2),
		"second run must refuse the asymmetric pair as exit 2 (nothing was touched; the plan phase surfaces the refusal before any effect); stderr: {}",
		String::from_utf8_lossy(&second.stderr)
	);
	let stderr = String::from_utf8_lossy(&second.stderr);
	assert!(
		stderr.contains("key.pem") && stderr.contains("missing"),
		"the error must name the missing key: {stderr}"
	);
	let cert_after = std::fs::read(&cert_path).expect("read cert");
	assert_eq!(
		cert_before, cert_after,
		"the surviving certificate must NOT be overwritten"
	);
}
