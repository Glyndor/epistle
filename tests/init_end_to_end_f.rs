//! End-to-end integration tests for the validator and plan refusals
//! the file path triggers on a hand-crafted `config_path`. Three
//! shapes the previous run accepted at validation time and only
//! failed after every key was on disk: an existing directory, a
//! path inside `<data_dir>/keys`, and the bare `/x/etc/.` shape
//! whose trailing separator the kernel refuses at the open step.

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

/// `config_path` that resolves to an existing directory must be
/// refused with exit 2 before any effect: the operator must not see
/// `data_dir` and the seven key files on disk after a refusal. The
/// plan phase catches the directory at `symlink_metadata` time and
/// surfaces `ConfigNotAFile`; `mod.rs` maps the plan error to exit 2.
#[test]
fn init_refuses_a_config_path_that_is_an_existing_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_root = tempfile::tempdir().expect("tempdir");
	let data_dir = data_root.path().join("data");
	let config_dir = dir.path().join("etc");
	std::fs::create_dir(&config_dir).expect("mkdir config dir");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\
		 image = \"localhost/epistle:dev\"\n\n\
		 [services]\n\
		 database = false\n",
		data_dir.display(),
		config_dir.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let output = run_init(&answers);
	assert_eq!(
		output.status.code(),
		Some(2),
		"a directory config_path must be refused as exit 2 (nothing was touched); stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("not a regular file"),
		"the error must name the shape: {stderr}"
	);
	assert!(
		stderr.contains(&config_dir.display().to_string()),
		"the error must name the path: {stderr}"
	);
	assert!(
		!data_dir.exists(),
		"no data_dir must have been created: {}",
		data_dir.display()
	);
}

/// Acceptance half of the directory pair: the same answers with a
/// `config_path` that points at a regular file in the directory
/// must succeed. Without this test, a refusal that fires on every
/// path would still satisfy the rejection test above.
#[test]
fn init_succeeds_when_config_path_is_a_file_in_the_directory() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_root = tempfile::tempdir().expect("tempdir");
	let data_dir = data_root.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	std::fs::create_dir(config_path.parent().unwrap()).expect("mkdir etc");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\
		 image = \"localhost/epistle:dev\"\n\n\
		 [services]\n\
		 database = false\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let output = run_init(&answers);
	assert!(
		output.status.success(),
		"a file config_path must succeed; exit: {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
}

/// `config_path` inside `<data_dir>/keys` must be refused with exit
/// 2 before any effect: the validator catches the componentwise
/// containment and refuses before the plan runs.
#[test]
fn init_refuses_a_config_path_inside_data_dir_keys() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_root = tempfile::tempdir().expect("tempdir");
	let data_dir = data_root.path().join("data");
	let config_path = data_dir.join("keys").join("s1.pem");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\
		 image = \"localhost/epistle:dev\"\n\n\
		 [services]\n\
		 database = false\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let output = run_init(&answers);
	assert_eq!(
		output.status.code(),
		Some(2),
		"a config_path inside data_dir/keys must be refused as exit 2; stderr: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("data_dir/keys"),
		"the error must name the offending directory: {stderr}"
	);
	assert!(
		!data_dir.exists(),
		"no data_dir must have been created: {}",
		data_dir.display()
	);
}
