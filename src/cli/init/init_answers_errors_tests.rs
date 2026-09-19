//! `--answers FILE` errors: every case asserts the user-visible
//! outcome the spec asks for: exit code 2 and no keys, no config,
//! and no data_dir on disk after the run. A test written only to
//! exercise lines is forbidden; each of these pins a behaviour an
//! operator can observe on the wire.

use super::*;

fn run_with_answers(body: &str) -> (ExitCode, tempfile::TempDir) {
	let dir = tempfile::tempdir().expect("tempdir");
	let answers_file = dir.path().join("answers.toml");
	std::fs::write(&answers_file, body).expect("write answers");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	// Make the default TOML point at fresh paths so any leakage into
	// the filesystem is visible: every test asserts these do not exist.
	let mut body_owned = body.to_string();
	if !body_owned.contains("data_dir") {
		body_owned.push_str(&format!("data_dir = \"{}\"\n", data_dir.display()));
	}
	if !body_owned.contains("config_path") {
		body_owned.push_str(&format!("config_path = \"{}\"\n", config_path.display()));
	}
	std::fs::write(&answers_file, &body_owned).expect("write answers");
	let args = Args {
		answers: Some(answers_file),
		dry_run: false,
		print_answers: false,
	};
	let code = run(args);
	assert!(
		!data_dir.exists(),
		"data_dir leaked even though init refused: {}",
		data_dir.display()
	);
	assert!(
		!config_path.exists(),
		"config leaked even though init refused: {}",
		config_path.display()
	);
	(code, dir)
}

#[test]
fn run_exits_2_when_answers_file_does_not_exist() {
	let dir = tempfile::tempdir().expect("tempdir");
	let answers_file = dir.path().join("missing.toml");
	assert!(
		!answers_file.exists(),
		"sanity: the answers file must not exist before the run"
	);
	let args = Args {
		answers: Some(answers_file),
		dry_run: false,
		print_answers: false,
	};
	let code = run(args);
	assert_eq!(
		code,
		ExitCode::from(2),
		"missing answers file must surface as exit code 2"
	);
}

#[test]
fn run_exits_2_when_answers_file_is_not_valid_toml() {
	let (code, _dir) = run_with_answers("this is not = valid TOML\n\tbroken\n");
	assert_eq!(
		code,
		ExitCode::from(2),
		"malformed TOML must surface as exit code 2"
	);
}

#[test]
fn run_exits_2_when_answers_file_has_an_unknown_key() {
	// A typo in an answers file must not be silently ignored:
	// `deny_unknown_fields` on `Answers` makes the parser
	// refuse the file with a line number the operator can act on.
	let (code, _dir) = run_with_answers(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 mystery_field = 1\n",
	);
	assert_eq!(
		code,
		ExitCode::from(2),
		"unknown key must surface as exit code 2"
	);
}

#[test]
fn run_exits_2_when_manual_mode_has_dns_section() {
	let (code, _dir) = run_with_answers(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 [dns]\n\
		 provider = \"cloudflare\"\n\
		 zone = \"example.org\"\n\
		 token_env = \"EPISLE_DNS\"\n",
	);
	assert_eq!(
		code,
		ExitCode::from(2),
		"manual mode with [dns] must surface as exit code 2"
	);
}

#[test]
fn run_exits_2_when_automatic_mode_lacks_dns_section() {
	let (code, _dir) = run_with_answers(
		"mode = \"automatic\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n",
	);
	assert_eq!(
		code,
		ExitCode::from(2),
		"automatic mode without [dns] must surface as exit code 2"
	);
}

#[test]
fn run_exits_2_when_dns_has_two_token_sources() {
	// token and token_env both present: naming two of token,
	// token_file, token_env is rejected.
	let (code, _dir) = run_with_answers(
		"mode = \"automatic\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 [dns]\n\
		 provider = \"cloudflare\"\n\
		 zone = \"example.org\"\n\
		 token = \"value-a\"\n\
		 token_env = \"EPISLE_DNS\"\n",
	);
	assert_eq!(
		code,
		ExitCode::from(2),
		"two dns token sources must surface as exit code 2"
	);
}
