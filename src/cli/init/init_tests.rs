//! Init module unit tests.

use super::*;

#[test]
fn template_deserialises_into_answers() {
	let toml_text = "mode = \"manual\"\n\
		hostname = \"mail.example.org\"\n\
		domains = [\"example.org\"]\n\
		data_dir = \"/var/lib/epistle\"\n\
		config_path = \"/etc/epistle/mail.toml\"\n"
		.to_string();
	let parsed: Answers = toml::from_str(&toml_text).expect("deserialise");
	assert!(parsed.validate().is_ok());
}

#[test]
fn print_answers_returns_the_template() {
	let args = Args {
		answers: None,
		dry_run: false,
		print_answers: true,
	};
	let code = run(args);
	assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn dry_run_writes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let answers_file = dir.path().join("answers.toml");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let input = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
		data_dir.display(),
		config_path.display(),
	);
	std::fs::write(&answers_file, input).expect("write");
	let args = Args {
		answers: Some(answers_file),
		dry_run: true,
		print_answers: false,
	};
	let code = run(args);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(!data_dir.exists(), "dry-run must not create data_dir");
	assert!(!config_path.exists(), "dry-run must not create config");
}

#[test]
fn invalid_answers_file_exits_invalid() {
	let dir = tempfile::tempdir().expect("tempdir");
	let answers_file = dir.path().join("answers.toml");
	std::fs::write(&answers_file, "mode = \"manual\"\n").expect("write");
	let args = Args {
		answers: Some(answers_file),
		dry_run: false,
		print_answers: false,
	};
	let code = run(args);
	assert_eq!(code, ExitCode::from(2));
}

#[test]
fn run_exits_2_when_plan_fails_and_nothing_was_touched() {
	// A plan failure means a precondition stopped the run before any
	// effect. The answers validate fine, but an existing config on
	// disk is unparseable TOML: the plan surfaces the read failure
	// with exit 2 (nothing was touched), not exit 1 (which means
	// "look at what landed on your machine"). The data_dir must
	// stay absent.
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
	let answers_file = dir.path().join("answers.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
		data_dir.display(),
		config_path.display(),
	);
	std::fs::write(&answers_file, body).expect("write answers");
	let args = Args {
		answers: Some(answers_file),
		dry_run: false,
		print_answers: false,
	};
	let code = run(args);
	assert_eq!(
		code,
		ExitCode::from(2),
		"plan failure must surface as exit code 2 (nothing was touched)"
	);
	assert!(
		!data_dir.exists(),
		"plan failure must not create the data_dir: {}",
		data_dir.display()
	);
}

#[test]
fn run_exits_1_when_apply_partially_fails() {
	// Block the config path's parent with a regular file. Validation
	// passes (the answers are sound), the apply phase writes the keys
	// and the self-signed cert, and then fails at the config step. The
	// operator must see exit code 1.
	let dir = tempfile::tempdir().expect("tempdir");
	let blocker = dir.path().join("etc");
	std::fs::write(&blocker, b"not a directory").expect("blocker");
	let config_path = blocker.join("mail.toml");
	let data_dir = dir.path().join("data");
	let answers_file = dir.path().join("answers.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n",
		data_dir.display(),
		config_path.display(),
	);
	std::fs::write(&answers_file, body).expect("write answers");
	let args = Args {
		answers: Some(answers_file),
		dry_run: false,
		print_answers: false,
	};
	let code = run(args);
	assert_eq!(
		code,
		ExitCode::from(1),
		"apply partial failure must surface as exit code 1"
	);
	// The keys the apply phase wrote before failing stay on disk.
	assert!(
		data_dir.join("keys").join("s1.pem").exists(),
		"the dkim ed25519 key written before the failure must remain on disk"
	);
	// Nothing under the blocker: the apply phase refused to write the
	// config because the parent is not a directory.
	assert!(
		!config_path.exists(),
		"no config was written through a regular-file parent"
	);
}
