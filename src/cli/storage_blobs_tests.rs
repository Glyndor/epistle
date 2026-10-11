use std::path::PathBuf;

use clap::{CommandFactory, Parser};

use super::*;
use crate::cli::resource::{Run, test_config};

pub(super) const S3: &str = "
# blobs
[storage.blobs] # where
backend = 's3' # kind
endpoint = 'https://s3.example.net'
bucket = 'mail-blobs'
region = 'us-east-1'
access_key_id = 'AKIAEXAMPLE'
secret_access_key_env = 'S3_SECRET' # secret source
";

pub(super) fn no_restart(_: &Config, _: StackAction) -> ExitCode {
	panic!("a test host has no compose file, so nothing may be restarted")
}

/// Run the command against `extra` appended to the base fixture. `prepare`
/// may create files inside the data directory first.
pub(super) fn run_with(
	extra: &str,
	args: &[&str],
	dry_run: bool,
	prepare: impl FnOnce(&Path),
) -> Run {
	let (dir, file) = test_config(extra);
	prepare(dir.path());
	let before = std::fs::read_to_string(file.path()).unwrap();
	let mut full = vec!["epistle", "storage", "blobs"];
	full.extend_from_slice(args);
	let crate::cli::Command::Storage { action, .. } =
		crate::cli::Cli::try_parse_from(full).unwrap().command
	else {
		unreachable!("storage arguments must select the storage command")
	};
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		file.path(),
		action,
		dry_run,
		&mut out,
		&mut status,
		no_restart,
	);
	Run {
		result,
		out: String::from_utf8(out).unwrap(),
		status: String::from_utf8(status).unwrap(),
		after: std::fs::read_to_string(file.path()).unwrap(),
		before,
	}
}

pub(super) fn run(extra: &str, args: &[&str]) -> Run {
	run_with(extra, args, false, |_| {})
}

#[test]
fn storage_accepts_config_before_or_after_the_action_and_defaults_it() {
	for (args, want) in [
		(
			vec!["epistle", "storage", "blobs", "show"],
			"/etc/epistle/mail.toml",
		),
		(
			vec![
				"epistle",
				"storage",
				"--config",
				"/tmp/x.toml",
				"blobs",
				"show",
			],
			"/tmp/x.toml",
		),
		(
			vec![
				"epistle",
				"storage",
				"blobs",
				"show",
				"--config",
				"/tmp/x.toml",
			],
			"/tmp/x.toml",
		),
	] {
		let matches = crate::cli::Cli::command()
			.try_get_matches_from(args)
			.unwrap();
		assert_eq!(
			matches
				.subcommand_matches("storage")
				.unwrap()
				.get_one::<PathBuf>("config")
				.unwrap(),
			&PathBuf::from(want)
		);
	}
}

#[test]
fn show_defaults_to_the_filesystem() {
	let run = run("", &["show"]);
	assert_eq!(run.out, "backend\tfs\n");
	assert_eq!(
		super::tests::run("", &["show", "--json"]).out,
		"{\"backend\":\"fs\"}\n"
	);
}

#[test]
fn show_prints_the_secret_source_but_never_a_secret() {
	let run = run(S3, &["show"]);
	assert_eq!(
		run.out,
		"backend\ts3\nendpoint\thttps://s3.example.net\nbucket\tmail-blobs\nregion\tus-east-1\naccess_key_id\tAKIAEXAMPLE\nsecret_access_key_env\tS3_SECRET\n"
	);
	let json = super::tests::run(S3, &["show", "--json"]).out;
	assert_eq!(
		json,
		"{\"access_key_id\":\"AKIAEXAMPLE\",\"backend\":\"s3\",\"bucket\":\"mail-blobs\",\"endpoint\":\"https://s3.example.net\",\"region\":\"us-east-1\",\"secret_access_key_env\":\"S3_SECRET\"}\n"
	);
}
