use crate::cli::storage::blobs::tests::base::{S3, run, run_with};
use crate::cli::storage::blobs::tests::*;

const NEW_S3: [&str; 12] = [
	"set",
	"s3",
	"--endpoint",
	"https://s3.example.net",
	"--bucket",
	"mail-blobs",
	"--region",
	"us-east-1",
	"--access-key-id",
	"AKIAEXAMPLE",
	"--secret-env",
	"S3_SECRET",
];

fn s3_args(extra: &[&'static str]) -> Vec<&'static str> {
	let mut args = NEW_S3.to_vec();
	args.extend_from_slice(extra);
	args
}

#[test]
fn set_s3_writes_the_section_and_prints_the_migration_caveat() {
	let run = run("", &s3_args(&[]));
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		format!(
			"{}\n[storage]\n\n[storage.blobs]\nbackend = \"s3\"\nendpoint = \"https://s3.example.net\"\nbucket = \"mail-blobs\"\nregion = \"us-east-1\"\naccess_key_id = \"AKIAEXAMPLE\"\nsecret_access_key_env = \"S3_SECRET\"\n",
			run.before
		)
	);
	assert_eq!(
		run.status,
		"Existing blobs are not migrated: those stored in the previous backend stay there and stop being served.\nblob storage saved\nThe server must be restarted.\n",
		"the migration caveat must be printed on every switch"
	);
}

#[test]
fn set_s3_refuses_when_local_blobs_exist_unless_forced() {
	let create = |dir: &Path| {
		std::fs::create_dir_all(dir.join("blobs/ab/cd")).unwrap();
		std::fs::write(dir.join("blobs/ab/cd/0123"), b"payload").unwrap();
	};
	let refused = run_with("", &s3_args(&[]), false, create);
	let message = refused.result.unwrap_err();
	assert!(
		message.as_ref().starts_with("blobs already exist under ")
			&& message.as_ref().ends_with(
				"blobs; they are not migrated and would stop being served. Pass --force to switch anyway"
			),
		"{message}"
	);
	assert!(
		refused.after == refused.before,
		"a refused switch must not write"
	);
	let forced = run_with("", &s3_args(&["--force"]), false, create);
	assert_eq!(forced.result.unwrap(), ExitCode::SUCCESS);
	assert!(forced.after.contains("backend = \"s3\""));
}

#[test]
fn empty_blob_directories_do_not_block_the_switch() {
	let run = run_with("", &s3_args(&[]), false, |dir| {
		std::fs::create_dir_all(dir.join("blobs/ab/cd")).unwrap();
	});
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
}

#[test]
fn an_uninspectable_blob_directory_refuses_the_switch() {
	let run = run_with("", &s3_args(&[]), false, |dir| {
		std::fs::write(dir.join("blobs"), b"not a directory").unwrap();
	});
	assert!(
		run.result
			.unwrap_err()
			.as_ref()
			.starts_with("cannot inspect "),
		"an unreadable store must fail closed"
	);
	assert!(run.after == run.before);
}

#[test]
fn set_fs_clears_every_s3_key_and_keeps_comments() {
	let run = run(S3, &["set", "fs"]);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		run.before
			.replace("backend = 's3' # kind", "backend = \"fs\" # kind")
			.replace("endpoint = 'https://s3.example.net'\nbucket = 'mail-blobs'\nregion = 'us-east-1'\naccess_key_id = 'AKIAEXAMPLE'\nsecret_access_key_env = 'S3_SECRET' # secret source\n", "")
			+ "# secret source\n"
	);
	assert!(
		run.status.starts_with("Existing blobs are not migrated"),
		"{}",
		run.status
	);
}

#[test]
fn changing_only_the_credentials_keeps_the_quiet_path() {
	let run = run(
		S3,
		&[
			"set",
			"s3",
			"--endpoint",
			"https://s3.example.net",
			"--bucket",
			"mail-blobs",
			"--region",
			"us-east-1",
			"--access-key-id",
			"OTHERKEY",
			"--secret-file",
			"/etc/epistle/s3.key",
		],
	);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert_eq!(
		run.after,
		run.before.replace("'AKIAEXAMPLE'", "\"OTHERKEY\"").replace(
			"secret_access_key_env = 'S3_SECRET' # secret source\n",
			"secret_access_key_file = \"/etc/epistle/s3.key\"\n"
		) + "# secret source\n"
	);
	assert_eq!(
		run.status, "blob storage saved\nThe server must be restarted.\n",
		"the same bucket needs no migration warning"
	);
}

#[test]
fn dry_run_prints_the_diff_and_writes_nothing() {
	let run = run_with("", &["set", "fs"], true, |_| {});
	assert!(run.out.contains("+backend = \"fs\""), "{}", run.out);
	assert_eq!(run.after, run.before);
}

#[test]
fn invalid_requests_are_refused_and_leave_the_file_untouched() {
	let base = |overrides: &[(&str, &'static str)]| {
		let mut args = s3_args(&[]);
		for (flag, value) in overrides {
			let at = args.iter().position(|a| a == flag).unwrap();
			args[at + 1] = value;
		}
		args
	};
	for (args, message) in [
		(
			base(&[("--endpoint", "s3.example.net")]),
			"--endpoint must start with https:// or http://",
		),
		(
			base(&[("--endpoint", "https://user:pw@s3.example.net")]),
			"--endpoint must be a URL without credentials or spaces",
		),
		(
			base(&[("--bucket", "Mail_Blobs")]),
			"--bucket \"Mail_Blobs\" is not a valid bucket name (3 to 63 lowercase letters, digits, '-' and '.')",
		),
		(
			base(&[("--region", "us east")]),
			"--region \"us east\" is not a valid region name",
		),
		(
			base(&[("--access-key-id", " ")]),
			"--access-key-id must not be empty or contain whitespace",
		),
		(
			base(&[("--secret-env", "S-3")]),
			"--secret-env \"S-3\" is not an environment variable name",
		),
		(
			s3_args(&["--secret-file", "/etc/epistle/s3.key"]),
			"choose one of --secret-env and --secret-file",
		),
	] {
		let run = run(S3, &args);
		assert_eq!(run.result.unwrap_err(), message, "{args:?}");
		assert!(run.after == run.before, "{args:?} must not change the file");
	}
	let mut missing = s3_args(&[]);
	missing.truncate(missing.len() - 2);
	let run = run("", &missing);
	assert_eq!(
		run.result.unwrap_err(),
		"s3 needs --secret-env or --secret-file for the secret access key"
	);
	let run = crate::cli::storage::blobs::tests::base::run(
		"",
		&[
			"set",
			"s3",
			"--endpoint",
			"https://s3.example.net",
			"--bucket",
			"mail-blobs",
			"--region",
			"r1",
			"--access-key-id",
			"k",
			"--secret-file",
			"key",
		],
	);
	assert_eq!(
		run.result.unwrap_err(),
		"--secret-file must be an absolute path"
	);
}

#[test]
fn set_fs_clears_a_secret_file_reference_too() {
	let with_file = S3.replace(
		"secret_access_key_env = 'S3_SECRET' # secret source",
		"secret_access_key_file = '/etc/epistle/s3.key'",
	);
	let run = run(&with_file, &["set", "fs"]);
	assert_eq!(run.result.unwrap(), ExitCode::SUCCESS);
	assert!(
		!run.after.contains("secret_access_key_file") && !run.after.contains("s3.key"),
		"the fs backend must not keep the s3 credentials: {}",
		run.after
	);
}
