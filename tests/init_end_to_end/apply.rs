//! Apply-phase scenarios: a fresh `database = false` apply that
//! must create every file at the right mode and pass `config-check`,
//! the `database = true` rerun that must reuse the password and the
//! compose file byte-for-byte, and the no-op rerun that must say
//! `reuse` and `identical` for every key and the config.

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::process::{Command, Stdio};

use super::helpers::{
	binary, make_answers_body, mode, mtime, openssl_on_path, plan_paths, sha256_of, write_answers,
};

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
fn second_apply_with_database_leaves_compose_and_password_files_untouched() {
	// The `database = false` half of the rerun story is
	// pinned by `second_apply_is_a_noop_on_disk_and_uses_reuse_identical`
	// in a different shape. The `database = true` half
	// has to walk two more files: the database password
	// (`<data_dir>/secrets/epistle_db_password`) and the
	// compose file (`<data_dir>/compose/compose.yaml`).
	// The password is reused byte-for-byte (rotating it
	// would lock epistle out of the existing database)
	// and the compose file is rendered byte-for-byte
	// from the answers (it carries the freshly minted
	// password path), so both must come out of the
	// second apply with the same bytes and the same
	// mtime as the first. A regression that touched
	// either of them would re-write a file the plan
	// said was identical.
	let dir = tempfile::tempdir().expect("tempdir");
	let probe_dir = dir.path().join("bin");
	std::fs::create_dir(&probe_dir).unwrap();
	let probe = probe_dir.join("podman");
	std::fs::write(
		&probe,
		"#!/bin/sh\n[ \"$*\" = 'volume exists epistle_epistle-pgdata' ] || exit 2\nexit 1\n",
	)
	.unwrap();
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).unwrap();
	let probe_path = format!(
		"{}:{}",
		probe_dir.display(),
		std::env::var("PATH").unwrap_or_default()
	);
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("etc").join("mail.toml");
	let body = format!(
		"mode = \"manual\"\n\
		 hostname = \"mail.example.org\"\n\
		 domains = [\"example.org\"]\n\
		 data_dir = \"{}\"\n\
		 config_path = \"{}\"\n\n\
		 [services]\n\
		 database = true\n",
		data_dir.display(),
		config_path.display(),
	);
	let answers = write_answers(dir.path(), "answers.toml", &body);
	let mut cmd = Command::new(binary());
	cmd.env("PATH", &probe_path);
	cmd.args(["init", "--answers", answers.to_str().unwrap()]);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("first apply");
	assert!(
		output.status.success(),
		"first apply failed: {:?}",
		output.status
	);

	// Walk the second-apply target files: the database
	// password and the compose file. A regression that
	// touched either of them under a `database = true`
	// re-run would re-write a file the plan said was
	// identical.
	let password_path = data_dir.join("secrets").join("epistle_db_password");
	let compose_path = data_dir.join("compose").join("compose.yaml");
	let pwd_hash = sha256_of(&password_path);
	let pwd_mtime = mtime(&password_path);
	let compose_hash = sha256_of(&compose_path);
	let compose_mtime = mtime(&compose_path);

	let mut cmd = Command::new(binary());
	cmd.env("PATH", &probe_path);
	cmd.args(["init", "--answers", answers.to_str().unwrap()]);
	cmd.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped());
	let output = cmd.output().expect("second apply");
	assert!(
		output.status.success(),
		"second apply failed: {:?}; stderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		!stderr.contains("epistle_db_password")
			|| stderr.contains("reused:")
			|| stderr.contains("config identical"),
		"the database password must be reused on a database = true re-run, not regenerated; stderr: {stderr}"
	);
	assert!(
		!stderr.contains("compose.yaml") || stderr.contains("identical"),
		"the compose file must be identical on a database = true re-run, not regenerated; stderr: {stderr}"
	);

	assert_eq!(
		sha256_of(&password_path),
		pwd_hash,
		"the database password must be byte-identical after the second apply"
	);
	assert_eq!(
		mtime(&password_path),
		pwd_mtime,
		"the database password mtime must be unchanged after the second apply"
	);
	assert_eq!(
		sha256_of(&compose_path),
		compose_hash,
		"the compose file must be byte-identical after the second apply"
	);
	assert_eq!(
		mtime(&compose_path),
		compose_mtime,
		"the compose file mtime must be unchanged after the second apply"
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

	// Walk the plan on the data dir the first apply populated,
	// so a regression that drops a reuse from the plan (or makes
	// the apply phase regenerate) shows up here as a missing
	// `reuse` line in the rendered plan.
	let plan_cmd_args = ["init", "--answers", answers.to_str().unwrap(), "--dry-run"];
	let plan_output = Command::new(binary())
		.args(plan_cmd_args)
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.output()
		.expect("plan");
	assert!(
		plan_output.status.success(),
		"plan exit: {:?}",
		plan_output.status
	);
	let plan_stderr = String::from_utf8_lossy(&plan_output.stderr);
	for needle in [
		"dkim ed25519 key: reuse",
		"storage key: reuse",
		"oauth private key: reuse",
		"oauth public key: reuse",
	] {
		assert!(
			plan_stderr.contains(needle),
			"dry-run plan must name the reuse for {needle}; got: {plan_stderr}"
		);
	}
	// The RSA DKIM key step is `reuse` only when openssl is on
	// PATH AND the operator already wrote `s2.pem`. The plan
	// renders `skip` (with a hand-run `dkim-keygen` hint) when
	// openssl is missing and the file is absent, and `generate`
	// when openssl is on PATH and the file is absent. A second
	// apply against a tree that already has the file is `reuse`
	// in both cases. The two assertions below pin both shapes
	// against the openssl signal the rest of the test already
	// reads.
	if openssl_on_path() {
		assert!(
			plan_stderr.contains("dkim rsa key: reuse"),
			"dry-run plan must reuse the RSA key when openssl is on PATH; got: {plan_stderr}"
		);
	} else {
		assert!(
			plan_stderr.contains("dkim rsa key: skip"),
			"dry-run plan must skip the RSA key when openssl is missing; got: {plan_stderr}"
		);
	}
	assert!(
		plan_stderr.contains("config:"),
		"dry-run plan must list the config step; got: {plan_stderr}"
	);
	assert!(
		plan_stderr.contains("identical"),
		"dry-run plan must say the config is identical; got: {plan_stderr}"
	);

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

	// Every key step and the config step must say reuse / identical
	// in the apply-phase report. None must say generate.
	assert!(
		stderr.contains("reuse") && stderr.contains("identical"),
		"second apply must reuse every key and leave the config identical; stderr: {stderr}"
	);
	assert!(
		!stderr.contains("generate "),
		"second apply must not regenerate anything; stderr: {stderr}"
	);
}
