//! A first account that collides with, or is found among, the static `[[accounts]]` of the config.

use super::*;

/// Install once without an account, then declare `torre-control` as a
/// static `[[accounts]]` entry in the written config.
fn install_with_static_account(dir: &Path) {
	let (code, out) = init(answers(dir, ""), false);
	assert_eq!(code, ExitCode::from(EXIT_OK), "{out}");
	let config = dir.join("etc").join("mail.toml");
	let mut text = std::fs::read_to_string(&config).expect("read config");
	text.push_str(
		"\n[[accounts]]\nname = \"torre-control\"\naddresses = [\"torre-control@example.org\"]\n",
	);
	std::fs::write(&config, text).expect("write config");
}

#[test]
fn a_static_account_holding_the_derived_name_is_a_collision_or_is_skipped() {
	let dir = tempfile::tempdir().expect("tempdir");
	install_with_static_account(dir.path());
	let before = std::fs::read(dir.path().join("etc").join("mail.toml")).expect("read");

	let clash = first_account_table(dir.path(), "torre.control@example.org");
	let (code, _) = init(answers(dir.path(), &clash), false);
	assert_eq!(code, ExitCode::from(EXIT_INVALID), "a clash stops the run");
	assert_eq!(
		std::fs::read(dir.path().join("etc").join("mail.toml")).expect("read"),
		before,
		"nothing is rewritten when the name clashes"
	);

	let same = first_account_table(dir.path(), "torre-control@example.org");
	let (code, _) = init(answers(dir.path(), &same), false);
	assert_eq!(code, ExitCode::from(EXIT_OK), "the same account is skipped");
	assert!(
		store(dir.path()).dynamic("torre-control").is_none(),
		"no dynamic copy of the static account is created"
	);
}

#[test]
fn a_clash_stops_a_dry_run_and_a_real_run_before_anything_is_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let table = first_account_table(dir.path(), "torre-control@example.org");
	assert_eq!(
		init(answers(dir.path(), &table), false).0,
		ExitCode::from(EXIT_OK)
	);
	let before = listing(dir.path());
	let clash = first_account_table(dir.path(), "torre.control@example.org");
	for dry_run in [true, false] {
		let (code, out) = init(answers(dir.path(), &clash), dry_run);
		assert_eq!(
			code,
			ExitCode::from(EXIT_INVALID),
			"dry_run {dry_run}: {out}"
		);
	}
	assert_eq!(
		listing(dir.path()),
		before,
		"the clash left the tree as it was"
	);
}

#[test]
fn a_clash_is_found_when_the_config_is_gone_and_only_the_data_dir_remains() {
	let dir = tempfile::tempdir().expect("tempdir");
	let table = first_account_table(dir.path(), "torre-control@example.org");
	assert_eq!(
		init(answers(dir.path(), &table), false).0,
		ExitCode::from(EXIT_OK)
	);
	std::fs::remove_file(dir.path().join("etc").join("mail.toml")).expect("remove config");
	let before = listing(dir.path());
	let clash = first_account_table(dir.path(), "torre.control@example.org");
	for dry_run in [true, false] {
		let (code, out) = init(answers(dir.path(), &clash), dry_run);
		assert_eq!(
			code,
			ExitCode::from(EXIT_INVALID),
			"dry_run {dry_run}: {out}"
		);
	}
	assert_eq!(listing(dir.path()), before, "no config, no acme, nothing");
}

#[test]
fn a_clash_is_found_when_the_existing_config_does_not_load() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let table = first_account_table(dir.path(), "torre-control@example.org");
	assert_eq!(
		init(answers(dir.path(), &table), false).0,
		ExitCode::from(EXIT_OK)
	);
	// A config the loader refuses (group-readable) that a changed domain
	// list would make the run rewrite.
	let config = dir.path().join("etc").join("mail.toml");
	std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o664)).expect("chmod");
	let before = listing(dir.path());
	let clash = first_account_table(dir.path(), "torre.control@example.org");
	for dry_run in [true, false] {
		let file = answers(dir.path(), &clash);
		let text = std::fs::read_to_string(&file)
			.expect("read")
			.replace("\"example.net\"]", "\"example.net\", \"example.com\"]");
		std::fs::write(&file, text).expect("write");
		let (code, out) = init(file, dry_run);
		assert_eq!(
			code,
			ExitCode::from(EXIT_INVALID),
			"dry_run {dry_run}: {out}"
		);
	}
	assert_eq!(listing(dir.path()), before, "the config was not rewritten");
	assert_eq!(
		std::fs::metadata(&config)
			.expect("meta")
			.permissions()
			.mode()
			& 0o777,
		0o664
	);
}

/// A static account written the way a loaded config reads it: the install
/// is done, the dynamic copy is gone, and `lines` is appended to the config.
fn install_then_declare(dir: &Path, lines: &str) {
	let table = first_account_table(dir, "torre-control@example.org");
	assert_eq!(init(answers(dir, &table), false).0, ExitCode::from(EXIT_OK));
	std::fs::remove_file(dir.join("data").join("accounts.toml")).expect("drop dynamic copy");
	let config = dir.join("etc").join("mail.toml");
	let mut text = std::fs::read_to_string(&config).expect("read config");
	text.push_str(lines);
	std::fs::write(&config, text).expect("write config");
}

#[test]
fn a_static_account_with_padded_addresses_is_the_same_account_not_a_clash() {
	let dir = tempfile::tempdir().expect("tempdir");
	install_then_declare(
		dir.path(),
		"\n[[accounts]]\nname = \"torre-control\"\naddresses = [\"  Torre-Control@example.org \"]\n",
	);
	let before = listing(dir.path());
	let table = first_account_table(dir.path(), "torre-control@example.org");
	let (code, out) = init(answers(dir.path(), &table), true);
	assert_eq!(code, ExitCode::from(EXIT_OK), "dry run: {out}");
	assert_eq!(listing(dir.path()), before, "a dry run writes nothing");
	let (code, out) = init(answers(dir.path(), &table), false);
	assert_eq!(code, ExitCode::from(EXIT_OK), "re-run is a skip: {out}");
}

/// An environment variable set for one test and removed when the guard
/// drops, also when the test fails before its end.
struct EnvVar(&'static str);

impl EnvVar {
	fn set(name: &'static str, value: &str) -> Self {
		// SAFETY: `name` is unique to the one test that creates this guard, so
		// no other test reads or writes it. Tests elsewhere in the process
		// only read other variables, the same arrangement as
		// `expands_environment_variables` in `src/config/tests/env.rs`.
		unsafe { std::env::set_var(name, value) };
		EnvVar(name)
	}
}

impl Drop for EnvVar {
	fn drop(&mut self) {
		// SAFETY: same uniquely-named variable as set in `EnvVar::set`.
		unsafe { std::env::remove_var(self.0) };
	}
}

#[test]
fn the_env_guard_removes_the_variable_even_on_a_panic() {
	let name = "EPISTLE_TEST_1208_GUARD";
	let unwound = std::panic::catch_unwind(|| {
		let _env = EnvVar::set(name, "x");
		assert_eq!(std::env::var(name).as_deref(), Ok("x"));
		panic!("the test fails before its end");
	});
	assert!(unwound.is_err());
	assert!(std::env::var(name).is_err(), "the variable did not leak");
}

#[test]
fn a_static_account_named_by_an_environment_variable_is_found_by_its_value() {
	let dir = tempfile::tempdir().expect("tempdir");
	let _env = EnvVar::set("EPISTLE_TEST_1208_ACCT", "torre-control");
	install_then_declare(
		dir.path(),
		"\n[[accounts]]\nname = \"${EPISTLE_TEST_1208_ACCT}\"\naddresses = [\"torre-control@example.org\"]\n",
	);
	let before = listing(dir.path());
	let clash = first_account_table(dir.path(), "torre.control@example.org");
	for dry_run in [true, false] {
		let (code, out) = init(answers(dir.path(), &clash), dry_run);
		assert_eq!(
			code,
			ExitCode::from(EXIT_INVALID),
			"dry_run {dry_run}: {out}"
		);
	}
	assert_eq!(listing(dir.path()), before, "nothing was written");
	let same = first_account_table(dir.path(), "torre-control@example.org");
	let (code, out) = init(answers(dir.path(), &same), false);
	assert_eq!(
		code,
		ExitCode::from(EXIT_OK),
		"the same account is skipped: {out}"
	);
}

#[test]
fn a_static_account_is_still_found_when_the_config_does_not_load() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	install_then_declare(
		dir.path(),
		"\n[[accounts]]\nname = \"torre-control\"\naddresses = [\"torre-control@example.org\"]\n",
	);
	let config = dir.path().join("etc").join("mail.toml");
	std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o664)).expect("chmod");
	let before = listing(dir.path());
	let clash = first_account_table(dir.path(), "torre.control@example.org");
	for dry_run in [true, false] {
		let file = answers(dir.path(), &clash);
		let text = std::fs::read_to_string(&file)
			.expect("read")
			.replace("\"example.net\"]", "\"example.net\", \"example.com\"]");
		std::fs::write(&file, text).expect("write");
		let (code, out) = init(file, dry_run);
		assert_eq!(
			code,
			ExitCode::from(EXIT_INVALID),
			"dry_run {dry_run}: {out}"
		);
	}
	assert_eq!(listing(dir.path()), before, "nothing was written");
}
