//! `init` with a first account: from an answers file (password from a file
//! or from stdin), skipped, and what `config-check` says afterwards.

use std::path::Path;

use super::*;
use crate::cli::prompt::script::scripted;

const PASSWORD: &str = "Zq8!vT3#mL0@pW6$";

/// An answers file under `dir` with `extra` appended (the
/// `[first_account]` table, when the test has one).
fn answers(dir: &Path, extra: &str) -> std::path::PathBuf {
	let file = dir.join("answers.toml");
	let text = format!(
		"mode = \"manual\"\nhostname = \"mail.example.org\"\ndomains = [\"example.org\", \"example.net\"]\n\
		 data_dir = \"{}\"\nconfig_path = \"{}\"\nimage = \"localhost/epistle:dev\"\n\n\
		 [services]\ndatabase = false\n\n{extra}",
		dir.join("data").display(),
		dir.join("etc").join("mail.toml").display(),
	);
	std::fs::write(&file, text).expect("write answers");
	file
}

/// Run init on `file`; the exit code and what it printed on the stream it
/// is handed.
fn init(file: std::path::PathBuf, dry_run: bool) -> (ExitCode, String) {
	let detector = super::detect::tests::Scripted::found(None, None);
	let resolver = || None;
	let probes = Probes {
		detector: &detector,
		resolver: &resolver,
		meminfo: std::path::Path::new(""),
		clock: &|| crate::clock::sync::HostClock::Synced,
	};
	let mut out = Vec::new();
	let code = run_with(
		Args {
			answers: Some(file),
			dry_run,
			print_answers: false,
			json: false,
		},
		&probes,
		&mut out,
	);
	(code, String::from_utf8(out).expect("utf-8"))
}

fn store(dir: &Path) -> crate::directory_store::AccountStore {
	let config = crate::config::Config::load(&dir.join("etc").join("mail.toml")).expect("config");
	crate::directory_store::AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("store")
}

fn config_check(dir: &Path) -> String {
	let (mut out, mut err) = (Vec::new(), Vec::new());
	let code = crate::cli::config_check::run(
		&dir.join("etc").join("mail.toml"),
		false,
		&mut out,
		&mut err,
	);
	assert_eq!(code, ExitCode::SUCCESS, "{}", String::from_utf8_lossy(&err));
	String::from_utf8(err).expect("utf-8")
}

fn first_account_table(dir: &Path, address: &str) -> String {
	let secret = dir.join("password");
	std::fs::write(&secret, format!("{PASSWORD}\n")).expect("write secret");
	format!(
		"[first_account]\naddress = \"{address}\"\npassword_file = \"{}\"\n",
		secret.display()
	)
}

#[test]
fn a_dotted_address_creates_a_hyphenated_account_that_keeps_the_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let table = first_account_table(dir.path(), "Torre.Control@example.org");
	let (code, out) = init(answers(dir.path(), &table), false);
	assert_eq!(code, ExitCode::from(EXIT_OK), "{out}");
	let account = store(dir.path())
		.dynamic("torre-control")
		.expect("the account is named after the address, dots as hyphens");
	assert_eq!(account.addresses, ["torre.control@example.org"]);
}

#[test]
fn two_addresses_that_give_the_same_account_name_are_refused_not_merged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let table = first_account_table(dir.path(), "torre-control@example.org");
	let (code, out) = init(answers(dir.path(), &table), false);
	assert_eq!(code, ExitCode::from(EXIT_OK), "{out}");
	let table = first_account_table(dir.path(), "torre.control@example.org");
	let (code, out) = init(answers(dir.path(), &table), false);
	assert_ne!(code, ExitCode::from(EXIT_OK), "{out}");
	let accounts = store(dir.path()).dynamic_accounts();
	assert_eq!(accounts.len(), 1, "the second address must not be added");
	assert_eq!(accounts[0].addresses, ["torre-control@example.org"]);
}

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

/// Every path under `dir` with its size, sorted, without the answers file
/// the helpers rewrite on each call.
fn listing(dir: &Path) -> Vec<String> {
	fn tree(dir: &Path, into: &mut Vec<String>) {
		for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
			let path = entry.path();
			let len = entry.metadata().map_or(0, |m| m.len());
			into.push(format!("{}:{len}", path.display()));
			if path.is_dir() {
				tree(&path, into);
			}
		}
	}
	let mut names = Vec::new();
	tree(dir, &mut names);
	names.retain(|line| !line.contains("answers.toml"));
	names.sort();
	names
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

#[path = "init_first_account_address_tests.rs"]
mod address_tests;

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
			.mode() & 0o777,
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
		// `expands_environment_variables` in config_tests.rs.
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

#[test]
fn an_answers_file_creates_the_account_and_points_the_role_addresses_at_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = dir.path().join("password");
	std::fs::write(&secret, format!("{PASSWORD}\n")).expect("write secret");
	let file = answers(
		dir.path(),
		&format!(
			"[first_account]\naddress = \"alice@example.org\"\ndisplay_name = \"Alice\"\npassword_file = \"{}\"\n",
			secret.display()
		),
	);
	let (code, _) = init(file, false);
	assert_eq!(code, ExitCode::from(EXIT_OK));
	let store = store(dir.path());
	let alice = store.dynamic("alice").expect("the account exists");
	assert_eq!(alice.addresses, ["alice@example.org"]);
	assert_eq!(alice.display_name.as_deref(), Some("Alice"));
	let config =
		crate::config::Config::load(&dir.path().join("etc").join("mail.toml")).expect("config");
	for role in [
		"postmaster@example.org",
		"abuse@example.org",
		"postmaster@example.net",
		"abuse@example.net",
	] {
		let alias = config
			.alias
			.iter()
			.find(|alias| alias.address == role)
			.unwrap_or_else(|| panic!("{role} is an alias"));
		assert_eq!(alias.members, ["alice@example.org"]);
	}
	assert!(
		!config_check(dir.path()).contains("postmaster"),
		"config-check no longer warns about postmaster"
	);
}

#[test]
fn without_the_role_aliases_config_check_warns_about_postmaster() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = dir.path().join("password");
	std::fs::write(&secret, PASSWORD).expect("write secret");
	let file = answers(
		dir.path(),
		&format!(
			"[first_account]\naddress = \"alice@example.org\"\npassword_file = \"{}\"\nrole_aliases = false\n",
			secret.display()
		),
	);
	assert_eq!(init(file, false).0, ExitCode::from(EXIT_OK));
	let warned = config_check(dir.path());
	assert!(
		warned.contains("example.org has no postmaster@ address"),
		"{warned}"
	);
}

#[test]
fn a_password_file_of_dash_is_read_from_stdin() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = answers(
		dir.path(),
		"[first_account]\naddress = \"bob@example.net\"\npassword_file = \"-\"\n",
	);
	let run = scripted(false, None, format!("{PASSWORD}\n"), || init(file, false));
	assert_eq!(run.value.0, ExitCode::from(EXIT_OK), "{}", run.stderr);
	assert!(store(dir.path()).dynamic("bob").is_some());
}

#[test]
fn a_weak_password_or_a_missing_password_file_stops_before_anything_is_written() {
	let dir = tempfile::tempdir().expect("tempdir");
	let secret = dir.path().join("password");
	std::fs::write(&secret, "short\n").expect("write secret");
	let file = answers(
		dir.path(),
		&format!(
			"[first_account]\naddress = \"alice@example.org\"\npassword_file = \"{}\"\n",
			secret.display()
		),
	);
	assert_eq!(init(file, false).0, ExitCode::from(EXIT_INVALID));
	assert!(!dir.path().join("data").exists(), "nothing was written");
	let file = answers(
		dir.path(),
		"[first_account]\naddress = \"alice@example.org\"\n",
	);
	assert_eq!(init(file, false).0, ExitCode::from(EXIT_INVALID));
	assert!(!dir.path().join("data").exists(), "nothing was written");
}

#[test]
fn the_plan_lists_the_account_and_its_aliases_and_a_dry_run_creates_neither() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = answers(
		dir.path(),
		"[first_account]\naddress = \"alice@example.org\"\npassword_file = \"/nonexistent\"\n",
	);
	let plan = super::apply::plan(&{
		let mut parsed: Answers =
			toml::from_str(&std::fs::read_to_string(&file).expect("read")).expect("parse");
		parsed.normalise();
		parsed
	})
	.expect("plan");
	let mut text = String::new();
	plan.write_to(&mut text).expect("render");
	assert!(
		text.contains("account: create alice <alice@example.org>"),
		"{text}"
	);
	assert!(
		text.contains("alias: postmaster@example.net -> alice@example.org"),
		"{text}"
	);
	assert_eq!(init(file, true).0, ExitCode::from(EXIT_OK));
	assert!(!dir.path().join("data").exists());
}

#[test]
fn without_a_first_account_nothing_is_created() {
	let dir = tempfile::tempdir().expect("tempdir");
	let file = answers(dir.path(), "");
	assert_eq!(init(file, false).0, ExitCode::from(EXIT_OK));
	let views = store(dir.path()).account_views();
	assert!(
		views.iter().all(|(_, _, dynamic)| !dynamic),
		"init without a first account created a dynamic account"
	);
}
