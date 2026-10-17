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
