//! `init` with a first account: from an answers file (password from a file
//! or from stdin), skipped, and what `config-check` says afterwards.

use std::path::Path;

use super::*;

mod address;
mod answers_file;
mod static_account;

fn password() -> &'static str {
	crate::test_support::fixtures::password()
}

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
	let detector = super::super::detect::tests::base::Scripted::found(None, None);
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
	let code = crate::cli::config::check::run(
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
	std::fs::write(&secret, format!("{}\n", password())).expect("write secret");
	format!(
		"[first_account]\naddress = \"{address}\"\npassword_file = \"{}\"\n",
		secret.display()
	)
}

/// Every path under `dir` with its size, sorted, without the answers file
/// the helpers rewrite on each call.
pub(super) fn listing(dir: &Path) -> Vec<String> {
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
