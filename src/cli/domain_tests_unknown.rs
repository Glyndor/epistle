//! `epistle domain`: an unknown domain (or domain alias) is a refusal
//! (exit code 2), the same way `epistle account disable` refuses one.
//! The message is preserved exactly so scripts that parse
//! `error: domain X is not configured` keep working.
//!
//! Lives in a sibling so `domain_tests.rs` stays under the per-file
//! code-line budget.

use std::io::Write;
use std::process::ExitCode;

use super::run;
use super::{DomainAliasArgs, DomainAliasSubcommand, DomainCli};

fn fixture(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	(dir, file)
}

fn assert_unknown_domain_is_refused(action: DomainCli) {
	let (_dir, file) = fixture("");
	let code = run(file.path(), action, false);
	assert_eq!(
		code,
		ExitCode::from(super::super::exit::REFUSED),
		"an unknown domain must exit 2 (usage error)"
	);
}

#[test]
fn show_unknown_domain_exits_two() {
	assert_unknown_domain_is_refused(DomainCli::Show {
		domain: "ghost.example.org".to_string(),
		json: false,
	});
}

#[test]
fn show_unknown_domain_json_exits_two() {
	assert_unknown_domain_is_refused(DomainCli::Show {
		domain: "ghost.example.org".to_string(),
		json: true,
	});
}

#[test]
fn remove_unknown_domain_exits_two() {
	assert_unknown_domain_is_refused(DomainCli::Remove {
		domain: "ghost.example.org".to_string(),
		yes: true,
	});
}

#[test]
fn remove_unknown_domain_alias_exits_two() {
	assert_unknown_domain_is_refused(DomainCli::Alias(DomainAliasArgs {
		action: DomainAliasSubcommand::Remove {
			alias: "ghost.alias.example.org".to_string(),
			yes: true,
		},
	}));
}

#[test]
fn unknown_domain_keeps_its_message_and_leaves_the_config_alone() {
	// Scripts branch on the exit code, people read the message: the
	// refusal keeps the phrasing a log scan for "is not configured"
	// matches.
	let (_dir, file) = fixture("");
	let before = std::fs::read_to_string(file.path()).expect("read config");
	let outcome = super::execute(
		file.path(),
		DomainCli::Remove {
			domain: "ghost.example.org".to_string(),
			yes: true,
		},
		false,
	);
	let super::Outcome::Refusal(message) = outcome else {
		panic!("an unknown domain must be a refusal");
	};
	assert_eq!(message, "domain ghost.example.org is not configured");
	assert_eq!(
		std::fs::read_to_string(file.path()).expect("read config"),
		before,
		"the file must not change when the name is unknown"
	);
}
