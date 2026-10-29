use super::*;
use crate::cli::Cli;
use clap::{CommandFactory, Parser};

/// Every subcommand `epistle --help` lists, hidden ones left out.
fn visible_subcommands() -> Vec<String> {
	Cli::command()
		.get_subcommands()
		.filter(|command| !command.is_hide_set())
		.map(|command| command.get_name().to_owned())
		.collect()
}

#[test]
fn bash_completion_offers_every_visible_subcommand() {
	let script = String::from_utf8(completion_script(CompletionShell::Bash)).unwrap();
	let names = visible_subcommands();
	assert!(
		names.iter().any(|name| name == "account"),
		"the parser must still declare `account`"
	);
	for name in &names {
		assert!(
			script.contains(name.as_str()),
			"the bash completion script must offer the `{name}` subcommand"
		);
	}
	assert!(
		script.contains("complete -F _epistle"),
		"the bash script must register its function for the `epistle` command"
	);
}

#[test]
fn zsh_and_fish_scripts_name_the_command_and_its_subcommands() {
	let zsh = String::from_utf8(completion_script(CompletionShell::Zsh)).unwrap();
	assert!(
		zsh.starts_with("#compdef epistle"),
		"the zsh script must open with `#compdef epistle` so compinit binds it"
	);
	let fish = String::from_utf8(completion_script(CompletionShell::Fish)).unwrap();
	assert!(
		fish.contains("complete -c epistle"),
		"the fish script must register completions for `epistle`"
	);
	for script in [&zsh, &fish] {
		assert!(
			script.contains("account") && script.contains("domain"),
			"each completion script must offer the resource subcommands"
		);
	}
}

#[test]
fn completions_parses_only_the_three_shipped_shells() {
	for (shell, expected) in [
		("bash", CompletionShell::Bash),
		("zsh", CompletionShell::Zsh),
		("fish", CompletionShell::Fish),
	] {
		let cli = Cli::try_parse_from(["epistle", "completions", shell]).unwrap();
		assert!(
			matches!(cli.command, crate::cli::Command::Completions { shell } if shell == expected),
			"`epistle completions {shell}` must select that shell"
		);
	}
	let error = Cli::try_parse_from(["epistle", "completions", "powershell"]).unwrap_err();
	assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
}

#[test]
fn manpages_writes_a_root_page_that_mentions_account() {
	let dir = tempfile::tempdir().unwrap();
	let out = dir.path().join("man");
	write_manpages(&out).unwrap();
	let root = std::fs::read_to_string(out.join("epistle.1")).unwrap_or_default();
	assert!(
		root.contains(".TH epistle 1"),
		"epistle.1 must be a section 1 roff page, got {} bytes",
		root.len()
	);
	assert!(
		root.contains("account"),
		"epistle.1 must list the `account` subcommand"
	);
	assert!(
		out.join("epistle-account.1").is_file(),
		"each subcommand must get its own page"
	);
	assert!(
		!out.join("epistle-manpages.1").exists(),
		"the hidden `manpages` command must not get a page of its own"
	);
}

#[test]
fn manpages_reports_a_directory_it_cannot_create() {
	let dir = tempfile::tempdir().unwrap();
	let blocker = dir.path().join("file");
	std::fs::write(&blocker, b"").unwrap();
	let error = write_manpages(&blocker.join("man")).unwrap_err();
	assert_eq!(error.kind(), std::io::ErrorKind::NotADirectory);
}
