//! The confirmation gate on the configuration edits (domain, domain alias,
//! alias) and on masked addresses, and the account password prompts on a
//! pseudo-terminal.

use std::io::Cursor;
use std::process::ExitCode;

use super::confirmation_flow::{NAME, error, fixture, gate, load, store, with_alice};
use crate::cli::alias::{self, AliasCli};
use crate::cli::domain::{self, DomainAliasArgs, DomainAliasSubcommand, DomainCli};
use crate::cli::masked::{self, MaskedCli};
use crate::cli::prompt::script::{Pty, scripted};
use crate::cli::prompt::{MISMATCH, REPEAT};
use crate::cli::{account, accounts};

#[test]
fn masked_remove_asks_naming_address_and_account() {
	gate(
		"masked remove",
		|(_, _, address)| format!("Remove masked address \"{address}\" from \"alice\"? [y/N]"),
		|| {
			let (dir, cfg) = with_alice();
			let address = store(&load(cfg.path()))
				.add_masked(NAME, "Shop", "example.org", 1_000)
				.expect("add masked")
				.address;
			(dir, cfg, address)
		},
		|(_, cfg, address), yes| {
			let action = MaskedCli::Remove {
				account: NAME.to_string(),
				address: address.clone(),
				yes,
			};
			masked::run(
				&load(cfg.path()),
				action,
				false,
				1_000,
				&mut Vec::new(),
				&mut Vec::new(),
			)
		},
		|(_, cfg, _)| !store(&load(cfg.path())).list_masked(NAME).is_empty(),
	);
}

fn two_domains() -> (tempfile::TempDir, tempfile::NamedTempFile) {
	fixture("[domain_aliases]\n\"alias.example.org\" = \"example.org\"\n")
}

#[test]
fn domain_remove_asks_and_a_dry_run_asks_nothing() {
	let remove = |cfg: &tempfile::NamedTempFile, yes, dry_run| {
		let action = DomainCli::Alias(DomainAliasArgs {
			action: DomainAliasSubcommand::Remove {
				alias: "alias.example.org".to_string(),
				yes,
			},
		});
		domain::run(cfg.path(), action, dry_run, false)
	};
	let present = |cfg: &tempfile::NamedTempFile| {
		load(cfg.path())
			.domain_aliases
			.contains_key("alias.example.org")
	};
	gate(
		"domain alias remove",
		|_| "Remove domain alias \"alias.example.org\"? [y/N]".to_string(),
		two_domains,
		|(_, cfg), yes| remove(cfg, yes, false),
		|(_, cfg)| present(cfg),
	);
	let (_dir, cfg) = two_domains();
	let dry = scripted(false, None, "", || remove(&cfg, false, true));
	assert_eq!(dry.value, ExitCode::SUCCESS, "a dry run needs no --yes");
	assert_eq!(dry.stderr, "");
	assert!(present(&cfg), "a dry run changes nothing");
}

#[test]
fn domain_remove_asks_before_editing_the_configuration() {
	gate(
		"domain remove",
		|_| "Remove domain \"example.org\" from the configuration? [y/N]".to_string(),
		|| fixture(""),
		|(_, cfg), yes| {
			let action = DomainCli::Remove {
				domain: "example.org".to_string(),
				yes,
			};
			domain::run(cfg.path(), action, false, false)
		},
		|(_, cfg)| load(cfg.path()).domains.iter().any(|d| d == "example.org"),
	);
}

#[test]
fn alias_remove_asks_naming_the_alias() {
	gate(
		"alias remove",
		|_| "Remove alias \"team@example.org\"? [y/N]".to_string(),
		|| {
			fixture(
				"[[alias]]\naddress = \"team@example.org\"\nmembers = [\"alice@example.org\"]\n",
			)
		},
		|(_, cfg), yes| {
			let action = AliasCli::Remove {
				address: "team@example.org".to_string(),
				yes,
			};
			alias::run(cfg.path(), action, false, false)
		},
		|(_, cfg)| !load(cfg.path()).alias.is_empty(),
	);
}

/// What `account-add bob` prints on a terminal before its verdict.
fn asked_twice(name: &str) -> String {
	format!("Password for \"{name}\": \n{REPEAT}: \n")
}

fn add_bob(typed: &str) -> (ExitCode, String, bool, bool) {
	let (_dir, cfg) = fixture("");
	let config = load(cfg.path());
	let pty = Pty::open();
	let run = scripted(true, Some(pty.slave), "", || {
		accounts::add(
			&config,
			"bob",
			vec!["bob@example.org".to_string()],
			Cursor::new(typed.as_bytes().to_vec()),
		)
	});
	let created = store(&config).dynamic("bob").is_some();
	(run.value, run.stderr, created, pty.echo_on())
}

#[test]
fn account_add_on_a_terminal_refuses_a_mismatch_with_the_exact_message() {
	let strong = crate::test_fixtures::second_password();
	let (code, stderr, created, echo) = add_bob(&format!("{strong}\n{strong}x\n"));
	assert_eq!(code, ExitCode::from(2));
	assert_eq!(stderr, format!("{}{}", asked_twice("bob"), error(MISMATCH)));
	assert!(!created, "a mismatch creates nothing");
	assert!(echo, "echo is back on after the prompt");
}

#[test]
fn account_add_on_a_terminal_names_the_policy_rule_that_failed() {
	let (code, stderr, created, _) = add_bob("short\nshort\n");
	assert_eq!(code, ExitCode::from(2));
	assert_eq!(
		stderr,
		format!(
			"{}{}",
			asked_twice("bob"),
			error(crate::password::Rejection::TooShort.message())
		)
	);
	assert!(!created);
}

#[test]
fn account_add_on_a_terminal_creates_the_account_when_both_agree() {
	let strong = crate::test_fixtures::second_password();
	let (code, stderr, created, echo) = add_bob(&format!("{strong}\n{strong}\n"));
	assert_eq!(code, ExitCode::SUCCESS, "{stderr}");
	assert_eq!(stderr, asked_twice("bob"));
	assert!(created);
	assert!(echo);
}

#[test]
fn account_password_refuses_an_unknown_name_before_reading_anything() {
	let (_dir, cfg) = with_alice();
	let typed = "a-long-enough-pass\na-long-enough-pass\n";
	let run = scripted(true, None, typed, || {
		account::run(
			cfg.path(),
			account::Subcommand::Password {
				name: "ghost".to_string(),
			},
			false,
			&mut Vec::new(),
		)
	});
	assert_eq!(run.value, ExitCode::from(2));
	assert_eq!(run.unread, typed.len(), "nothing typed was read");
	assert_eq!(run.stderr, "", "no password question for an unknown name");
}

#[test]
fn account_password_asks_twice_for_a_known_name() {
	let (_dir, cfg) = with_alice();
	let pty = Pty::open();
	let strong = crate::test_fixtures::second_password();
	let run = scripted(
		true,
		Some(pty.slave),
		format!("{strong}\n{strong}\n"),
		|| {
			account::run(
				cfg.path(),
				account::Subcommand::Password {
					name: NAME.to_string(),
				},
				false,
				&mut Vec::new(),
			)
		},
	);
	assert_eq!(run.value, ExitCode::SUCCESS, "{}", run.stderr);
	assert_eq!(run.stderr, asked_twice(NAME));
	assert!(pty.echo_on());
}

#[test]
fn account_show_reads_a_static_account() {
	let (_dir, cfg) = fixture("[[accounts]]\nname = \"bob\"\naddresses = [\"bob@example.org\"]\n");
	let mut out = Vec::new();
	let code = account::run(
		cfg.path(),
		account::Subcommand::Show {
			name: "bob".to_string(),
			json: false,
		},
		false,
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	let shown = String::from_utf8(out).expect("utf-8");
	assert!(shown.contains("name: bob\n"), "{shown}");
	assert!(shown.contains("source: static\n"), "{shown}");
	assert!(shown.contains("addresses: bob@example.org\n"), "{shown}");
}
