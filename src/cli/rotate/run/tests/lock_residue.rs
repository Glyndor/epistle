//! A run that ends before it has anything to keep, refused or answered no,
//! leaves the data directory as it found it, and the next run starts
//! normally; a lock someone else holds is never removed.

use std::path::Path;
use std::process::ExitCode;

use super::super::{Options, Scope, execute, lock};
use super::fixture::{rotate_dir, run_scoped, server};
use crate::cli::prompt::script::scripted;
use crate::cli::stack::StackAction;
use crate::config::Config;

const NOW: u64 = 1_900_000_000;

/// One run of the accounts reset without `--yes`.
fn ask(config: &Path) -> (ExitCode, String) {
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let options = Options {
		yes: false,
		json: true,
		now: NOW,
		scope: Scope::Accounts,
	};
	let code = execute(
		config,
		options,
		&mut out,
		&mut status,
		|_: &Config, _: StackAction| ExitCode::SUCCESS,
	);
	(code, String::from_utf8(status).unwrap())
}

#[test]
fn a_run_refused_for_lack_of_yes_leaves_no_lock_and_the_next_run_starts() {
	let server = server();
	assert!(!rotate_dir(&server).exists());
	let (code, _) = ask(&server.config);
	assert_eq!(code, ExitCode::from(2));
	assert!(
		!rotate_dir(&server).exists(),
		"the refusal left {} behind",
		rotate_dir(&server).display()
	);
	let ran = run_scoped(&server.config, NOW, Scope::Accounts);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
}

#[test]
fn a_no_at_the_question_leaves_no_lock_either() {
	let server = server();
	let run = scripted(true, None, "n\n", || ask(&server.config));
	assert_ne!(run.value.0, ExitCode::SUCCESS);
	assert!(!rotate_dir(&server).exists());
	let ran = run_scoped(&server.config, NOW, Scope::Accounts);
	assert_eq!(ran.code, ExitCode::SUCCESS, "{}", ran.status);
}

#[test]
fn a_lock_that_another_run_holds_is_reported_and_kept() {
	let server = server();
	let held = lock(&server.data_dir)
		.expect("lock")
		.expect("nobody holds it yet");
	let (code, _) = ask(&server.config);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(
		rotate_dir(&server).join("lock").exists(),
		"the holder's lock file was removed"
	);
	let ran = run_scoped(&server.config, NOW, Scope::Accounts);
	assert_eq!(ran.code, ExitCode::FAILURE);
	drop(held);
}
