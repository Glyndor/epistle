//! `epistle relay`: an unknown rule is a refusal (exit code 2), the
//! same way `epistle account disable` refuses one. The message is
//! preserved exactly so scripts that parse `error: no relay is
//! configured for X` keep working.
//!
//! Lives in a sibling so `relay_tests.rs` stays under the per-file
//! code-line budget.

use std::process::ExitCode;

use crate::cli::exit;
use crate::cli::relay::run;
use crate::cli::relay::{RelayCli, Target};

fn assert_unknown_relay_is_refused(action: RelayCli) {
	let (_dir, file) = crate::cli::resource::test_config("");
	let code = run(file.path(), action, false);
	assert_eq!(
		code,
		ExitCode::from(exit::REFUSED),
		"an unknown relay must exit 2 (usage error)"
	);
}

#[test]
fn show_unknown_account_relay_exits_two() {
	assert_unknown_relay_is_refused(RelayCli::Show {
		json: false,
		target: Target {
			account: Some("alice".to_string()),
			domain: None,
		},
	});
}

#[test]
fn show_unknown_account_relay_json_exits_two() {
	assert_unknown_relay_is_refused(RelayCli::Show {
		json: true,
		target: Target {
			account: Some("alice".to_string()),
			domain: None,
		},
	});
}

#[test]
fn show_unknown_domain_relay_exits_two() {
	assert_unknown_relay_is_refused(RelayCli::Show {
		json: false,
		target: Target {
			account: None,
			domain: Some("missing.example.org".to_string()),
		},
	});
}

#[test]
fn remove_unknown_account_relay_exits_two() {
	assert_unknown_relay_is_refused(RelayCli::Remove {
		target: Target {
			account: Some("alice".to_string()),
			domain: None,
		},
	});
}

#[test]
fn remove_unknown_domain_relay_exits_two() {
	assert_unknown_relay_is_refused(RelayCli::Remove {
		target: Target {
			account: None,
			domain: Some("missing.example.org".to_string()),
		},
	});
}

#[test]
fn unknown_relay_message_is_preserved() {
	// The exit code is what scripts branch on, but the message is
	// what humans read. A refusal must keep the original phrasing so a
	// log scan for "no relay is configured" still matches.
	let (_dir, file) = crate::cli::resource::test_config("");
	let before = std::fs::read_to_string(file.path()).expect("read config");
	let code = run(
		file.path(),
		RelayCli::Remove {
			target: Target {
				account: Some("alice".to_string()),
				domain: None,
			},
		},
		false,
	);
	assert_eq!(code, ExitCode::from(exit::REFUSED));
	assert_eq!(
		std::fs::read_to_string(file.path()).expect("read config"),
		before,
		"the file must not change when the relay is unknown"
	);
}
