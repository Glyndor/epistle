//! `epistle relay`: an unknown rule is a refusal (exit code 2), the
//! same way `epistle account disable` refuses one. The message is
//! preserved exactly so scripts that parse `error: no relay is
//! configured for X` keep working.
//!
//! Lives in a separate leaf so `src/cli/relay/tests/base.rs` stays under the per-file
//! code-line budget.

use std::process::ExitCode;

use crate::cli::exit;
use crate::cli::relay::run;
use crate::cli::relay::{RelayCli, Target};
use crate::cli::resource::ResourceError;

fn assert_unknown_relay_is_refused(action: RelayCli) {
	let (_dir, file) = crate::cli::resource::test_config("");
	let code = run(file.path(), action, false, false);
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
fn unknown_relay_keeps_its_message_and_leaves_the_config_alone() {
	// Scripts branch on the exit code, people read the message: the
	// refusal keeps the phrasing a log scan for "no relay is
	// configured" matches.
	let (_dir, file) = crate::cli::resource::test_config("");
	let before = std::fs::read_to_string(file.path()).expect("read config");
	let result = super::execute_with(
		file.path(),
		RelayCli::Remove {
			target: Target {
				account: Some("alice".to_string()),
				domain: None,
			},
		},
		false,
		false,
		&mut std::io::empty(),
		&mut Vec::new(),
		&mut Vec::new(),
		|_, _| panic!("a refused removal must not restart anything"),
	);
	let Err(ResourceError::Refusal(message)) = result else {
		panic!("an unknown relay must be a refusal");
	};
	assert_eq!(message, "no relay is configured for account alice");
	assert_eq!(
		std::fs::read_to_string(file.path()).expect("read config"),
		before,
		"the file must not change when the relay is unknown"
	);
}
