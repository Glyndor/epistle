//! `epistle alert`: an unknown rule is a refusal (exit code 2), the
//! same way `epistle account disable` refuses one. The message is
//! preserved exactly so scripts that parse `error: no alert named "X"`
//! keep working.
//!
//! Lives in a sibling so `alert_tests.rs` stays under the per-file
//! code-line budget.

use std::process::ExitCode;

use crate::cli::exit;
use crate::cli::resource::test_config;

use super::{AlertCli, run};

fn assert_unknown_alert_is_refused(action: AlertCli) {
	let (_dir, file) = test_config("");
	let code = run(file.path(), action, false);
	assert_eq!(
		code,
		ExitCode::from(exit::REFUSED),
		"an unknown alert must exit 2 (usage error)"
	);
}

#[test]
fn remove_unknown_alert_exits_two() {
	assert_unknown_alert_is_refused(AlertCli::Remove {
		name: "nope".to_string(),
	});
}

#[test]
fn unknown_alert_message_is_preserved() {
	// The exit code is what scripts branch on, but the message is
	// what humans read. A refusal must keep the original phrasing so a
	// log scan for "no alert named" still matches.
	let (_dir, file) = test_config("");
	let before = std::fs::read_to_string(file.path()).expect("read config");
	let code = run(
		file.path(),
		AlertCli::Remove {
			name: "nope".to_string(),
		},
		false,
	);
	assert_eq!(code, ExitCode::from(exit::REFUSED));
	assert_eq!(
		std::fs::read_to_string(file.path()).expect("read config"),
		before,
		"the file must not change when the alert is unknown"
	);
}
