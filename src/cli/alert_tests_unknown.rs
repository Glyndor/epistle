//! `epistle alert`: an unknown rule is a refusal (exit code 2), the
//! same way `epistle account disable` refuses one. The message is
//! preserved exactly so scripts that parse `error: no alert named "X"`
//! keep working.
//!
//! Lives in a sibling so `alert_tests.rs` stays under the per-file
//! code-line budget.

use std::process::ExitCode;

use crate::cli::exit;
use crate::cli::resource::ResourceError;
use crate::cli::resource::test_config;

use super::{AlertCli, run};

fn assert_unknown_alert_is_refused(action: AlertCli) {
	let (_dir, file) = test_config("");
	let code = run(file.path(), action, false, false);
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
fn unknown_alert_keeps_its_message_and_leaves_the_config_alone() {
	// Scripts branch on the exit code, people read the message: the
	// refusal keeps the phrasing a log scan for "no alert named"
	// matches.
	let (_dir, file) = test_config("");
	let before = std::fs::read_to_string(file.path()).expect("read config");
	let result = super::execute_with(
		file.path(),
		AlertCli::Remove {
			name: "nope".to_string(),
		},
		false,
		false,
		&mut Vec::new(),
		&mut Vec::new(),
		|_, _| panic!("a refused removal must not restart anything"),
	);
	let Err(ResourceError::Refusal(message)) = result else {
		panic!("an unknown alert must be a refusal");
	};
	assert_eq!(message, "no alert named \"nope\"");
	assert_eq!(
		std::fs::read_to_string(file.path()).expect("read config"),
		before,
		"the file must not change when the alert is unknown"
	);
}
