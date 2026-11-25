//! `evidence policy set` checks its arguments before it looks at the data
//! directory, so a value the policy refuses is exit code 2 whether or not
//! the directory has an evidence chain.

use std::process::ExitCode;

use crate::cli::evidence::PolicyCli;

fn set(
	root: &std::path::Path,
	class: &str,
	mode: crate::evidence::policy::Mode,
	days: u32,
) -> ExitCode {
	crate::cli::evidence::policy::run(
		root,
		PolicyCli::Set {
			class: class.into(),
			account: None,
			tenant: None,
			mode,
			days,
			json: false,
		},
		&mut Vec::new(),
	)
}

#[test]
fn days_the_policy_refuses_are_a_usage_error_with_no_chain_at_all() {
	use crate::evidence::policy::Mode;
	let dir = tempfile::tempdir().expect("tempdir");
	let nowhere = dir.path().join("no-evidence-here");
	for days in [0, 9151, u32::MAX] {
		assert_eq!(
			set(&nowhere, "marketing", Mode::Full, days),
			ExitCode::from(2),
			"{days}"
		);
	}
	assert_eq!(
		set(&nowhere, "transactional", Mode::Off, 0),
		ExitCode::from(2)
	);
	assert!(!nowhere.exists(), "nothing was created");
}

#[test]
fn a_good_rule_on_a_directory_without_a_chain_is_still_a_failure() {
	use crate::evidence::policy::Mode;
	let dir = tempfile::tempdir().expect("tempdir");
	let nowhere = dir.path().join("no-evidence-here");
	assert_eq!(
		set(&nowhere, "marketing", Mode::Full, 30),
		ExitCode::FAILURE
	);
}
