//! `decide` is what the plan reads, and `ensure` does the same: the plan must
//! not say one thing and the run do another, and the plan must write nothing.

use super::*;

#[test]
fn deciding_writes_nothing_and_says_what_a_first_run_would_do() {
	let layout = layout();
	let decision = decide(&layout.data, NOW).expect("decide");
	assert_eq!(
		decision,
		Decision {
			key: KeyAction::Create,
			session: SessionAction::Generate,
			admin_id: AdminIdAction::Generate,
		}
	);
	assert!(
		!layout
			.data
			.parent()
			.expect("parent")
			.join("secrets")
			.exists()
	);
	assert!(!layout.data.join("api_keys.toml").exists());
}

#[test]
fn the_decision_matches_what_the_run_then_does() {
	let layout = layout();
	let cases = [
		(
			NOW,
			KeyAction::Create,
			SessionAction::Generate,
			AdminIdAction::Generate,
		),
		(
			NOW + DAY,
			KeyAction::Reuse,
			SessionAction::Reuse,
			AdminIdAction::Reuse,
		),
		(
			NOW + 340 * DAY,
			KeyAction::Renew,
			SessionAction::Reuse,
			AdminIdAction::Reuse,
		),
	];
	for (now, key, session, admin_id) in cases {
		assert_eq!(
			decide(&layout.data, now).expect("decide"),
			Decision {
				key,
				session,
				admin_id
			}
		);
		run(&layout, now);
	}
	std::fs::remove_file(api_token_path(&layout.data)).expect("remove");
	assert_eq!(
		decide(&layout.data, NOW + 340 * DAY).expect("decide").key,
		KeyAction::Rotate
	);
}

#[test]
fn a_secret_that_cannot_be_used_is_refused_when_planning_too() {
	let layout = layout();
	let path = api_token_path(&layout.data);
	std::fs::create_dir_all(&path).expect("dir");
	assert!(decide(&layout.data, NOW).is_err());
}

#[test]
fn the_words_the_plan_prints_are_the_decisions() {
	assert_eq!(KeyAction::Create.to_string(), "create");
	assert_eq!(KeyAction::Reuse.to_string(), "reuse");
	assert_eq!(KeyAction::Renew.to_string(), "renew");
	assert_eq!(KeyAction::Rotate.to_string(), "replace the lost secret of");
	assert_eq!(SessionAction::Generate.to_string(), "generate");
	assert_eq!(SessionAction::Reuse.to_string(), "reuse");
}

#[test]
fn the_paths_list_every_file_the_module_owns() {
	let layout = layout();
	run(&layout, NOW);
	let secrets = layout.data.parent().expect("parent").join("secrets");
	let mut found: Vec<PathBuf> = std::fs::read_dir(&secrets)
		.expect("read_dir")
		.map(|entry| entry.expect("entry").path())
		.collect();
	found.sort();
	let mut owned = paths(&layout.data).to_vec();
	owned.sort();
	assert_eq!(
		found, owned,
		"no stray file, such as a staging copy, is left behind"
	);
}
