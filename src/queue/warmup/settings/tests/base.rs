use std::os::unix::fs::PermissionsExt;

use super::*;

#[test]
fn orders_are_numbered_and_one_per_group_is_kept() {
	let mut settings = Settings::default();
	settings.order(Group::Gmail, Action::Set { cap: 200 });
	settings.order(Group::Outlook, Action::Next);
	let last = settings.order(Group::Gmail, Action::Reset);
	assert_eq!(
		last,
		Order {
			seq: 3,
			group: Group::Gmail,
			action: Action::Reset
		}
	);
	assert_eq!(
		settings.orders,
		vec![
			Order {
				seq: 2,
				group: Group::Outlook,
				action: Action::Next
			},
			last
		]
	);
}

#[test]
fn the_file_is_written_at_0600_and_read_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(load(dir.path()).expect("no file"), None);
	let mut settings = Settings {
		enabled: true,
		..Settings::default()
	};
	settings.order(Group::Yahoo, Action::Set { cap: 120 });
	save(dir.path(), &settings).expect("save");
	let mode = std::fs::metadata(path(dir.path()))
		.expect("stat")
		.permissions()
		.mode();
	assert_eq!(mode & 0o777, 0o600);
	let text = std::fs::read_to_string(path(dir.path())).expect("read");
	assert_eq!(
		text,
		"{\n  \"enabled\": true,\n  \"paused\": false,\n  \"orders\": [\n    {\n      \"seq\": 1,\n      \"group\": \"yahoo\",\n      \"action\": {\n        \"set\": {\n          \"cap\": 120\n        }\n      }\n    }\n  ]\n}"
	);
	assert_eq!(load(dir.path()).expect("load"), Some(settings));
}

#[test]
fn a_file_that_says_what_the_cli_never_writes_is_refused() {
	let refused = [
		(r#"{"enabled": true, "extra": 1}"#, "unknown field"),
		(
			r#"{"orders": [{"seq": 1, "group": "hotmail", "action": "next"}]}"#,
			"unknown variant",
		),
		(
			r#"{"orders": [{"seq": 1, "group": "gmail", "action": {"set": {"cap": 0}}}]}"#,
			"cap 0 is not between 1 and 1000000",
		),
		(
			r#"{"orders": [{"seq": 1, "group": "gmail", "action": {"set": {"cap": 1000001}}}]}"#,
			"cap 1000001 is not between 1 and 1000000",
		),
		(
			r#"{"orders": [{"seq": 1, "group": "gmail", "action": "next"}, {"seq": 2, "group": "gmail", "action": "reset"}]}"#,
			"more than one order for gmail",
		),
		(
			r#"{"orders": [{"seq": 0, "group": "gmail", "action": "next"}]}"#,
			"an order's sequence starts at 1",
		),
	];
	for (text, why) in refused {
		let error = Settings::parse(text).expect_err(text);
		assert!(error.contains(why), "{text}: {error}");
	}
}

#[test]
fn a_loose_settings_file_is_not_trusted() {
	let dir = tempfile::tempdir().expect("tempdir");
	save(dir.path(), &Settings::default()).expect("save");
	std::fs::set_permissions(path(dir.path()), std::fs::Permissions::from_mode(0o666))
		.expect("chmod");
	assert!(matches!(load(dir.path()), Err(ReadError::Insecure(_))));
	assert_eq!(
		Settings::distrusted(),
		Settings {
			enabled: true,
			paused: false,
			orders: Vec::new()
		}
	);
}
