use std::os::unix::fs::PermissionsExt;

use super::*;

fn mode(path: &Path) -> u32 {
	std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

#[test]
fn the_state_survives_a_write_and_a_read_at_mode_0600() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert!(load(dir.path()).expect("no file yet").is_none());
	let mut state = State::new(20_375);
	let gmail = state.group_mut(Group::Gmail);
	gmail.cap = Some(75);
	gmail.sent = 12;
	gmail.senders.insert("account:alice".into(), 12);
	gmail.raise = Some(Raise {
		from: 50,
		trial_day: 20_376,
	});
	save(dir.path(), &state).expect("save");
	assert_eq!(mode(&path(dir.path())), 0o600);
	assert_eq!(load(dir.path()).expect("load"), Some(state));
}

#[test]
fn a_file_others_can_write_is_not_trusted() {
	let dir = tempfile::tempdir().expect("tempdir");
	save(dir.path(), &State::new(1)).expect("save");
	for loose in [0o620, 0o602, 0o666] {
		std::fs::set_permissions(path(dir.path()), std::fs::Permissions::from_mode(loose))
			.expect("chmod");
		let error = load(dir.path()).expect_err("a loose file is refused");
		assert!(
			matches!(error, ReadError::Insecure(_)),
			"{loose:o}: {error}"
		);
	}
	// Readable by others but writable only by us is still ours.
	std::fs::set_permissions(path(dir.path()), std::fs::Permissions::from_mode(0o644))
		.expect("chmod");
	assert!(load(dir.path()).expect("0644 is read").is_some());
}

#[test]
fn a_link_in_place_of_the_file_is_not_followed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let elsewhere = dir.path().join("elsewhere.json");
	save(dir.path(), &State::new(1)).expect("save");
	std::fs::rename(path(dir.path()), &elsewhere).expect("move");
	std::os::unix::fs::symlink(&elsewhere, path(dir.path())).expect("link");
	let error = load(dir.path()).expect_err("a link is refused");
	assert!(matches!(error, ReadError::Insecure(_)), "{error}");
	// A save replaces the link itself, never the file it points at.
	let mut state = State::new(2);
	state.group_mut(Group::Gmail).cap = Some(10);
	save(dir.path(), &state).expect("save over the link");
	assert_eq!(load(dir.path()).expect("load"), Some(state));
	assert_eq!(
		serde_json::from_slice::<State>(&std::fs::read(&elsewhere).expect("read")).expect("parse"),
		State::new(1)
	);
}

#[test]
fn a_file_that_does_not_parse_or_is_too_large_is_not_trusted() {
	let dir = tempfile::tempdir().expect("tempdir");
	crate::storage::write_secret(
		&path(dir.path()),
		b"{\"day\": 1, \"groups\": {\"hotmail\": {}}}",
	)
	.expect("write");
	assert!(matches!(load(dir.path()), Err(ReadError::Corrupt(..))));
	crate::storage::write_secret(&path(dir.path()), &vec![b' '; MAX_STATE_BYTES as usize + 1])
		.expect("write");
	assert!(matches!(load(dir.path()), Err(ReadError::TooLarge(_))));
}

#[test]
fn a_distrusted_state_lets_nothing_more_go_today() {
	let state = State::distrusted(7);
	for group in Group::ALL {
		let schedule = state.group(group);
		assert_eq!((schedule.cap, schedule.sent), (Some(START_CAP), START_CAP));
	}
}

#[test]
fn history_and_senders_are_bounded() {
	let mut schedule = GroupState::default();
	for day in 0..(MAX_HISTORY as i64 + 10) {
		schedule.remember(DayRecord {
			day,
			cap: Some(50),
			sent: 1,
			attempted: 1,
			deferred: 0,
			bounced: 0,
			spam_blocks: 0,
			verdict: Verdict::Good,
			next_cap: Some(50),
			raise: None,
			paused: false,
			causes: Vec::new(),
		});
	}
	assert_eq!(schedule.history.len(), MAX_HISTORY);
	assert_eq!(schedule.history.front().map(|record| record.day), Some(10));
	for n in 0..MAX_SENDERS {
		let key = schedule.sender_key(&format!("account:{n}")).to_string();
		schedule.senders.insert(key, 1);
	}
	assert_eq!(schedule.sender_key("account:late"), OVERFLOW_SENDER);
	assert_eq!(schedule.sender_key("account:7"), "account:7");
}

#[test]
fn a_cap_this_server_never_writes_is_not_trusted() {
	use super::super::policy::MAX_CAP;
	for (cap, from) in [
		(Some(0), None),
		(Some(MAX_CAP + 1), None),
		(Some(100), Some(0)),
	] {
		let dir = tempfile::tempdir().expect("tempdir");
		let mut state = State::new(20_375);
		let gmail = state.group_mut(Group::Gmail);
		gmail.cap = cap;
		gmail.raise = from.map(|from| Raise {
			from,
			trial_day: 20_376,
		});
		save(dir.path(), &state).expect("save");
		assert!(
			matches!(load(dir.path()), Err(ReadError::Corrupt(..))),
			"cap {cap:?}, raise from {from:?}"
		);
	}
}
