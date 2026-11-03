//! The state lists the values a refresh may remove from the zone, so it is
//! read only from a regular file at its own name: a symlink there, which
//! the mail container could leave before a stack splits, is not followed,
//! and saving never writes through a link left at the temporary name.

use super::support::HOST;
use super::*;

const PLANTED: &str = "3 0 1 00000000000000000000000000000000000000000000000000000000000000aa";

fn planted() -> State {
	State {
		hostname: HOST.to_string(),
		pending: None,
		managed: vec![PLANTED.to_string()],
	}
}

#[test]
fn a_state_reached_through_a_symlink_is_not_trusted() {
	let elsewhere = tempfile::tempdir().expect("dir");
	planted().save(elsewhere.path()).expect("save");
	// The premise: the same file, read at its own name, gives the values.
	assert_eq!(State::load(elsewhere.path(), HOST).managed, [PLANTED]);

	let dir = tempfile::tempdir().expect("dir");
	std::fs::create_dir_all(dir.path().join("dns-tlsa")).expect("dns-tlsa");
	std::os::unix::fs::symlink(state_path(elsewhere.path()), state_path(dir.path())).expect("link");

	let state = State::load(dir.path(), HOST);
	assert!(state.managed.is_empty(), "followed the link");
	assert_eq!(state.pending, None);
}

#[test]
fn saving_replaces_a_link_at_the_temporary_name_instead_of_writing_through_it() {
	let dir = tempfile::tempdir().expect("dir");
	let victim = dir.path().join("victim");
	std::fs::write(&victim, "kept").expect("victim");
	std::fs::create_dir_all(dir.path().join("dns-tlsa")).expect("dns-tlsa");
	let staging = state_path(dir.path()).with_extension("json.new");
	std::os::unix::fs::symlink(&victim, &staging).expect("link");

	planted().save(dir.path()).expect("save");

	assert_eq!(std::fs::read_to_string(&victim).expect("victim"), "kept");
	assert!(!staging.exists(), "the temporary file was renamed");
	assert_eq!(State::load(dir.path(), HOST).managed, [PLANTED]);
}
