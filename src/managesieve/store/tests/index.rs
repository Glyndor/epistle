//! Ids and the change counter: what JMAP needs to follow scripts that
//! ManageSieve may rename, rewrite and delete at any time.

use super::*;

fn store(dir: &std::path::Path) -> ScriptStore {
	ScriptStore::new(dir, "alice")
}

fn info(s: &ScriptStore, name: &str) -> ScriptInfo {
	s.list()
		.expect("list")
		.into_iter()
		.find(|script| script.name == name)
		.unwrap_or_else(|| panic!("{name} is listed"))
}

fn is_id(id: &str) -> bool {
	id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

#[test]
fn a_script_keeps_its_id_through_a_rewrite_and_a_rename() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("work", "keep;\r\n").expect("put");
	let first = info(&s, "work");
	assert!(is_id(&first.id), "an id is 32 hex digits");
	assert_eq!(first.rev, 1);
	s.put("work", "discard;\r\n").expect("rewrite");
	let second = info(&s, "work");
	assert_eq!((second.id.as_str(), second.rev), (first.id.as_str(), 2));
	s.rename("work", "main").expect("rename");
	let third = info(&s, "main");
	assert_eq!((third.id.as_str(), third.rev), (first.id.as_str(), 2));
}

#[test]
fn two_scripts_never_share_an_id_and_a_deleted_one_is_not_reused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("a", "keep;\r\n").expect("a");
	s.put("b", "keep;\r\n").expect("b");
	let (a, b) = (info(&s, "a"), info(&s, "b"));
	assert_ne!(a.id, b.id);
	s.delete("a").expect("delete");
	s.put("a", "keep;\r\n").expect("again");
	assert_ne!(info(&s, "a").id, a.id, "a new script is a new id");
}

#[test]
fn the_state_moves_with_every_change_and_only_then() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	let mut last = s.state().expect("state");
	let mut moved = |label: &str, expect_move: bool| {
		let now = s.state().expect("state");
		assert_eq!(now != last, expect_move, "{label}");
		last = now;
	};
	s.put("a", "keep;\r\n").expect("put");
	moved("put", true);
	s.list().expect("list");
	s.get("a").expect("get");
	moved("reading", false);
	assert!(s.put("a", "if if if").is_err());
	assert!(s.put("b/c", "keep;\r\n").is_err());
	moved("a refused put", false);
	s.put("a", "discard;\r\n").expect("rewrite");
	moved("rewrite", true);
	s.set_active(Some("a")).expect("activate");
	moved("activate", true);
	s.set_active(Some("a")).expect("activate again");
	moved("activating the active script again", false);
	s.rename("a", "b").expect("rename");
	moved("rename", true);
	assert!(s.delete("b").is_err());
	moved("a refused delete", false);
	s.set_active(None).expect("deactivate");
	moved("deactivate", true);
	s.set_active(None).expect("deactivate again");
	moved("deactivating nothing", false);
	s.delete("b").expect("delete");
	moved("delete", true);
}

#[test]
fn every_store_on_the_account_sees_the_same_scripts_and_state() {
	// ManageSieve and JMAP each open their own store on the same directory.
	let dir = tempfile::tempdir().expect("tempdir");
	let (managesieve, jmap) = (store(dir.path()), store(dir.path()));
	managesieve.put("work", "keep;\r\n").expect("put");
	assert_eq!(jmap.state(), managesieve.state());
	let seen = info(&jmap, "work");
	jmap.rename("work", "main").expect("rename");
	let again = info(&managesieve, "main");
	assert_eq!(again.id, seen.id, "the id follows the rename across stores");
	assert_eq!(jmap.state(), managesieve.state());
}

#[test]
fn a_script_dropped_into_the_directory_is_adopted_with_an_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("a", "keep;\r\n").expect("put");
	let before = s.state().expect("state");
	let sieve = dir.path().join("alice/sieve");
	std::fs::write(sieve.join("found.sieve"), "keep;\r\n").expect("write");
	let found = info(&s, "found");
	assert!(is_id(&found.id));
	assert_ne!(
		s.state().expect("state"),
		before,
		"a new script moves the state"
	);
	assert_eq!(info(&s, "found").id, found.id, "and keeps its id");
}

#[test]
fn a_script_removed_from_the_directory_leaves_the_listing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("a", "keep;\r\n").expect("put");
	let id = info(&s, "a").id;
	let before = s.state().expect("state");
	std::fs::remove_file(dir.path().join("alice/sieve/a.sieve")).expect("remove");
	assert!(s.list().expect("list").is_empty());
	assert_ne!(s.state().expect("state"), before);
	s.put("a", "keep;\r\n").expect("again");
	assert_ne!(info(&s, "a").id, id);
}

#[test]
fn a_damaged_index_costs_the_ids_and_nothing_else() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("a", "keep;\r\n").expect("put");
	s.set_active(Some("a")).expect("activate");
	std::fs::write(dir.path().join("alice/sieve/.index.json"), "{ not json").expect("damage");
	let a = info(&s, "a");
	assert!(is_id(&a.id));
	assert!(a.active);
	assert_eq!(s.get("a").expect("get"), "keep;\r\n");
}

#[test]
fn names_that_could_not_have_been_stored_are_not_listed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("ok", "keep;\r\n").expect("put");
	let sieve = dir.path().join("alice/sieve");
	std::fs::write(sieve.join("bad\u{2028}name.sieve"), "keep;\r\n").expect("write");
	std::fs::write(
		sieve.join(format!("{}.sieve", "n".repeat(220))),
		"keep;\r\n",
	)
	.expect("long");
	let names: Vec<String> = s
		.list()
		.expect("list")
		.into_iter()
		.map(|i| i.name)
		.collect();
	assert_eq!(names, vec!["ok".to_string()]);
}

#[test]
fn concurrent_writers_cannot_overfill_the_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().to_path_buf();
	let outcomes: Vec<bool> = (0..MAX_SCRIPTS + 30)
		.map(|n| {
			let root = root.clone();
			std::thread::spawn(move || {
				ScriptStore::new(&root, "alice")
					.put(&format!("s{n}"), "keep;\r\n")
					.is_ok()
			})
		})
		.collect::<Vec<_>>()
		.into_iter()
		.map(|handle| handle.join().expect("join"))
		.collect();
	let stored = outcomes.iter().filter(|ok| **ok).count();
	let s = store(dir.path());
	assert_eq!(stored, MAX_SCRIPTS, "exactly the limit gets in");
	assert_eq!(s.list().expect("list").len(), MAX_SCRIPTS);
	assert_eq!(s.state().expect("state"), MAX_SCRIPTS as u64);
	let ids: std::collections::BTreeSet<String> =
		s.list().expect("list").into_iter().map(|i| i.id).collect();
	assert_eq!(ids.len(), MAX_SCRIPTS, "no two share an id");
}

#[test]
fn no_staging_file_is_left_behind() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("a", "keep;\r\n").expect("put");
	s.set_active(Some("a")).expect("activate");
	s.rename("a", "b").expect("rename");
	for directory in ["alice", "alice/sieve"] {
		let leftovers: Vec<String> = std::fs::read_dir(dir.path().join(directory))
			.expect("read_dir")
			.flatten()
			.map(|entry| entry.file_name().to_string_lossy().into_owned())
			.filter(|name| name.ends_with(".tmp"))
			.collect();
		assert!(leftovers.is_empty(), "{directory}: {leftovers:?}");
	}
}
