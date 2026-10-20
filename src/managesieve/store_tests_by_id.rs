//! Creating, updating and destroying a script by its id.

use super::*;

fn store(dir: &std::path::Path) -> ScriptStore {
	ScriptStore::new(dir, "alice")
}

#[test]
fn create_never_overwrites_a_script_of_the_same_name() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	let first = s.create("work", "keep;\r\n").expect("create");
	assert_eq!((first.name.as_str(), first.rev), ("work", 1));
	assert_eq!(
		s.create("work", "discard;\r\n").map(|i| i.id),
		Err(StoreError::AlreadyExists)
	);
	assert_eq!(s.get("work").expect("get"), "keep;\r\n");
}

#[test]
fn racing_creates_of_one_name_have_one_winner() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().to_path_buf();
	let results: Vec<Result<String, StoreError>> = (0..16)
		.map(|n| {
			let root = root.clone();
			std::thread::spawn(move || {
				ScriptStore::new(&root, "alice")
					.create("same", &format!("# {n}\r\nkeep;\r\n"))
					.map(|info| info.id)
			})
		})
		.collect::<Vec<_>>()
		.into_iter()
		.map(|handle| handle.join().expect("join"))
		.collect();
	assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
	assert!(
		results
			.iter()
			.filter_map(|r| r.as_ref().err())
			.all(|e| *e == StoreError::AlreadyExists)
	);
}

#[test]
fn update_replaces_content_and_keeps_the_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	let made = s.create("work", "keep;\r\n").expect("create");
	s.set_active(Some("work")).expect("activate");
	let after = s
		.update(&made.id, None, Some("discard;\r\n"))
		.expect("update");
	assert_eq!(
		(after.id.as_str(), after.rev, after.active),
		(made.id.as_str(), 2, true)
	);
	assert_eq!(s.get("work").expect("get"), "discard;\r\n");
	let live = std::fs::read_to_string(dir.path().join("alice/filter.sieve")).expect("live");
	assert_eq!(
		live, "discard;\r\n",
		"the live filter follows an active script"
	);
}

#[test]
fn update_renames_and_the_active_marker_follows() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	let made = s.create("work", "keep;\r\n").expect("create");
	s.set_active(Some("work")).expect("activate");
	let after = s.update(&made.id, Some("main"), None).expect("rename");
	assert_eq!(
		(after.name.as_str(), after.id.as_str()),
		("main", made.id.as_str())
	);
	assert_eq!(s.active_name().as_deref(), Some("main"));
	let both = s
		.update(&made.id, Some("final"), Some("stop;\r\n"))
		.expect("both");
	assert_eq!((both.name.as_str(), both.rev), ("final", 2));
	assert_eq!(s.get("final").expect("get"), "stop;\r\n");
}

#[test]
fn an_update_that_is_refused_changes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	let a = s.create("a", "keep;\r\n").expect("a");
	s.create("b", "keep;\r\n").expect("b");
	let state = s.state().expect("state");
	assert_eq!(
		s.update(&a.id, Some("b"), Some("discard;\r\n"))
			.map(|i| i.id),
		Err(StoreError::AlreadyExists)
	);
	assert!(matches!(
		s.update(&a.id, Some("c"), Some("if if if")),
		Err(StoreError::InvalidScript(_))
	));
	assert_eq!(
		s.update(&a.id, Some("x/y"), None).map(|i| i.id),
		Err(StoreError::InvalidName)
	);
	assert_eq!(s.get("a").expect("get"), "keep;\r\n");
	assert!(matches!(s.get("c"), Err(StoreError::NoSuchScript)));
	assert_eq!(s.state().expect("state"), state);
}

#[test]
fn an_unknown_id_is_no_such_script() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	assert_eq!(
		s.update("nope", None, Some("keep;\r\n")).map(|i| i.id),
		Err(StoreError::NoSuchScript)
	);
	assert_eq!(s.destroy("nope"), Err(StoreError::NoSuchScript));
}

#[test]
fn destroy_refuses_the_active_script_and_removes_the_others() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	let work = s.create("work", "keep;\r\n").expect("work");
	let draft = s.create("draft", "keep;\r\n").expect("draft");
	s.set_active(Some("work")).expect("activate");
	assert_eq!(s.destroy(&work.id), Err(StoreError::ActiveScript));
	s.destroy(&draft.id).expect("destroy");
	assert!(matches!(s.get("draft"), Err(StoreError::NoSuchScript)));
	assert_eq!(s.get("work").expect("still there"), "keep;\r\n");
}

#[test]
fn an_id_belongs_to_one_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let alice = store(dir.path());
	let bob = ScriptStore::new(dir.path(), "bob");
	let made = alice.create("work", "keep;\r\n").expect("create");
	assert_eq!(
		bob.update(&made.id, Some("mine"), Some("discard;\r\n"))
			.map(|i| i.id),
		Err(StoreError::NoSuchScript)
	);
	assert_eq!(bob.destroy(&made.id), Err(StoreError::NoSuchScript));
	assert_eq!(alice.get("work").expect("untouched"), "keep;\r\n");
	assert!(bob.list().expect("list").is_empty());
}
