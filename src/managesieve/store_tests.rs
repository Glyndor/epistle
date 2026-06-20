//! Tests for the ManageSieve script store.

use super::*;

fn store(dir: &std::path::Path) -> ScriptStore {
	ScriptStore::new(dir, "alice")
}

const SCRIPT: &str = "keep;\r\n";

#[test]
fn put_get_list_roundtrip() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	assert!(s.list().expect("list").is_empty());
	s.put("work", SCRIPT).expect("put");
	assert_eq!(s.get("work").expect("get"), SCRIPT);
	let list = s.list().expect("list");
	assert_eq!(list.len(), 1);
	assert_eq!(list[0].name, "work");
	assert!(!list[0].active);
}

#[test]
fn invalid_script_is_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	let result = s.put("bad", "if if if");
	assert!(matches!(result, Err(StoreError::InvalidScript(_))));
	// Nothing was stored.
	assert!(matches!(s.get("bad"), Err(StoreError::NoSuchScript)));
}

#[test]
fn rejects_path_traversal_names() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	for name in ["", "..", ".", "a/b", "a\\b", "x\ny"] {
		assert_eq!(
			s.put(name, SCRIPT),
			Err(StoreError::InvalidName),
			"{name:?}"
		);
	}
}

#[test]
fn set_active_mirrors_to_filter_and_lists_active() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("work", SCRIPT).expect("put");
	s.set_active(Some("work")).expect("activate");
	assert_eq!(s.active_name().as_deref(), Some("work"));
	// The live filter the delivery path reads is updated.
	let live = std::fs::read_to_string(dir.path().join("alice").join("filter.sieve"))
		.expect("filter.sieve");
	assert_eq!(live, SCRIPT);
	assert!(s.list().expect("list")[0].active);
}

#[test]
fn activating_missing_script_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	assert_eq!(s.set_active(Some("nope")), Err(StoreError::NoSuchScript));
}

#[test]
fn deactivate_removes_live_filter() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("work", SCRIPT).expect("put");
	s.set_active(Some("work")).expect("activate");
	s.set_active(None).expect("deactivate");
	assert!(s.active_name().is_none());
	assert!(!dir.path().join("alice").join("filter.sieve").exists());
}

#[test]
fn cannot_delete_active_script() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("work", SCRIPT).expect("put");
	s.set_active(Some("work")).expect("activate");
	assert_eq!(s.delete("work"), Err(StoreError::ActiveScript));
	// A non-active script deletes fine.
	s.put("draft", SCRIPT).expect("put");
	s.delete("draft").expect("delete");
	assert!(matches!(s.get("draft"), Err(StoreError::NoSuchScript)));
}

#[test]
fn delete_missing_script_fails() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	assert_eq!(s.delete("ghost"), Err(StoreError::NoSuchScript));
}

#[test]
fn put_updates_live_copy_when_active() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("work", "keep;\r\n").expect("put");
	s.set_active(Some("work")).expect("activate");
	s.put("work", "discard;\r\n").expect("re-put");
	let live = std::fs::read_to_string(dir.path().join("alice").join("filter.sieve"))
		.expect("filter.sieve");
	assert_eq!(live, "discard;\r\n");
}

#[test]
fn rename_moves_script_and_active_marker() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("work", SCRIPT).expect("put");
	s.set_active(Some("work")).expect("activate");
	s.rename("work", "main").expect("rename");
	assert_eq!(s.active_name().as_deref(), Some("main"));
	assert!(matches!(s.get("work"), Err(StoreError::NoSuchScript)));
	assert_eq!(s.get("main").expect("get"), SCRIPT);
}

#[test]
fn rename_rejects_existing_target_and_missing_source() {
	let dir = tempfile::tempdir().expect("tempdir");
	let s = store(dir.path());
	s.put("a", SCRIPT).expect("put a");
	s.put("b", SCRIPT).expect("put b");
	assert_eq!(s.rename("a", "b"), Err(StoreError::AlreadyExists));
	assert_eq!(s.rename("ghost", "c"), Err(StoreError::NoSuchScript));
}
