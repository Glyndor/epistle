use super::read_or_init;
use crate::util::path_component::{AccountName, AccountRoot};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

fn root(data: &Path) -> AccountRoot {
	std::fs::create_dir_all(data.join("accounts/alice")).unwrap();
	AccountName::new("alice").unwrap().root(data).unwrap()
}

fn folder(root: &AccountRoot, name: &str) -> PathBuf {
	let dir = root.as_path().join("folders").join(name).join("new");
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

/// Run `open` for every directory at once from its own thread.
fn race(root: &AccountRoot, dirs: Vec<PathBuf>) -> Vec<u32> {
	let barrier = Arc::new(Barrier::new(dirs.len()));
	let handles: Vec<_> = dirs
		.into_iter()
		.map(|dir| {
			let (barrier, root) = (Arc::clone(&barrier), root.clone());
			std::thread::spawn(move || {
				barrier.wait();
				read_or_init(&dir, &root)
			})
		})
		.collect();
	handles.into_iter().map(|h| h.join().unwrap()).collect()
}

#[test]
fn concurrent_creators_never_share_a_value() {
	for _ in 0..20 {
		let data = tempfile::tempdir().unwrap();
		let root = root(data.path());
		let dirs = (0..16).map(|i| folder(&root, &format!("box{i}"))).collect();
		let values = race(&root, dirs);
		let distinct: HashSet<u32> = values.iter().copied().collect();
		assert_eq!(distinct.len(), values.len(), "{values:?}");
	}
}

#[test]
fn concurrent_openers_of_one_mailbox_agree() {
	for _ in 0..20 {
		let data = tempfile::tempdir().unwrap();
		let root = root(data.path());
		let dir = folder(&root, "box");
		let values = race(&root, vec![dir.clone(); 16]);
		assert!(values.iter().all(|v| *v == values[0]), "{values:?}");
		assert_eq!(read_or_init(&dir, &root), values[0]);
	}
}

#[test]
fn a_lost_counter_does_not_go_below_a_mailbox_in_use() {
	let data = tempfile::tempdir().unwrap();
	let root = root(data.path());
	let ahead = u32::MAX - 11;
	let used = folder(&root, "used");
	std::fs::write(used.join(".uidvalidity"), ahead.to_string()).unwrap();
	for counter in [None, Some("not a number"), Some("")] {
		let path = root.as_path().join(".uidvalidity_last");
		match counter {
			Some(text) => std::fs::write(&path, text).unwrap(),
			None => {
				let _ = std::fs::remove_file(&path);
			}
		}
		let fresh = folder(&root, &format!("fresh{}", counter.map_or(0, str::len)));
		let value = read_or_init(&fresh, &root);
		assert!(value > ahead, "{counter:?}: {value} after {ahead}");
		std::fs::write(used.join(".uidvalidity"), value.to_string()).unwrap();
	}
}
