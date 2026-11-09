//! A rename is durable only once the directory that holds the new name is
//! synced: the helper does it, and every rename that publishes a spool file
//! is followed by it.

use std::path::Path;

use super::super::durability::{sync_dir, sync_dir_of};

#[test]
fn a_directory_can_be_synced_and_a_missing_one_is_an_error() {
	let dir = tempfile::tempdir().expect("tempdir");
	sync_dir(dir.path()).expect("an existing directory syncs");
	let file = dir.path().join("name");
	std::fs::write(&file, b"x").expect("file");
	sync_dir_of(&file).expect("the directory of a file syncs");
	assert!(sync_dir(&dir.path().join("absent")).is_err());
	assert!(sync_dir_of(Path::new("/")).is_ok());
}

/// Every `fs::rename` of the spool code is followed, on the same line or the next
/// lines, by the sync of the directory that now holds the name. The renames
/// that publish a file are the ones that need it; a new rename without it
/// fails here and has to be looked at.
#[test]
fn every_rename_of_the_spool_is_followed_by_a_directory_sync() {
	let folder = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/storage/spool");
	let mut checked = 0;
	for entry in std::fs::read_dir(&folder).expect("spool sources") {
		let path = entry.expect("entry").path();
		if path.extension().and_then(|e| e.to_str()) != Some("rs") {
			continue;
		}
		let text = std::fs::read_to_string(&path).expect("source");
		let lines: Vec<&str> = text.lines().collect();
		for (index, line) in lines.iter().enumerate() {
			if !line.contains("fs::rename(") || line.trim_start().starts_with("//") {
				continue;
			}
			checked += 1;
			let window = lines[index..lines.len().min(index + 2)].join("\n");
			assert!(
				window.contains("sync_dir_of("),
				"{}:{} renames without syncing the directory",
				path.display(),
				index + 1
			);
		}
	}
	assert!(
		checked >= 4,
		"the scan found {checked} renames, not the four"
	);
}
