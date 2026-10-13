use super::*;

#[test]
fn clear_removes_links_and_never_their_targets() {
	let (dir, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let kept = outside.path().join("kept");
	fs::create_dir_all(kept.join("inner")).unwrap();
	fs::write(kept.join("inner/file"), "kept").unwrap();
	fs::create_dir_all(dir.path().join("sub/deeper")).unwrap();
	fs::write(dir.path().join("sub/deeper/file"), "gone").unwrap();
	std::os::unix::fs::symlink(&kept, dir.path().join("link")).unwrap();
	std::os::unix::fs::symlink(&kept, dir.path().join("sub/link")).unwrap();
	clear(&open_dir(dir.path()).unwrap()).unwrap();
	assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
	assert_eq!(fs::read_to_string(kept.join("inner/file")).unwrap(), "kept");
}

#[test]
fn open_beneath_takes_no_link_on_the_way() {
	let (dir, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	fs::write(outside.path().join("out"), "outside").unwrap();
	std::os::unix::fs::symlink(outside.path(), dir.path().join("0")).unwrap();
	let handle = open_dir(dir.path()).unwrap();
	assert!(open_beneath(&handle, Path::new("0/out"), false).is_err());
	fs::remove_file(dir.path().join("0")).unwrap();
	fs::create_dir(dir.path().join("0")).unwrap();
	fs::write(dir.path().join("0/out"), "inside").unwrap();
	let mut text = String::new();
	open_beneath(&handle, Path::new("0/out"), false)
		.unwrap()
		.read_to_string(&mut text)
		.unwrap();
	assert_eq!(text, "inside");
}

#[test]
fn a_renamed_directory_is_still_the_one_written() {
	// The account owns the home and may rename the staging directory while
	// root copies into it: the copy follows the descriptor, not the name.
	let home = tempfile::tempdir().unwrap();
	fs::create_dir(home.path().join("stage")).unwrap();
	let handle = open_dir(&home.path().join("stage")).unwrap();
	fs::rename(home.path().join("stage"), home.path().join("moved")).unwrap();
	fs::create_dir(home.path().join("stage")).unwrap();
	make_dir(&handle, "0").unwrap();
	assert!(home.path().join("moved/0").is_dir());
	assert!(!home.path().join("stage/0").exists());
}

#[test]
fn sizes_read_in_the_largest_whole_unit() {
	assert_eq!(size(4 * 1024 * 1024 * 1024), "4 GiB");
	assert_eq!(size(64 * 1024 * 1024), "64 MiB");
	assert_eq!(size(10), "10 bytes");
}
