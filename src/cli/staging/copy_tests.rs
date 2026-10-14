use super::*;

fn dir(path: &Path) -> File {
	open_node(path, path).unwrap().dir().unwrap()
}

#[test]
fn clear_removes_links_and_never_their_targets() {
	let (staging, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	let kept = outside.path().join("kept");
	fs::create_dir_all(kept.join("inner")).unwrap();
	fs::write(kept.join("inner/file"), "kept").unwrap();
	fs::create_dir_all(staging.path().join("sub/deeper")).unwrap();
	fs::write(staging.path().join("sub/deeper/file"), "gone").unwrap();
	std::os::unix::fs::symlink(&kept, staging.path().join("link")).unwrap();
	std::os::unix::fs::symlink(&kept, staging.path().join("sub/link")).unwrap();
	clear(&dir(staging.path())).unwrap();
	assert_eq!(fs::read_dir(staging.path()).unwrap().count(), 0);
	assert_eq!(fs::read_to_string(kept.join("inner/file")).unwrap(), "kept");
}

#[test]
fn open_beneath_takes_no_link_on_the_way() {
	let (staging, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
	fs::write(outside.path().join("out"), "outside").unwrap();
	std::os::unix::fs::symlink(outside.path(), staging.path().join("0")).unwrap();
	let handle = dir(staging.path());
	assert!(open_beneath(&handle, Path::new("0/out"), Source::Operator).is_err());
	fs::remove_file(staging.path().join("0")).unwrap();
	fs::create_dir(staging.path().join("0")).unwrap();
	fs::write(staging.path().join("0/out"), "inside").unwrap();
	let mut text = String::new();
	open_beneath(&handle, Path::new("0/out"), Source::Operator)
		.unwrap()
		.file()
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
	let handle = dir(&home.path().join("stage"));
	fs::rename(home.path().join("stage"), home.path().join("moved")).unwrap();
	fs::create_dir(home.path().join("stage")).unwrap();
	make_dir(&handle, "0").unwrap();
	assert!(home.path().join("moved/0").is_dir());
	assert!(!home.path().join("stage/0").exists());
}

#[test]
fn an_entry_swapped_for_a_link_after_it_is_opened_is_not_read_through() {
	// Between the open and the read, the entry `a` becomes a link to a file
	// the copy must not take: the copy reads the inode it opened.
	let (source, target, outside) = (
		tempfile::tempdir().unwrap(),
		tempfile::tempdir().unwrap(),
		tempfile::tempdir().unwrap(),
	);
	let secret = outside.path().join("shadow");
	fs::write(&secret, "root only").unwrap();
	let entry = source.path().join("a");
	fs::write(&entry, "mail").unwrap();
	let (swap, aside) = (entry.clone(), outside.path().join("a.orig"));
	hook::set(Some(Box::new(move |shown: &Path| {
		if shown == swap && !aside.exists() {
			fs::rename(&swap, &aside).unwrap();
			std::os::unix::fs::symlink(&secret, &swap).unwrap();
		}
	})));
	let mut budget = Budget::new(1024 + 4 * ENTRY_COST, source.path());
	let copied = copy_tree(
		&dir(source.path()),
		&dir(target.path()),
		source.path(),
		Path::new(""),
		&mut budget,
		&|_, _| Ok(()),
	);
	hook::set(None);
	copied.unwrap();
	assert!(
		fs::symlink_metadata(&entry)
			.unwrap()
			.file_type()
			.is_symlink(),
		"the hook swapped the entry"
	);
	assert_eq!(fs::read_to_string(target.path().join("a")).unwrap(), "mail");
}

#[test]
fn sizes_read_in_the_largest_whole_unit() {
	assert_eq!(size(4 * 1024 * 1024 * 1024), "4 GiB");
	assert_eq!(size(64 * 1024 * 1024), "64 MiB");
	assert_eq!(size(10), "10 bytes");
}

/// Copy `source` into a fresh directory with a byte budget of `limit`.
fn copy_with_limit(source: &Path, limit: u64) -> io::Result<()> {
	let target = tempfile::tempdir().unwrap();
	let mut budget = Budget::new(limit, source);
	copy_tree(
		&dir(source),
		&dir(target.path()),
		source,
		Path::new(""),
		&mut budget,
		&|_, _| Ok(()),
	)
}

#[test]
fn empty_entries_cost_a_block_each() {
	let source = tempfile::tempdir().unwrap();
	for index in 0..10 {
		fs::write(source.path().join(format!("empty{index}")), "").unwrap();
	}
	// Ten empty files hold no bytes, but each costs a block and an inode.
	assert!(copy_with_limit(source.path(), 10 * ENTRY_COST).is_ok());
	assert!(copy_with_limit(source.path(), 10 * ENTRY_COST - 1).is_err());
}

#[test]
fn a_tree_deeper_than_the_bound_is_refused() {
	let source = tempfile::tempdir().unwrap();
	let mut path = source.path().to_path_buf();
	for _ in 0..=MAX_DEPTH {
		path.push("d");
	}
	fs::create_dir_all(&path).unwrap();
	let error = copy_with_limit(source.path(), u64::MAX).unwrap_err();
	assert!(error.to_string().contains("directories deep"), "{error}");
	let mut shallow = source.path().join("ok");
	for _ in 0..MAX_DEPTH - 1 {
		shallow.push("d");
	}
	let ok = tempfile::tempdir().unwrap();
	fs::create_dir_all(ok.path().join(shallow.strip_prefix(source.path()).unwrap())).unwrap();
	assert!(copy_with_limit(ok.path(), u64::MAX).is_ok());
}
