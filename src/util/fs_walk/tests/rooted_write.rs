use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::symlink;
use std::path::PathBuf;

use crate::util::fs_walk::rooted_write::{metadata, open_lock, write_atomic};

/// A `root` directory with a sibling `outside` one the writes must never reach.
struct Layout {
	_guard: tempfile::TempDir,
	root: PathBuf,
	outside: PathBuf,
}

fn layout() -> Layout {
	let guard = tempfile::tempdir().expect("tempdir");
	let root = guard.path().join("root");
	let outside = guard.path().join("outside");
	std::fs::create_dir(&root).expect("mkdir root");
	std::fs::create_dir(&outside).expect("mkdir outside");
	Layout {
		_guard: guard,
		root,
		outside,
	}
}

fn kind<T>(result: std::io::Result<T>) -> ErrorKind {
	match result {
		Ok(_) => panic!("the call must refuse this"),
		Err(error) => error.kind(),
	}
}

fn entries(dir: &std::path::Path) -> Vec<String> {
	let mut names: Vec<String> = std::fs::read_dir(dir)
		.expect("read_dir")
		.map(|entry| entry.expect("entry").file_name().to_string_lossy().into())
		.collect();
	names.sort();
	names
}

#[test]
fn write_atomic_creates_then_replaces_and_leaves_no_staging_file() {
	let l = layout();
	let file = l.root.join("state");
	write_atomic(&l.root, &file, b"one").expect("create");
	write_atomic(&l.root, &file, b"two").expect("replace");
	assert_eq!(std::fs::read(&file).expect("read"), b"two");
	assert_eq!(entries(&l.root), vec!["state"]);
}

#[test]
fn write_atomic_refuses_a_directory_that_is_a_link_out_of_the_root() {
	let l = layout();
	symlink(&l.outside, l.root.join("account")).expect("symlink");
	let target = l.root.join("account").join("state");
	assert_eq!(
		kind(write_atomic(&l.root, &target, b"x")),
		ErrorKind::InvalidInput
	);
	assert!(
		entries(&l.outside).is_empty(),
		"nothing was written outside"
	);
}

#[test]
fn write_atomic_refuses_a_dotdot_and_a_missing_directory() {
	let l = layout();
	let up = l.root.join("..").join("outside").join("state");
	assert_eq!(
		kind(write_atomic(&l.root, &up, b"x")),
		ErrorKind::InvalidInput
	);
	let missing = l.root.join("absent").join("state");
	assert_eq!(
		kind(write_atomic(&l.root, &missing, b"x")),
		ErrorKind::NotFound
	);
	assert!(entries(&l.outside).is_empty());
}

#[test]
fn write_atomic_replaces_a_link_at_the_leaf_without_following_it() {
	let l = layout();
	let victim = l.outside.join("victim");
	std::fs::write(&victim, "kept").expect("write");
	let file = l.root.join("state");
	symlink(&victim, &file).expect("symlink");
	write_atomic(&l.root, &file, b"new").expect("replace");
	assert_eq!(std::fs::read(&victim).expect("read"), b"kept");
	assert_eq!(std::fs::read(&file).expect("read"), b"new");
}

#[test]
fn write_atomic_cleans_its_staging_file_when_the_rename_fails() {
	let l = layout();
	let file = l.root.join("state");
	std::fs::create_dir(&file).expect("a directory at the destination");
	std::fs::write(file.join("inner"), "x").expect("write");
	assert!(write_atomic(&l.root, &file, b"x").is_err());
	assert_eq!(entries(&l.root), vec!["state"]);
}

#[test]
fn open_lock_creates_without_truncating_and_refuses_a_link() {
	let l = layout();
	let lock = l.root.join(".lock");
	std::fs::write(&lock, "keep").expect("write");
	let mut file = open_lock(&l.root, &lock).expect("open");
	let mut text = String::new();
	std::fs::File::open(&lock)
		.expect("open")
		.read_to_string(&mut text)
		.expect("read");
	assert_eq!(text, "keep");
	file.write_all(b"").expect("write");
	assert!(open_lock(&l.root, &l.root.join(".new")).is_ok());

	let victim = l.outside.join("victim");
	std::fs::write(&victim, "kept").expect("write");
	symlink(&victim, l.root.join(".linked")).expect("symlink");
	assert_eq!(
		kind(open_lock(&l.root, &l.root.join(".linked"))),
		ErrorKind::InvalidInput
	);
	symlink(&l.outside, l.root.join("account")).expect("symlink");
	assert_eq!(
		kind(open_lock(&l.root, &l.root.join("account").join(".lock"))),
		ErrorKind::InvalidInput
	);
	assert_eq!(entries(&l.outside), vec!["victim"]);
}

#[test]
fn metadata_reads_inside_the_root_and_refuses_a_directory_out_of_it() {
	let l = layout();
	std::fs::write(l.root.join("here"), "x").expect("write");
	assert_eq!(
		metadata(&l.root, &l.root.join("here")).expect("meta").len(),
		1
	);
	assert_eq!(
		kind(metadata(&l.root, &l.root.join("none"))),
		ErrorKind::NotFound
	);

	std::fs::write(l.outside.join("note"), "reached").expect("write");
	symlink(&l.outside, l.root.join("account")).expect("symlink");
	let through = l.root.join("account").join("note");
	assert_eq!(kind(metadata(&l.root, &through)), ErrorKind::InvalidInput);
}
