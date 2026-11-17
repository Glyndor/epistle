use std::io::ErrorKind;
use std::os::unix::fs::symlink;
use std::path::Path;

use crate::util::fs_walk::rooted::{check_directories, read, read_dir, read_to_string};

/// A `root` directory with a sibling `outside` one that holds a file the
/// walk must never reach.
struct Layout {
	_guard: tempfile::TempDir,
	root: std::path::PathBuf,
	outside: std::path::PathBuf,
}

fn layout() -> Layout {
	let guard = tempfile::tempdir().expect("tempdir");
	let root = guard.path().join("root");
	let outside = guard.path().join("outside");
	std::fs::create_dir(&root).expect("mkdir root");
	std::fs::create_dir(&outside).expect("mkdir outside");
	std::fs::write(outside.join("note"), "reached").expect("write");
	Layout {
		_guard: guard,
		root,
		outside,
	}
}

fn kind<T>(result: std::io::Result<T>) -> ErrorKind {
	match result {
		Ok(_) => panic!("the walk must refuse this"),
		Err(error) => error.kind(),
	}
}

#[test]
fn reads_a_plain_nested_file_and_lists_its_directory() {
	let l = layout();
	let dir = l.root.join("a").join("b");
	std::fs::create_dir_all(&dir).expect("mkdir");
	std::fs::write(dir.join("note"), "hello").expect("write");
	assert_eq!(read(&l.root, dir.join("note")).expect("read"), b"hello");
	assert_eq!(
		read_to_string(&l.root, dir.join("note")).expect("read"),
		"hello"
	);
	let names: Vec<_> = read_dir(&l.root, &dir)
		.expect("list")
		.flatten()
		.map(|entry| entry.file_name())
		.collect();
	assert_eq!(names, vec![std::ffi::OsString::from("note")]);
}

#[test]
fn accepts_a_name_that_contains_two_dots() {
	let l = layout();
	let dir = l.root.join("a..b");
	std::fs::create_dir(&dir).expect("mkdir");
	std::fs::write(dir.join("c..d"), "ok").expect("write");
	assert_eq!(read(&l.root, dir.join("c..d")).expect("read"), b"ok");
	assert!(read_dir(&l.root, &dir).is_ok());
}

#[test]
fn refuses_a_path_that_escapes_through_dot_dot() {
	let l = layout();
	let escaped = l.root.join("..").join("outside");
	assert_eq!(kind(read_dir(&l.root, &escaped)), ErrorKind::InvalidInput);
	assert_eq!(
		kind(read(&l.root, escaped.join("note"))),
		ErrorKind::InvalidInput
	);
	assert_eq!(
		kind(check_directories(&l.root, &escaped)),
		ErrorKind::InvalidInput
	);
}

#[test]
fn refuses_a_dot_dot_after_a_real_directory() {
	let l = layout();
	std::fs::create_dir(l.root.join("inner")).expect("mkdir");
	let escaped = l.root.join("inner").join("..").join("..").join("outside");
	assert_eq!(kind(read_dir(&l.root, escaped)), ErrorKind::InvalidInput);
}

#[test]
fn refuses_an_absolute_path_outside_the_root() {
	let l = layout();
	assert_eq!(
		kind(read(&l.root, l.outside.join("note"))),
		ErrorKind::InvalidInput
	);
	assert_eq!(kind(read_dir(&l.root, &l.outside)), ErrorKind::InvalidInput);
	assert_eq!(kind(read(&l.root, Path::new("/"))), ErrorKind::InvalidInput);
}

#[test]
fn refuses_a_symlinked_ancestor_pointing_outside() {
	let l = layout();
	symlink(&l.outside, l.root.join("link")).expect("symlink");
	let through = l.root.join("link");
	assert_eq!(kind(read_dir(&l.root, &through)), ErrorKind::InvalidInput);
	assert_eq!(
		kind(read(&l.root, through.join("note"))),
		ErrorKind::InvalidInput
	);
	assert_eq!(
		kind(check_directories(&l.root, &through.join("deeper"))),
		ErrorKind::InvalidInput
	);
}

#[test]
fn skips_a_symlinked_ancestor_pointing_inside_the_root() {
	let l = layout();
	std::fs::create_dir(l.root.join("real")).expect("mkdir");
	std::fs::write(l.root.join("real").join("note"), "x").expect("write");
	symlink(l.root.join("real"), l.root.join("alias")).expect("symlink");
	let through = l.root.join("alias");
	assert_eq!(kind(read_dir(&l.root, &through)), ErrorKind::NotFound);
	assert_eq!(
		kind(read(&l.root, through.join("note"))),
		ErrorKind::NotFound
	);
}

#[test]
fn refuses_a_symlinked_leaf() {
	let l = layout();
	symlink(l.outside.join("note"), l.root.join("out")).expect("symlink");
	assert_eq!(
		kind(read(&l.root, l.root.join("out"))),
		ErrorKind::InvalidInput
	);
	std::fs::write(l.root.join("plain"), "x").expect("write");
	symlink(l.root.join("plain"), l.root.join("in")).expect("symlink");
	assert_eq!(kind(read(&l.root, l.root.join("in"))), ErrorKind::NotFound);
}

#[test]
fn refuses_a_fifo_leaf_without_blocking() {
	let l = layout();
	let fifo = l.root.join("pipe");
	let name = std::ffi::CString::new(fifo.to_str().expect("utf8")).expect("cstring");
	// SAFETY: `name` is a valid NUL-terminated path.
	assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
	assert_eq!(kind(read(&l.root, &fifo)), ErrorKind::NotFound);
}

#[test]
fn refuses_a_file_where_a_directory_is_needed() {
	let l = layout();
	std::fs::write(l.root.join("file"), "x").expect("write");
	let below = l.root.join("file").join("child");
	assert_eq!(kind(read(&l.root, &below)), ErrorKind::NotFound);
	assert_eq!(
		kind(check_directories(&l.root, &below)),
		ErrorKind::NotFound
	);
}

#[test]
fn a_missing_tail_is_not_found_for_reads_and_accepted_by_the_check() {
	let l = layout();
	let missing = l.root.join("one").join("two");
	assert_eq!(kind(read_dir(&l.root, &missing)), ErrorKind::NotFound);
	assert_eq!(kind(read(&l.root, missing.join("f"))), ErrorKind::NotFound);
	let checked = check_directories(&l.root, &missing).expect("missing tail is fine");
	assert!(checked.ends_with("one/two"));
	assert_eq!(
		kind(read_dir(&l.root.join("gone"), l.root.join("gone"))),
		ErrorKind::NotFound
	);
}

#[test]
fn a_dangling_link_is_not_found() {
	let l = layout();
	symlink(l.root.join("nowhere"), l.root.join("dangling")).expect("symlink");
	assert_eq!(
		kind(read_dir(&l.root, l.root.join("dangling"))),
		ErrorKind::NotFound
	);
}

#[test]
fn accepts_the_root_and_the_path_in_either_spelling() {
	let l = layout();
	std::fs::create_dir(l.root.join("a")).expect("mkdir");
	std::fs::write(l.root.join("a").join("note"), "same").expect("write");
	let alias = l.root.parent().expect("parent").join("alias");
	symlink(&l.root, &alias).expect("symlink");
	let resolved = l.root.canonicalize().expect("canonicalize");
	for path in [
		alias.join("a").join("note"),
		resolved.join("a").join("note"),
	] {
		assert_eq!(read(&alias, &path).expect("read"), b"same");
	}
	assert_eq!(
		kind(read(&resolved, alias.join("a").join("note"))),
		ErrorKind::InvalidInput
	);
}

#[test]
fn the_checked_path_is_in_the_resolved_spelling() {
	let l = layout();
	std::fs::create_dir(l.root.join("a")).expect("mkdir");
	let checked = check_directories(&l.root, &l.root.join("a").join(".")).expect("check");
	assert_eq!(
		checked,
		l.root.canonicalize().expect("canonicalize").join("a")
	);
}

#[test]
fn listing_skips_links_and_special_files() {
	let l = layout();
	std::fs::write(l.root.join("file"), "x").expect("write");
	symlink(l.outside.join("note"), l.root.join("link")).expect("symlink");
	let names: Vec<_> = read_dir(&l.root, &l.root)
		.expect("list")
		.flatten()
		.map(|entry| entry.file_name())
		.collect();
	assert_eq!(names, vec![std::ffi::OsString::from("file")]);
}

#[test]
fn an_account_directory_that_is_a_link_is_refused_from_the_data_dir_root() {
	let l = layout();
	let accounts = l.root.join("accounts");
	std::fs::create_dir_all(accounts.join("bob").join("new")).expect("mkdir");
	std::fs::write(accounts.join("bob").join("new").join("m.eml"), "bob").expect("write");
	symlink(accounts.join("bob"), accounts.join("alice")).expect("symlink");
	symlink(&l.outside, accounts.join("carol")).expect("symlink");
	let to_sibling = accounts.join("alice").join("new");
	assert_eq!(kind(read_dir(&l.root, &to_sibling)), ErrorKind::NotFound);
	assert_eq!(
		kind(read(&l.root, to_sibling.join("m.eml"))),
		ErrorKind::NotFound
	);
	let to_outside = accounts.join("carol");
	assert_eq!(
		kind(read_dir(&l.root, &to_outside)),
		ErrorKind::InvalidInput
	);
	assert_eq!(
		kind(read(&l.root, to_outside.join("note"))),
		ErrorKind::InvalidInput
	);
}
