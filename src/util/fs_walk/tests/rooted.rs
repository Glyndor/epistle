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
	mkfifo(&fifo);
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

fn mkfifo(path: &Path) {
	let name = std::ffi::CString::new(path.to_str().expect("utf8")).expect("cstring");
	// SAFETY: `name` is a valid NUL-terminated path.
	assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
}

#[test]
fn listing_skips_links_and_special_files_and_its_entries_can_be_read() {
	let l = layout();
	std::fs::write(l.root.join("file"), "x").expect("write");
	symlink(l.outside.join("note"), l.root.join("link")).expect("symlink");
	mkfifo(&l.root.join("pipe"));
	let entries: Vec<_> = read_dir(&l.root, &l.root)
		.expect("list")
		.flatten()
		.collect();
	let names: Vec<_> = entries.iter().map(|entry| entry.file_name()).collect();
	assert_eq!(names, vec![std::ffi::OsString::from("file")]);
	assert_eq!(read(&l.root, entries[0].path()).expect("read"), b"x");
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

#[test]
fn a_link_to_nowhere_is_not_a_missing_entry() {
	let l = layout();
	let accounts = l.root.join("accounts");
	std::fs::create_dir(&accounts).expect("mkdir");
	symlink(l.outside.join("absent"), accounts.join("evil")).expect("symlink");
	let below = accounts.join("evil").join("x");
	assert_eq!(
		kind(check_directories(&l.root, &below)),
		ErrorKind::NotFound
	);
	assert_eq!(kind(read_dir(&l.root, &below)), ErrorKind::NotFound);
	assert_eq!(kind(read(&l.root, &below)), ErrorKind::NotFound);
	assert!(!l.outside.join("absent").exists());
}

#[test]
fn a_missing_root_accepts_a_missing_tail_and_reads_nothing() {
	let l = layout();
	let root = l.root.join("not-created");
	let below = root.join("accounts").join("alice");
	let checked = check_directories(&root, &below).expect("a missing tail is fine");
	assert_eq!(checked, below);
	assert_eq!(kind(read_dir(&root, &below)), ErrorKind::NotFound);
	assert_eq!(kind(read(&root, below.join("m"))), ErrorKind::NotFound);
	assert_eq!(
		kind(check_directories(&root, &root.join("..").join("x"))),
		ErrorKind::InvalidInput
	);
}

#[test]
fn an_ancestor_swapped_for_a_link_after_the_check_is_caught_after_the_open() {
	let l = layout();
	let dir = l.root.join("a");
	std::fs::create_dir(&dir).expect("mkdir");
	std::fs::write(dir.join("m"), "inside").expect("write");
	std::fs::write(l.outside.join("m"), "outside").expect("write");
	let (root, outside) = (l.root.clone(), l.outside.clone());
	crate::util::fs_walk::rooted::hook::set(move || {
		std::fs::rename(root.join("a"), root.join("a-moved")).expect("rename");
		symlink(&outside, root.join("a")).expect("symlink");
	});
	assert_eq!(kind(read(&l.root, dir.join("m"))), ErrorKind::InvalidInput);
}

#[test]
fn a_root_that_is_a_link_is_resolved_not_refused() {
	let l = layout();
	std::fs::write(l.root.join("m"), "disk").expect("write");
	let alias = l.root.parent().expect("parent").join("mounted");
	symlink(&l.root, &alias).expect("symlink");
	assert_eq!(read(&alias, alias.join("m")).expect("read"), b"disk");
	assert!(read_dir(&alias, &alias).is_ok());
}

#[test]
fn text_that_is_not_utf8_is_invalid_data_and_such_a_name_is_refused() {
	use std::os::unix::ffi::OsStrExt;
	let l = layout();
	std::fs::write(l.root.join("bytes"), [0xff, 0xfe]).expect("write");
	let error = read_to_string(&l.root, l.root.join("bytes")).expect_err("not text");
	assert_eq!(error.kind(), ErrorKind::InvalidData);
	let odd = l.root.join(std::ffi::OsStr::from_bytes(b"caf\xe9"));
	assert_eq!(kind(read(&l.root, odd)), ErrorKind::InvalidInput);
}

#[test]
fn each_refused_entry_warns_once() {
	let l = layout();
	symlink(l.outside.join("note"), l.root.join("out")).expect("symlink");
	symlink(l.root.join("nowhere"), l.root.join("dangling")).expect("symlink");
	symlink(l.root.join("plain"), l.root.join("inside")).expect("symlink");
	std::fs::write(l.root.join("plain"), "x").expect("write");
	mkfifo(&l.root.join("pipe"));
	for name in ["out", "dangling", "inside", "pipe"] {
		let target = l.root.join(name);
		let events = crate::cli::trace::capture::run_with_capture(|| {
			let _scope = crate::util::fs_walk::warning_scope();
			let _ = read(&l.root, &target);
			let _ = read(&l.root, &target);
		});
		assert_eq!(events.len(), 1, "{name}: one warning for the path");
	}
}

#[test]
fn a_directory_swapped_for_another_after_the_check_is_refused_before_listing() {
	let l = layout();
	let dir = l.root.join("box");
	std::fs::create_dir(&dir).expect("mkdir");
	let root = l.root.clone();
	crate::util::fs_walk::rooted::hook::set(move || {
		std::fs::rename(root.join("box"), root.join("box-moved")).expect("rename");
		std::fs::create_dir(root.join("box")).expect("mkdir");
	});
	assert_eq!(kind(read_dir(&l.root, &dir)), ErrorKind::InvalidInput);
}

#[test]
fn a_root_that_does_not_exist_yet_behind_a_link_is_empty_not_refused() {
	let l = layout();
	let parent = l.root.parent().expect("parent").join("linked-parent");
	symlink(&l.root, &parent).expect("symlink");
	let absent = parent.join("data");
	let resolved_spelling = l
		.root
		.canonicalize()
		.expect("canonicalize")
		.join("data")
		.join("accounts");
	assert_eq!(
		kind(read_dir(&absent, &resolved_spelling)),
		ErrorKind::NotFound
	);
	assert!(check_directories(&absent, &resolved_spelling).is_ok());
	assert_eq!(
		kind(read(&absent, resolved_spelling.join("m"))),
		ErrorKind::NotFound
	);
}

#[test]
fn a_link_that_loops_back_on_itself_is_skipped_with_one_warning() {
	let l = layout();
	symlink(l.root.join("loop"), l.root.join("loop")).expect("symlink");
	let target = l.root.join("loop");
	let events = crate::cli::trace::capture::run_with_capture(|| {
		let _scope = crate::util::fs_walk::warning_scope();
		assert_eq!(kind(read(&l.root, &target)), ErrorKind::NotFound);
		assert_eq!(kind(read(&l.root, &target)), ErrorKind::NotFound);
	});
	assert_eq!(events.len(), 1, "one warning for the looping link");
}

#[test]
fn a_component_swapped_for_an_inner_link_after_the_walk_is_refused() {
	let l = layout();
	std::fs::create_dir_all(l.root.join("a").join("b")).expect("mkdir");
	let (dir, root) = (l.root.join("a").join("b"), l.root.clone());
	crate::util::fs_walk::rooted::hook::set_after_walk(move || {
		std::fs::rename(root.join("a"), root.join("a-moved")).expect("rename");
		symlink(root.join("a-moved"), root.join("a")).expect("symlink");
	});
	assert_eq!(kind(read_dir(&l.root, &dir)), ErrorKind::InvalidInput);
}
