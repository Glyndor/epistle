use super::*;

#[test]
fn a_link_opens_as_the_link_and_a_socket_without_opening_it() {
	let dir = tempfile::tempdir().unwrap();
	let file = dir.path().join("file");
	std::fs::write(&file, "12345").unwrap();
	let link = dir.path().join("link");
	std::os::unix::fs::symlink(&file, &link).unwrap();
	let socket = dir.path().join("sock");
	let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();

	let stat_of = |path: &Path| of(&open_path(path).unwrap()).unwrap();
	let linked = stat_of(&link);
	assert!(linked.is_symlink(), "{linked:?}");
	let sock = stat_of(&socket);
	assert!(
		!sock.is_file() && !sock.is_dir() && !sock.is_symlink(),
		"{sock:?}"
	);
	let regular = stat_of(&file);
	assert!(regular.is_file());
	assert_eq!((regular.len(), regular.nlink()), (5, 1));
	assert!(stat_of(dir.path()).is_dir());

	std::fs::hard_link(&file, dir.path().join("second")).unwrap();
	let twice = stat_of(&file);
	assert_eq!(twice.nlink(), 2);
	assert!(twice.same_inode(&stat_of(&dir.path().join("second"))));
	assert!(!twice.same_inode(&stat_of(dir.path())));
	// SAFETY: geteuid takes no arguments and cannot fail.
	assert_eq!(twice.uid(), unsafe { libc::geteuid() });
}
