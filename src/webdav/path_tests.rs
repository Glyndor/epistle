use super::*;

#[test]
fn account_root_builds_under_data_dir() {
	let root = account_root(Path::new("/data"), "alice").expect("root");
	assert_eq!(root, Path::new("/data/accounts/alice/dav"));
}

#[test]
fn account_root_rejects_traversal_in_name() {
	assert!(account_root(Path::new("/data"), "..").is_none());
	assert!(account_root(Path::new("/data"), "a/b").is_none());
	assert!(account_root(Path::new("/data"), "a\\b").is_none());
	assert!(account_root(Path::new("/data"), "a\0b").is_none());
	assert!(account_root(Path::new("/data"), "").is_none());
}

#[test]
fn resolve_maps_simple_paths() {
	let root = Path::new("/r");
	assert_eq!(
		resolve(root, "/file.txt"),
		Some(PathBuf::from("/r/file.txt"))
	);
	assert_eq!(resolve(root, "/"), Some(PathBuf::from("/r")));
	assert_eq!(resolve(root, ""), Some(PathBuf::from("/r")));
	assert_eq!(
		resolve(root, "/a/b/c.txt"),
		Some(PathBuf::from("/r/a/b/c.txt"))
	);
}

#[test]
fn resolve_rejects_dotdot() {
	let root = Path::new("/r");
	assert!(resolve(root, "/../etc/passwd").is_none());
	assert!(resolve(root, "/a/../../b").is_none());
	assert!(resolve(root, "/a/..").is_none());
}

#[test]
fn resolve_rejects_encoded_dotdot() {
	let root = Path::new("/r");
	// %2e%2e decodes to ".." and must be rejected just as the literal is.
	assert!(resolve(root, "/%2e%2e/secret").is_none());
	assert!(resolve(root, "/%2E%2E/secret").is_none());
}

#[test]
fn resolve_rejects_nul() {
	assert!(resolve(Path::new("/r"), "/a%00b").is_none());
}

#[test]
fn resolve_rejects_bad_percent_escape() {
	assert!(resolve(Path::new("/r"), "/a%zz").is_none());
	assert!(resolve(Path::new("/r"), "/a%2").is_none());
}

#[test]
fn resolve_decodes_percent_escapes() {
	assert_eq!(
		resolve(Path::new("/r"), "/a%20b.txt"),
		Some(PathBuf::from("/r/a b.txt"))
	);
}

#[test]
fn resolve_result_is_always_under_root() {
	let root = Path::new("/r");
	for path in ["/x", "/x/y", "/x/y/z.txt", "/", ""] {
		let resolved = resolve(root, path).expect("resolved");
		assert!(resolved.starts_with(root), "{path} escaped root");
	}
}
