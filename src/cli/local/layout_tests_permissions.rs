use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

#[test]
fn replacing_local_file_does_not_chmod_a_swapped_symlink() {
	let dir = tempfile::tempdir_in(".").expect("tempdir");
	let path = dir.path().join("mail.toml");
	let victim = dir.path().join("unrelated.txt");
	std::fs::write(&victim, b"unchanged").expect("write victim");
	std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644))
		.expect("set victim mode");
	let target = victim.canonicalize().expect("absolute victim");
	let mut rename = |from: &Path, to: &Path| {
		std::fs::rename(from, to)?;
		assert_eq!(
			std::fs::metadata(to)?.permissions().mode() & 0o777,
			0o600,
			"replacement must have its final mode when renamed"
		);
		std::fs::remove_file(to)?;
		symlink(&target, to)
	};
	write_with_replace_using_rename(&path, b"replacement", 0o600, &mut || 0, &mut rename)
		.expect("replace file");
	assert_eq!(
		std::fs::metadata(&victim)
			.expect("victim metadata")
			.permissions()
			.mode() & 0o777,
		0o644,
		"replacing a local file must leave a swapped symlink target mode unchanged"
	);
	assert!(
		std::fs::read(&victim).expect("read victim") == b"unchanged",
		"replacing a local file must leave the symlink target contents unchanged"
	);
}
