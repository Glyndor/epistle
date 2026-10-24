use super::*;
use std::fs;

const TEXT: &str = "# deployment\nhostname = 'mail.example.org' # ${PATH}\ndata_dir = '/var/lib/mail'\nquota_bytes = 123 # cap\n";

fn fixture() -> tempfile::NamedTempFile {
	let file = tempfile::NamedTempFile::new_in(".").unwrap();
	fs::write(file.path(), TEXT).unwrap();
	file
}

#[test]
fn commit_and_no_op_preserve_bytes_and_mtime() {
	let file = fixture();
	let modified = fs::metadata(file.path()).unwrap().modified().unwrap();
	let mut doc = ConfigDocument::open(file.path()).unwrap();
	doc.set_scalar("quota_bytes", 123_i64).unwrap();
	assert_eq!(doc.commit().unwrap(), Outcome::Unchanged);
	assert_eq!(
		fs::metadata(file.path()).unwrap().modified().unwrap(),
		modified,
		"no-op must not rewrite the file"
	);
	assert!(
		fs::read_to_string(file.path()).unwrap() == TEXT,
		"no-op must keep exact bytes"
	);
	let mut doc = ConfigDocument::open(file.path()).unwrap();
	doc.set_scalar("quota_bytes", 456_i64).unwrap();
	assert_eq!(doc.commit().unwrap(), Outcome::Changed);
	assert!(
		fs::read_to_string(file.path()).unwrap() == TEXT.replace("123", "456"),
		"commit must keep comments and placeholders"
	);
}

#[test]
fn invalid_rendered_candidate_creates_no_files_and_leaves_bytes_identical() {
	let dir = tempfile::tempdir_in(".").unwrap();
	let path = dir.path().join("mail.toml");
	fs::write(&path, TEXT).unwrap();
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
	}
	let mut doc = ConfigDocument::open(&path).unwrap();
	doc.set_scalar("quota_bytes", "invalid").unwrap();
	assert!(
		doc.commit().unwrap_err().contains("invalid type: string"),
		"candidate must use typed Config validation"
	);
	assert!(
		fs::read_to_string(&path).unwrap() == TEXT,
		"validation failure must leave file byte-identical"
	);
	assert_eq!(
		fs::read_dir(dir.path()).unwrap().count(),
		1,
		"validation must precede staging"
	);
	let mut doc = ConfigDocument::open(&path).unwrap();
	doc.set_scalar("unknown_operator_key", true).unwrap();
	assert!(
		doc.commit()
			.unwrap_err()
			.contains("unknown field `unknown_operator_key`"),
		"candidate must deny unknown fields"
	);
	assert!(
		fs::read_to_string(&path).unwrap() == TEXT,
		"unknown field must leave file byte-identical"
	);
}

#[test]
fn dry_run_returns_exact_unified_diff_without_writing() {
	let file = fixture();
	let mut doc = ConfigDocument::open(file.path()).unwrap();
	doc.set_scalar("quota_bytes", 456_i64).unwrap();
	let expected = format!(
		"--- {}\n+++ {}\n@@ -1,4 +1,4 @@\n # deployment\n hostname = 'mail.example.org' # ${{PATH}}\n data_dir = '/var/lib/mail'\n-quota_bytes = 123 # cap\n+quota_bytes = 456 # cap\n",
		file.path().display(),
		file.path().display()
	);
	assert!(
		doc.dry_run().unwrap() == expected,
		"dry-run must return the exact unified diff"
	);
	assert!(
		fs::read_to_string(file.path()).unwrap() == TEXT,
		"dry-run must not write"
	);
	let doc = ConfigDocument::open(file.path()).unwrap();
	assert_eq!(doc.dry_run().unwrap(), "");
}

#[cfg(unix)]
#[test]
fn modes_and_owner_survive_atomic_replacement() {
	use std::os::unix::fs::{MetadataExt, PermissionsExt};
	for mode in [0o400, 0o600] {
		let file = fixture();
		fs::set_permissions(file.path(), fs::Permissions::from_mode(mode)).unwrap();
		let before = fs::metadata(file.path()).unwrap();
		let mut doc = ConfigDocument::open(file.path()).unwrap();
		doc.set_scalar("quota_bytes", 456_i64).unwrap();
		doc.commit().unwrap();
		let after = fs::metadata(file.path()).unwrap();
		assert_eq!(
			(after.mode() & 0o777, after.uid(), after.gid()),
			(mode, before.uid(), before.gid()),
			"commit must preserve mode and owner"
		);
		assert_ne!(
			before.ino(),
			after.ino(),
			"changed config must be atomically replaced"
		);
	}
}

#[cfg(unix)]
#[test]
fn verified_open_rejects_insecure_symlink_and_nonregular_files() {
	use std::os::unix::fs::{PermissionsExt, symlink};
	let dir = tempfile::tempdir_in(".").unwrap();
	let path = dir.path().join("mail.toml");
	fs::write(&path, TEXT).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
	assert!(
		ConfigDocument::open(&path).err().unwrap().contains("0o644"),
		"open must report insecure mode"
	);
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
	let link = dir.path().join("link.toml");
	symlink(path.canonicalize().unwrap(), &link).unwrap();
	assert!(
		ConfigDocument::open(&link)
			.err()
			.unwrap()
			.contains("is a symlink"),
		"open must refuse symlink traversal"
	);
	assert_eq!(
		ConfigDocument::open(dir.path()).err().as_deref(),
		Some("config must be a regular file")
	);
	assert!(
		fs::read_to_string(path).unwrap() == TEXT,
		"rejected reads must not alter the target"
	);
}

/// The loader follows a link to the configuration, so the read a writer that
/// is already holding the common lock uses has to follow one too, and it has
/// to refuse a fifo at the path or behind the link instead of waiting for a
/// writer that may never come.
#[cfg(unix)]
#[test]
fn a_link_to_the_configuration_is_read_and_a_fifo_behind_one_is_refused() {
	use crate::cli::init::compose_read::fifo_at;
	use std::os::unix::fs::{PermissionsExt, symlink};
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("mail.toml");
	fs::write(&path, TEXT).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
	let link = dir.path().join("linked.toml");
	symlink(&path, &link).unwrap();
	assert!(
		read_through_link(&link).unwrap() == TEXT,
		"a link to the configuration is read through"
	);
	let direct = dir.path().join("direct.toml");
	fifo_at(&direct);
	let behind = dir.path().join("behind.fifo");
	fifo_at(&behind);
	let through_link = dir.path().join("fifo.toml");
	symlink(&behind, &through_link).unwrap();
	for (label, path) in [
		("the path itself", &direct),
		("behind a link", &through_link),
	] {
		let error = read_through_link(path).unwrap_err();
		assert!(
			error.contains("must be a regular file") && error.contains(&path.display().to_string()),
			"a fifo at {label} must be refused by name: {error}"
		);
	}
}

#[test]
fn concurrent_change_is_not_overwritten_and_temp_is_cleaned() {
	let file = fixture();
	let mut doc = ConfigDocument::open(file.path()).unwrap();
	doc.set_scalar("quota_bytes", 456_i64).unwrap();
	let external = TEXT.replace("123", "789");
	fs::write(file.path(), &external).unwrap();
	assert_eq!(
		doc.commit().err().as_deref(),
		Some("config changed while editing; retry the command")
	);
	assert!(
		fs::read_to_string(file.path()).unwrap() == external,
		"commit must preserve a concurrent edit"
	);
}
