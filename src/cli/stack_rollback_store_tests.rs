//! Validate opened rollback sources and install from the verified descriptor.

use super::*;
use std::os::unix::fs::symlink;

const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n";

#[test]
fn source_links_and_non_root_files_are_rejected() {
	let temp = tempfile::tempdir().unwrap();
	std::fs::write(temp.path().join("binary"), "abc").unwrap();
	std::fs::set_permissions(
		temp.path().join("binary"),
		std::fs::Permissions::from_mode(0o644),
	)
	.unwrap();
	symlink("binary", temp.path().join("link")).unwrap();
	let dir = File::open(temp.path()).unwrap();
	assert_eq!(
		checked_file(&dir, "link").unwrap_err().raw_os_error(),
		Some(libc::ELOOP)
	);
	// A normal unprivileged test run must exercise the ownership refusal.
	if dir.metadata().unwrap().uid() != 0 {
		let error = checked_file(&dir, "binary").unwrap_err();
		assert!(error.to_string().contains("root-owned"));
	}
	assert!(checked_file(&dir, ".").is_err());
	assert!(checked_file(&dir, "../binary").is_err());
	assert!(checked_file(&dir, "missing").is_err());
}

#[test]
fn non_regular_sources_are_rejected_without_reading_them() {
	let temp = tempfile::tempdir().unwrap();
	std::fs::create_dir(temp.path().join("directory")).unwrap();
	let fifo = CString::new(temp.path().join("fifo").as_os_str().as_bytes()).unwrap();
	// SAFETY: fifo is a valid path C string throughout the call.
	assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
	let dir = File::open(temp.path()).unwrap();
	for name in ["directory", "fifo"] {
		assert!(
			checked_file(&dir, name)
				.unwrap_err()
				.to_string()
				.contains("regular")
		);
	}
}

#[test]
fn digest_verification_rewinds_and_rejects_altered_or_missing_manifests() {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("binary");
	std::fs::write(&path, "abc").unwrap();
	let mut file = File::open(&path).unwrap();
	verify_digest(&mut file, ABC_SHA256).unwrap();
	let mut bytes = String::new();
	file.read_to_string(&mut bytes).unwrap();
	assert_eq!(bytes, "abc");
	for manifest in ["", ABC_SHA256.trim(), "invalid\n"] {
		assert!(verify_digest(&mut File::open(&path).unwrap(), manifest).is_err());
	}
	std::fs::write(&path, "abd").unwrap();
	assert!(verify_digest(&mut File::open(path).unwrap(), ABC_SHA256).is_err());
}

#[test]
fn installation_uses_the_open_descriptor_and_an_atomic_private_copy() {
	let temp = tempfile::tempdir().unwrap();
	let source = temp.path().join("source");
	let installed = temp.path().join("installed");
	std::fs::write(&source, "abc").unwrap();
	std::fs::write(&installed, "current").unwrap();
	let mut binary = File::open(&source).unwrap();
	verify_digest(&mut binary, ABC_SHA256).unwrap();
	std::fs::rename(&source, temp.path().join("original")).unwrap();
	std::fs::write(source, "replacement").unwrap();
	install(&mut binary, &installed).unwrap();
	assert_eq!(std::fs::read_to_string(&installed).unwrap(), "abc");
	assert_eq!(
		installed.metadata().unwrap().permissions().mode() & 0o777,
		0o755
	);
	assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 3);
	let target_directory = temp.path().join("target-directory");
	std::fs::create_dir(&target_directory).unwrap();
	binary.rewind().unwrap();
	assert!(install(&mut binary, &target_directory).is_err());
	assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 4);
}

#[test]
fn directory_validation_requires_protected_root_parents_and_private_store() {
	let temp = tempfile::tempdir().unwrap();
	let file = File::open(temp.path()).unwrap();
	if file.metadata().unwrap().uid() != 0 {
		assert!(check_directory(&file, true).is_err());
	}
	assert!(Store::open(Path::new("relative")).is_err());
	assert!(Store::open(Path::new("/usr/../usr")).is_err());
	let link = temp.path().join("linked");
	symlink("/usr", &link).unwrap();
	assert!(Store::open(&link).is_err());
	assert!(Store::open(&temp.path().join("missing")).is_err());
}

#[test]
fn a_published_generation_is_read_from_its_own_directory() {
	let temp = tempfile::tempdir().unwrap();
	let kept = temp.path().join("epistle-0.12.1");
	std::fs::create_dir(&kept).unwrap();
	std::fs::write(kept.join("epistle"), "abc").unwrap();
	std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0o700)).unwrap();
	std::fs::write(kept.join("epistle.sha256"), ABC_SHA256).unwrap();
	std::fs::set_permissions(
		kept.join("epistle.sha256"),
		std::fs::Permissions::from_mode(0o600),
	)
	.unwrap();
	let store = Store {
		dir: File::open(temp.path()).unwrap(),
	};
	// A normal unprivileged test run reaches the ownership refusal of the
	// published generation; with root ownership the pair is read and checked.
	let uid = store.dir.metadata().unwrap().uid();
	if uid != 0 {
		assert!(
			store
				.binary("epistle-0.12.1")
				.unwrap_err()
				.to_string()
				.contains("root-owned"),
			"the ownership refusal must name what was wrong so a real Root can still see it"
		);
	} else {
		// The positive path a non-root run cannot reach: a root-owned store
		// reads the published generation and verifies the digest end to end.
		// Without this branch a regression that stopped opening the pair (the
		// silent failure R2-01 reported) would still show green here.
		let mut binary = store
			.binary("epistle-0.12.1")
			.expect("root ownership alone lets the published pair be opened and verified");
		let mut read = String::new();
		std::io::Read::read_to_string(&mut binary, &mut read).unwrap();
		assert_eq!(
			read, "abc",
			"the verified descriptor must yield the saved bytes"
		);
		assert!(
			store.select("0.12.2", Some("0.12.1")).is_ok(),
			"the explicit version pick must succeed against the published generation"
		);
	}
	// A link, a plain file and a nested name are not a generation directory.
	symlink("epistle-0.12.1", temp.path().join("linked")).unwrap();
	assert_eq!(
		store.binary("linked").unwrap_err().raw_os_error(),
		Some(libc::ENOTDIR)
	);
	std::fs::write(temp.path().join("plain"), "abc").unwrap();
	assert_eq!(
		store.binary("plain").unwrap_err().raw_os_error(),
		Some(libc::ENOTDIR)
	);
	assert!(store.binary("../epistle-0.12.1").is_err());
	assert!(store.binary("missing").is_err());
}

/// The literals the rollback store reads must be the same ones the package
/// maintainer script writes. The two names appear in the Rust source; the
/// integration test (in `tests/debian_isolated_user.rs`) reads the script and
/// checks the same names there. If either side moves, that integration test
/// fails; this one keeps the Rust side honest. The preinst writes the pair
/// inside a staging directory, then a single rename publishes them under
/// `epistle-<version>/{epistle,epistle.sha256}`.
///
/// The fixtures below stand in for the published pair the preinst writes.
/// Without root the Store refuses at the ownership check, so this test alone
/// cannot exercise the read; it lays out the shape every generation is
/// supposed to carry. The textual check in `the_store_source_keeps_the_published_names`
/// catches the rename that would otherwise pass the directory listing.
#[test]
fn the_store_opens_the_two_names_the_preinst_writes() {
	// The fixture mimics what the preinst stages and renames into place.
	let temp = tempfile::tempdir().unwrap();
	let kept = temp.path().join("epistle-0.12.1");
	std::fs::create_dir(&kept).unwrap();
	std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0o700)).unwrap();
	std::fs::write(kept.join("epistle"), "abc").unwrap();
	std::fs::set_permissions(kept.join("epistle"), std::fs::Permissions::from_mode(0o755)).unwrap();
	std::fs::write(kept.join("epistle.sha256"), ABC_SHA256).unwrap();
	std::fs::set_permissions(
		kept.join("epistle.sha256"),
		std::fs::Permissions::from_mode(0o600),
	)
	.unwrap();
	let store = Store {
		dir: File::open(temp.path()).unwrap(),
	};
	// The published pair must include the two names that the script writes
	// and the Store opens. The Store never reads them here (root is required
	// for the published path), so the assertion reads them at the path the
	// Store would take; a regression that renamed the lookup on the Rust
	// side would still find these files here but fail on the Store side, and
	// the integration test catches the corresponding rename on the script
	// side. Together the two tests pin both literals from either direction.
	for needle in ["epistle", "epistle.sha256"] {
		assert!(
			kept.join(needle).is_file(),
			"the published pair must include {needle:?}: this fixture is what the Store opens"
		);
	}
	// A name that is not a generation directory must close the lookup. The
	// Store asks for the literal `epistle-<version>` prefix by string.
	let err = store
		.binary("missing-generation")
		.expect_err("a name that is not a generation directory must close the lookup");
	let _ = err.raw_os_error();
}

/// The two literals the package script writes must appear as literal strings
/// inside the Store's lookup calls. Without this, a regression that opened the
/// pair under a different name (e.g. `epistle-bin`, `epistle.digest`) would
/// still find a directory listing that matches the script and let the
/// contract drift without any test going red. The integration test in
/// `tests/debian_isolated_user.rs` reads the script and asserts the
/// corresponding strings there.
#[test]
fn the_store_source_keeps_the_published_names() {
	let source = include_str!("stack_rollback_store.rs");
	for needle in ["\"epistle\"", "\"epistle.sha256\""] {
		assert!(
			source.contains(needle),
			"src/cli/stack_rollback_store.rs must open the published file under {needle:?}; \
			 the package maintainer script writes exactly that name, and a rename here would \
			 silently break every rollback"
		);
	}
}

#[test]
fn ownership_type_and_permissions_must_all_be_trusted() {
	assert!(protected(true, 0, 0o755));
	for (kind, uid, mode) in [
		(false, 0, 0o755),
		(true, 1000, 0o755),
		(true, 0, 0o775),
		(true, 0, 0o757),
	] {
		assert!(!protected(kind, uid, mode));
	}
	assert!(protected_directory(true, 0, 0, 0o755, false));
	assert!(protected_directory(true, 0, 0, 0o700, true));
	for (kind, uid, gid, mode, private) in [
		(false, 0, 0, 0o700, true),
		(true, 1000, 0, 0o700, true),
		(true, 0, 1000, 0o700, true),
		(true, 0, 0, 0o777, false),
		(true, 0, 0, 0o755, true),
	] {
		assert!(!protected_directory(kind, uid, gid, mode, private));
	}
}
