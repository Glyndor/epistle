//! A published generation read from its own directory, for the owner the store trusts.

use super::*;

#[test]
fn a_published_generation_is_read_from_its_own_directory() {
	let temp = tempfile::tempdir().unwrap();
	// Every mode here is explicit, because the branch below runs with a real
	// uid 0 where an inherited umask is not a test setting but the thing under
	// test: a group writable binary (umask 002) or a group writable directory
	// (umask 000) is refused by the same check the store exists to enforce,
	// and the failure would read as a defect in the store. 0755 on the parent
	// is what `/var/lib` looks like, 0700 on the generation is what the
	// preinst's exclusive temporary publishes.
	std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
	let kept = temp.path().join("epistle-0.12.1");
	std::fs::create_dir(&kept).unwrap();
	std::fs::write(kept.join("epistle"), "abc").unwrap();
	std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0o700)).unwrap();
	std::fs::set_permissions(kept.join("epistle"), std::fs::Permissions::from_mode(0o644)).unwrap();
	std::fs::write(kept.join("epistle.sha256"), ABC_SHA256).unwrap();
	std::fs::set_permissions(
		kept.join("epistle.sha256"),
		std::fs::Permissions::from_mode(0o600),
	)
	.unwrap();
	let store = Store {
		dir: File::open(temp.path()).unwrap(),
		owner: ROOT,
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

/// The happy path of a published generation for any user, with no sandbox and
/// no privileges: the store trusts the owner it is given, and production hands
/// it root. Without this the read of a verified generation ran only where a
/// root namespace was available.
#[test]
fn a_published_generation_opens_for_the_owner_the_store_trusts() {
	let temp = tempfile::tempdir().unwrap();
	let kept = temp.path().join("epistle-0.12.1");
	std::fs::create_dir(&kept).unwrap();
	std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0o700)).unwrap();
	std::fs::write(kept.join("epistle"), "abc").unwrap();
	std::fs::write(kept.join("epistle.sha256"), ABC_SHA256).unwrap();
	for (name, mode) in [("epistle", 0o755), ("epistle.sha256", 0o600)] {
		std::fs::set_permissions(kept.join(name), std::fs::Permissions::from_mode(mode)).unwrap();
	}
	let metadata = kept.metadata().unwrap();
	let owner = (metadata.uid(), metadata.gid());
	let open = |owner| Store {
		dir: File::open(temp.path()).unwrap(),
		owner,
	};

	let (chosen, mut binary) = open(owner)
		.select("0.12.2", None)
		.expect("the owner the store trusts reads the generation and checks its digest");
	assert_eq!(chosen, "epistle-0.12.1");
	let mut read = String::new();
	binary.read_to_string(&mut read).unwrap();
	assert_eq!(read, "abc");

	let other = (owner.0 + 1, owner.1);
	assert!(
		open(other)
			.select("0.12.2", None)
			.unwrap_err()
			.contains("root-owned"),
		"a generation owned by anybody else is refused"
	);
	std::fs::write(kept.join("epistle"), "abd").unwrap();
	assert!(
		open(owner)
			.select("0.12.2", None)
			.unwrap_err()
			.contains("digest"),
		"altered bytes fail the digest even for the trusted owner"
	);
}
