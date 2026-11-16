//! When a sign-in rewrites the hash, and when it must not.

use super::*;
use crate::smtp::auth::{cost, verify_password};

#[test]
fn a_hash_below_the_cost_in_force_is_rewritten_at_that_cost() {
	let dir = tempfile::tempdir().expect("dir");
	let old = hash_at(DEFAULT);
	let store = store_with(dir.path(), old.clone()).into_shared();
	let signed_in = cost::scoped(STRONGER, || login(&store, fixtures::password()));
	assert_eq!(signed_in.as_deref(), Some("alice"));

	let stored = persisted(dir.path()).password_hash;
	assert_ne!(stored, old);
	assert_eq!(parameters(&stored), "m=32768,t=3,p=2");
	assert!(verify_password(&stored, fixtures::password()));
	assert_eq!(writes(store.store_path()), 1);
	// The live directory serves the new hash as well.
	assert_eq!(
		login(&store, fixtures::password()).as_deref(),
		Some("alice")
	);
}

#[test]
fn a_hash_at_the_cost_in_force_is_not_written() {
	let dir = tempfile::tempdir().expect("dir");
	let old = hash_at(DEFAULT);
	let store = store_with(dir.path(), old.clone()).into_shared();
	let before = std::fs::read(store.store_path()).expect("read");
	assert_eq!(
		login(&store, fixtures::password()).as_deref(),
		Some("alice")
	);
	assert_eq!(persisted(dir.path()).password_hash, old);
	assert_eq!(std::fs::read(store.store_path()).expect("read"), before);
	assert_eq!(writes(store.store_path()), 0);
}

#[test]
fn a_wrong_password_never_rewrites() {
	let dir = tempfile::tempdir().expect("dir");
	let old = hash_at(DEFAULT);
	let store = store_with(dir.path(), old.clone()).into_shared();
	let signed_in = cost::scoped(STRONGER, || login(&store, fixtures::wrong_password()));
	assert_eq!(signed_in, None);
	assert_eq!(persisted(dir.path()).password_hash, old);
	assert_eq!(writes(store.store_path()), 0);
}

#[test]
fn a_stronger_hash_is_never_lowered() {
	let dir = tempfile::tempdir().expect("dir");
	let strong = hash_at(STRONGER);
	let store = store_with(dir.path(), strong.clone()).into_shared();
	assert_eq!(
		login(&store, fixtures::password()).as_deref(),
		Some("alice")
	);
	assert_eq!(persisted(dir.path()).password_hash, strong);
	assert_eq!(writes(store.store_path()), 0);
}

#[test]
fn a_hash_stronger_in_one_respect_keeps_it_when_raised_in_another() {
	let dir = tempfile::tempdir().expect("dir");
	let memory = Argon2Cost {
		memory_kib: 65_536,
		iterations: 2,
		parallelism: 1,
	};
	let store = store_with(dir.path(), hash_at(memory)).into_shared();
	let passes = Argon2Cost {
		memory_kib: 19_456,
		iterations: 3,
		parallelism: 1,
	};
	cost::scoped(passes, || login(&store, fixtures::password())).expect("signed in");
	assert_eq!(
		parameters(&persisted(dir.path()).password_hash),
		"m=65536,t=3,p=1"
	);
}

#[test]
fn an_older_algorithm_or_version_is_rewritten_as_argon2id() {
	use argon2::password_hash::PasswordHasher;
	use argon2::{Algorithm, Argon2, Params, Version};
	let params = Params::new(19_456, 2, 1, None).expect("params");
	for (algorithm, version, shown) in [
		(Algorithm::Argon2i, Version::V0x13, "$argon2i$"),
		(Algorithm::Argon2id, Version::V0x10, "v=16"),
	] {
		let old = Argon2::new(algorithm, version, params.clone())
			.hash_password_with_salt(fixtures::password().as_bytes(), &[3; 16])
			.expect("hash")
			.to_string();
		assert!(old.contains(shown), "{old}");
		let dir = tempfile::tempdir().expect("dir");
		let store = store_with(dir.path(), old).into_shared();
		assert_eq!(
			login(&store, fixtures::password()).as_deref(),
			Some("alice")
		);
		let stored = persisted(dir.path()).password_hash;
		assert!(stored.starts_with("$argon2id$v=19$"), "{stored}");
		assert!(verify_password(&stored, fixtures::password()));
	}
}

#[test]
fn logins_at_the_same_time_write_once() {
	let dir = tempfile::tempdir().expect("dir");
	let store = store_with(dir.path(), hash_at(DEFAULT)).into_shared();
	std::thread::scope(|scope| {
		for _ in 0..4 {
			scope.spawn(|| {
				let signed_in = cost::scoped(STRONGER, || login(&store, fixtures::password()));
				assert_eq!(signed_in.as_deref(), Some("alice"));
			});
		}
	});
	assert_eq!(writes(store.store_path()), 1);
	assert_eq!(
		parameters(&persisted(dir.path()).password_hash),
		"m=32768,t=3,p=2"
	);
}

#[test]
fn a_password_changed_in_the_meantime_is_not_put_back() {
	let dir = tempfile::tempdir().expect("dir");
	let old = hash_at(DEFAULT);
	let store = store_with(dir.path(), old.clone()).into_shared();
	let changed =
		hash_password_with_cost(fixtures::second_password(), DEFAULT, &[5; 16]).expect("hash");
	store
		.set_password_hash("alice", changed.clone(), None)
		.expect("change");
	cost::scoped(STRONGER, || {
		store.rehash_password("alice", &old, fixtures::password());
	});
	assert_eq!(persisted(dir.path()).password_hash, changed);
	assert_eq!(writes(store.store_path()), 0);
}

#[test]
fn an_account_that_is_not_a_dynamic_one_is_left_alone() {
	let dir = tempfile::tempdir().expect("dir");
	let store = store_with(dir.path(), hash_at(DEFAULT)).into_shared();
	cost::scoped(STRONGER, || {
		store.rehash_password("nobody", &hash_at(DEFAULT), fixtures::password());
	});
	assert_eq!(writes(store.store_path()), 0);
}

#[cfg(unix)]
#[test]
fn a_write_that_fails_keeps_the_sign_in_working_and_the_old_hash() {
	use std::os::unix::fs::PermissionsExt;
	struct Writable(PathBuf);
	impl Drop for Writable {
		fn drop(&mut self) {
			let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
		}
	}
	let dir = tempfile::tempdir().expect("dir");
	let old = hash_at(DEFAULT);
	let store = store_with(dir.path(), old.clone()).into_shared();
	let _restore = Writable(dir.path().to_path_buf());
	std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).expect("chmod");
	if std::fs::File::create(dir.path().join("probe")).is_ok() {
		// Running as root: the directory cannot be made unwritable.
		return;
	}
	let signed_in = cost::scoped(STRONGER, || login(&store, fixtures::password()));
	assert_eq!(signed_in.as_deref(), Some("alice"));
	std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
	assert_eq!(persisted(dir.path()).password_hash, old);
	assert_eq!(writes(store.store_path()), 0);
}
