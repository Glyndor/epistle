//! Rotating the server key: the previous key, listed as retired, still
//! reads what it sealed, and a rekey run moves that under the new key.

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::config::Storage;
use crate::storage::rekey::{self, NoHooks};

fn key(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
	let path = dir.join(name);
	std::fs::write(&path, generate_key_base64().expect("csprng")).expect("key");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	path
}

fn with(
	current: Option<&std::path::Path>,
	retired: &[&std::path::Path],
) -> Result<MessageCrypto, CryptoError> {
	let storage = Storage {
		encrypt_at_rest: current.is_some(),
		encryption_key_file: current.map(std::path::Path::to_path_buf),
		retired_key_files: retired.iter().map(|path| path.to_path_buf()).collect(),
		..Storage::default()
	};
	MessageCrypto::from_config(Some(&storage))
}

#[test]
fn a_retired_key_reads_what_it_sealed_and_a_run_moves_it_to_the_new_key() {
	let keys = tempfile::tempdir().expect("keys");
	let data = tempfile::tempdir().expect("data");
	let old = key(keys.path(), "old.key");
	let new = key(keys.path(), "new.key");
	let sealed = with(Some(&old), &[])
		.expect("old")
		.encode(b"before")
		.expect("seal");
	let path = data.path().join("accounts/alice/new/0001.eml");
	std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
	std::fs::write(&path, &sealed).expect("write");

	let rotated = with(Some(&new), &[&old]).expect("rotated");
	assert_eq!(rotated.decode(&sealed).expect("retired reads"), b"before");
	assert_eq!(
		rotated.open_owned(&sealed).expect("open").1,
		KeyOwner::Retired(0)
	);
	assert!(
		with(Some(&new), &[])
			.expect("new only")
			.decode(&sealed)
			.is_err(),
		"without the retired key the old file is closed"
	);

	let target = rekey::target_for(&rotated, "alice", rekey::Direction::Forward);
	assert_eq!(target, KeyOwner::Server);
	let totals = rekey::rekey_account(&rotated, data.path(), "alice", &target, false, &mut NoHooks)
		.expect("rekey");
	assert_eq!(totals.rewritten, 1);
	let moved = std::fs::read(&path).expect("read");
	assert_eq!(
		kind(&moved),
		EnvelopeKind::V1,
		"still the format older releases read"
	);
	assert_eq!(
		with(Some(&new), &[])
			.expect("new only")
			.decode(&moved)
			.expect("new key reads"),
		b"before"
	);
}

#[test]
fn a_retired_key_equal_to_the_current_one_is_refused() {
	let keys = tempfile::tempdir().expect("keys");
	let current = key(keys.path(), "current.key");
	assert!(matches!(
		with(Some(&current), &[&current]),
		Err(CryptoError::DuplicateKey { .. })
	));
}

#[test]
fn a_retired_key_needs_mode_0600_and_a_current_key() {
	let keys = tempfile::tempdir().expect("keys");
	let current = key(keys.path(), "current.key");
	let old = key(keys.path(), "old.key");
	assert!(matches!(
		with(None, &[&old]),
		Err(CryptoError::RetiredWithoutServerKey)
	));
	std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o640)).expect("chmod");
	assert!(matches!(
		with(Some(&current), &[&old]),
		Err(CryptoError::KeyFilePermissions { .. })
	));
}
