use std::os::unix::fs::PermissionsExt;

use super::{is_private_key_path, lay_files};

#[test]
fn private_key_classifier_recognises_known_shapes() {
	use std::path::Path;
	let sensitive = [
		"log-pseudonym.key",
		"accounts/alice/log-pseudonym.key", // tail match, not collide
		"dkim-ed20240101.key",
		"accounts/alice/totp.toml",
		"accounts/bob/credentials.json",
		"tls/key.pem",
		"acme/account.pem",
	];
	for path in sensitive {
		assert!(
			is_private_key_path(Path::new(path)),
			"{path} must be classified as private"
		);
	}
}

#[test]
fn private_key_classifier_leaves_ordinary_files_alone() {
	use std::path::Path;
	let ordinary = [
		"accounts/alice/new/0001.eml",
		"accounts/alice/folders/Projects..2024",
		"dkim-rotation.json",
		"server.crt",
		"envelope.json",
	];
	for path in ordinary {
		assert!(
			!is_private_key_path(Path::new(path)),
			"{path} must NOT be classified as private"
		);
	}
}

/// Restore a tarball-like list whose `key` archive entry is recorded as
/// 0644 and confirm the restored file lands at 0600. Without the
/// private-key floor this would land at 0644 and a backup that captured
/// a permissive umask (or was tampered with) would silently re-introduce
/// a world-readable key.
#[test]
fn lay_files_forces_0600_on_archived_private_key() {
	let data_dir = tempfile::tempdir().expect("tempdir");
	let entries = vec![
		// Sensitive entry, recorded in the tar as 0644.
		(
			"data/dkim-ed20240101.key".to_string(),
			0o644_u32,
			b"FAKE-PEM-PRIVATE".to_vec(),
		),
		// Ordinary entry, recorded in the tar as 0644.
		(
			"data/accounts/alice/new/0001.eml".to_string(),
			0o644_u32,
			b"Subject: hi\r\n\r\nbody".to_vec(),
		),
	];
	lay_files(&entries, data_dir.path()).expect("lay_files");

	let key_path = data_dir.path().join("dkim-ed20240101.key");
	let key_mode = std::fs::metadata(&key_path)
		.expect("key metadata")
		.permissions()
		.mode();
	assert_eq!(
		key_mode & 0o777,
		0o600,
		"archived private key landed at {:o}, must be 0600",
		key_mode & 0o777
	);

	let ordinary_path = data_dir.path().join("accounts/alice/new/0001.eml");
	let ordinary_mode = std::fs::metadata(&ordinary_path)
		.expect("ordinary metadata")
		.permissions()
		.mode();
	assert_eq!(
		ordinary_mode & 0o777,
		0o644,
		"ordinary file should keep the archive's mode, got {:o}",
		ordinary_mode & 0o777
	);
}

/// A restored JMAP journal is older than what clients may hold, so its
/// header must not come back: neither the archived one nor the one a
/// `--force` restore would leave in place. Without it the journal starts
/// a new epoch and every client resyncs instead of trusting rewound
/// positions.
#[test]
fn lay_files_drops_the_jmap_journal_header() {
	let data_dir = tempfile::tempdir().expect("tempdir");
	let account = data_dir.path().join("accounts/alice");
	std::fs::create_dir_all(&account).expect("account dir");
	std::fs::write(account.join(".jmap_state"), "777 0\n").expect("live header");
	let entries = vec![
		(
			"data/accounts/alice/.jmap_changes".to_string(),
			0o600_u32,
			b"1 e c 00000000-0000-0000-0000-000000000001\n".to_vec(),
		),
		(
			"data/accounts/alice/.jmap_state".to_string(),
			0o600_u32,
			b"777 0\n".to_vec(),
		),
	];
	lay_files(&entries, data_dir.path()).expect("lay_files");

	assert!(account.join(".jmap_changes").is_file(), "journal restored");
	assert!(
		!account.join(".jmap_state").exists(),
		"the journal header must not survive a restore"
	);
	let position = crate::imap::changelog::current(&account).expect("current");
	assert_ne!(
		position.epoch, 777,
		"the restored journal must start a new epoch"
	);
}
