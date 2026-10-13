//! Tests for the keys that live outside data_dir.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::*;

fn mode(path: &Path) -> u32 {
	fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn plant(data_dir: &Path, name: &str, bytes: &[u8]) {
	let keys = data_dir.join("keys");
	fs::create_dir_all(&keys).unwrap();
	fs::write(keys.join(name), bytes).unwrap();
	fs::set_permissions(keys.join(name), fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn the_directory_is_a_sibling_of_data_dir() {
	assert_eq!(
		dir(Path::new("/var/lib/glyndor/epistle/data")),
		Path::new("/var/lib/glyndor/epistle/secrets")
	);
	assert_eq!(
		storage_key(Path::new("/srv/mail/data")),
		Path::new("/srv/mail/secrets/storage.key")
	);
	assert_eq!(
		oauth_signing_key(Path::new("/srv/mail/data")),
		Path::new("/srv/mail/secrets/oauth_signing.key")
	);
}

#[test]
fn keys_under_data_dir_are_moved_out_with_owner_only_modes() {
	let root = tempfile::tempdir().unwrap();
	let data_dir = root.path().join("data");
	plant(&data_dir, "storage.key", b"storage-bytes");
	plant(&data_dir, "oauth_signing.key", b"oauth-bytes");
	plant(&data_dir, "oauth_public.key", b"public-bytes");
	let moved = move_legacy_keys(&data_dir).unwrap();
	assert_eq!(moved.len(), 2, "{moved:?}");
	assert_eq!(fs::read(storage_key(&data_dir)).unwrap(), b"storage-bytes");
	assert_eq!(
		fs::read(oauth_signing_key(&data_dir)).unwrap(),
		b"oauth-bytes"
	);
	assert!(!data_dir.join("keys/storage.key").exists());
	assert!(!data_dir.join("keys/oauth_signing.key").exists());
	assert!(
		data_dir.join("keys/oauth_public.key").exists(),
		"the public half is not a secret and stays"
	);
	assert_eq!(mode(&dir(&data_dir)), 0o700);
	assert_eq!(mode(&storage_key(&data_dir)), 0o600);
	assert!(
		move_legacy_keys(&data_dir).unwrap().is_empty(),
		"a second run has nothing to move"
	);
}

#[test]
fn a_copy_left_behind_that_matches_is_removed() {
	let root = tempfile::tempdir().unwrap();
	let data_dir = root.path().join("data");
	plant(&data_dir, "storage.key", b"same");
	fs::create_dir_all(dir(&data_dir)).unwrap();
	fs::write(storage_key(&data_dir), b"same").unwrap();
	move_legacy_keys(&data_dir).unwrap();
	assert!(!data_dir.join("keys/storage.key").exists());
	assert_eq!(fs::read(storage_key(&data_dir)).unwrap(), b"same");
}

#[test]
fn two_different_keys_are_left_for_the_operator() {
	let root = tempfile::tempdir().unwrap();
	let data_dir = root.path().join("data");
	plant(&data_dir, "storage.key", b"old");
	fs::create_dir_all(dir(&data_dir)).unwrap();
	fs::write(storage_key(&data_dir), b"new").unwrap();
	let error = move_legacy_keys(&data_dir).unwrap_err();
	assert!(error.contains("differ"), "{error}");
	assert!(error.contains(&data_dir.join("keys/storage.key").display().to_string()));
	assert_eq!(fs::read(data_dir.join("keys/storage.key")).unwrap(), b"old");
	assert_eq!(fs::read(storage_key(&data_dir)).unwrap(), b"new");
}

#[test]
fn a_symlink_in_place_of_a_key_is_not_followed() {
	let root = tempfile::tempdir().unwrap();
	let data_dir = root.path().join("data");
	fs::create_dir_all(data_dir.join("keys")).unwrap();
	fs::write(root.path().join("elsewhere"), b"x").unwrap();
	std::os::unix::fs::symlink(
		root.path().join("elsewhere"),
		data_dir.join("keys/storage.key"),
	)
	.unwrap();
	let error = move_legacy_keys(&data_dir).unwrap_err();
	assert!(error.contains("not a regular file"), "{error}");
}

#[test]
fn a_fresh_config_points_at_the_moved_storage_key() {
	let data_dir = Path::new("/srv/mail/data");
	let desired = with_storage_key("hostname = \"h\"\n".to_string(), None, data_dir);
	let value: toml::Value = toml::from_str(&desired).unwrap();
	assert_eq!(
		value["storage"]["encryption_key_file"].as_str(),
		Some("/srv/mail/secrets/storage.key")
	);
	assert!(
		value["storage"].get("encrypt_at_rest").is_none(),
		"init only names the key; turning encryption on stays the operator's choice"
	);
}

#[test]
fn an_old_path_is_repointed_and_an_operator_source_is_kept() {
	let data_dir = Path::new("/srv/mail/data");
	let repoint = |existing: &str| {
		let desired = with_storage_key(String::new(), Some(existing), data_dir);
		let value: toml::Value = toml::from_str(&desired).unwrap();
		value
			.get("storage")
			.and_then(|storage| storage.get("encryption_key_file"))
			.and_then(toml::Value::as_str)
			.map(str::to_string)
	};
	assert_eq!(
		repoint(
			"[storage]\nencrypt_at_rest = true\nencryption_key_file = \"/srv/mail/data/keys/storage.key\"\n"
		),
		Some("/srv/mail/secrets/storage.key".to_string())
	);
	assert_eq!(
		repoint("hostname = \"h\"\n"),
		Some("/srv/mail/secrets/storage.key".to_string())
	);
	assert_eq!(
		repoint("[storage]\nencryption_key_file = \"/etc/keys/mine\"\n"),
		None,
		"an operator's own key file is never replaced"
	);
	assert_eq!(
		repoint("[storage]\nencryption_key_env = \"MY_KEY\"\n"),
		None,
		"a file would win over the variable the operator chose"
	);
}

#[test]
fn stack_update_repoints_only_the_old_path_and_keeps_comments() {
	let data_dir = Path::new("/srv/mail/data");
	let text = "# my server\n[storage]\nencrypt_at_rest = true # on since May\nencryption_key_file = \"/srv/mail/data/keys/storage.key\"\n\n[oauth]\nsigning_key_file = \"/srv/mail/data/keys/oauth_signing.key\"\n";
	let rewritten = repoint_config(text, data_dir).unwrap().expect("changed");
	assert!(rewritten.contains("# my server"));
	assert!(rewritten.contains("# on since May"));
	assert!(rewritten.contains("encryption_key_file = \"/srv/mail/secrets/storage.key\""));
	assert!(rewritten.contains("signing_key_file = \"/srv/mail/secrets/oauth_signing.key\""));
	assert_eq!(repoint_config(&rewritten, data_dir).unwrap(), None);
	assert_eq!(
		repoint_config("[storage]\nencryption_key_file = \"/etc/mine\"\n", data_dir).unwrap(),
		None
	);
}
