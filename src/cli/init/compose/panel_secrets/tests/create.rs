//! The first run lays both secrets down with the right reach, mode and owner.

use super::*;
use crate::api::api_keys::sha256_hash;

#[test]
fn the_first_run_creates_the_key_row_and_both_files() {
	let layout = layout();
	let report = run(&layout, NOW);
	let (token, session) = (
		api_token_path(&layout.data),
		session_secret_path(&layout.data),
	);
	assert_eq!(
		kinds(&report),
		[("wrote", token.clone()), ("wrote", session.clone())]
	);
	let key = row(&layout);
	assert_eq!(
		key.hash,
		sha256_hash(&text(&token)),
		"the stored hash is the file's secret"
	);
	assert!(!text(&token).is_empty());
	assert!(
		!text(&token).ends_with('\n'),
		"no line ending in the secret"
	);
}

#[test]
fn the_key_has_exactly_the_scopes_read_and_write_and_no_other_reach() {
	let layout = layout();
	run(&layout, NOW);
	let key = row(&layout);
	assert_eq!(key.label, "panel");
	assert_eq!(key.scopes, ["read", "write"]);
	assert!(key.domains.is_empty());
	assert_eq!(key.account, None);
	assert_eq!(key.ip_cidr, None);
}

#[test]
fn the_key_expires_in_365_days() {
	let layout = layout();
	run(&layout, NOW);
	assert_eq!(row(&layout).expires_at, Some(NOW + 365 * DAY));
}

#[test]
fn the_files_are_owner_only_in_an_owner_only_directory() {
	let layout = layout();
	run(&layout, NOW);
	let dir = layout.data.parent().expect("parent").join("secrets");
	assert_eq!(mode(&dir), 0o700);
	assert_eq!(mode(&api_token_path(&layout.data)), 0o600);
	assert_eq!(mode(&session_secret_path(&layout.data)), 0o600);
}

#[test]
fn the_files_belong_to_the_account_that_ran_the_command() {
	use std::os::unix::fs::MetadataExt;
	let layout = layout();
	run(&layout, NOW);
	// SAFETY: `geteuid` takes no arguments, reads no memory and cannot fail.
	let me = unsafe { libc::geteuid() };
	for path in paths(&layout.data) {
		assert_eq!(
			std::fs::metadata(&path).expect("metadata").uid(),
			me,
			"{path:?}"
		);
	}
}

#[test]
fn a_loose_directory_from_an_older_deploy_is_tightened() {
	use std::os::unix::fs::PermissionsExt;
	let layout = layout();
	let dir = layout.data.parent().expect("parent").join("secrets");
	std::fs::create_dir_all(&dir).expect("dir");
	std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
	run(&layout, NOW);
	assert_eq!(mode(&dir), 0o700);
}

#[test]
fn the_session_secret_is_96_hex_characters_and_differs_between_installs() {
	let (first, second) = (layout(), layout());
	run(&first, NOW);
	run(&second, NOW);
	let (a, b) = (
		text(&session_secret_path(&first.data)),
		text(&session_secret_path(&second.data)),
	);
	assert_eq!(a.len(), SESSION_SECRET_BYTES * 2);
	assert!(a.bytes().all(|byte| byte.is_ascii_hexdigit()), "{a}");
	assert_ne!(a, b);
	assert_ne!(
		text(&api_token_path(&first.data)),
		text(&api_token_path(&second.data))
	);
}

#[test]
fn the_two_secrets_are_different_values() {
	let layout = layout();
	run(&layout, NOW);
	assert_ne!(
		text(&api_token_path(&layout.data)),
		text(&session_secret_path(&layout.data))
	);
}
