//! `is_live` reads one fixed file directly under the data dir; a revoked id
//! is not live, anything else is, and an unreadable store fails closed.

use super::super::revocation::is_live;

fn store_with(dir: &std::path::Path, id: &str, expiry: u64) {
	let hash = crate::api::api_keys::sha256_hash(id);
	std::fs::write(
		dir.join("oauth_revocations.json"),
		format!("{{\"revoked\":{{\"{hash}\":{expiry}}}}}"),
	)
	.expect("write store");
}

#[test]
fn a_data_dir_without_a_store_has_every_token_live() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert!(is_live(dir.path(), "jti-1", 100));
}

#[test]
fn a_revoked_id_is_not_live_until_its_expiry_passes() {
	let dir = tempfile::tempdir().expect("tempdir");
	store_with(dir.path(), "jti-1", 500);
	assert!(!is_live(dir.path(), "jti-1", 100));
	assert!(is_live(dir.path(), "jti-2", 100));
	assert!(is_live(dir.path(), "jti-1", 500));
}

#[test]
fn an_id_that_looks_like_a_path_never_picks_the_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	store_with(dir.path(), "jti-1", 500);
	for hostile in ["../oauth_revocations.json", "/etc/passwd", "..", ""] {
		assert!(is_live(dir.path(), hostile, 100), "{hostile:?}");
	}
	assert!(!is_live(dir.path(), "jti-1", 100));
}

#[test]
fn a_store_that_does_not_parse_fails_closed() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::write(dir.path().join("oauth_revocations.json"), b"{not json").expect("write");
	assert!(!is_live(dir.path(), "jti-1", 100));
}

#[cfg(unix)]
#[test]
fn a_data_dir_reached_through_a_link_still_reads_its_store() {
	let dir = tempfile::tempdir().expect("tempdir");
	let real = dir.path().join("real");
	std::fs::create_dir(&real).expect("real");
	store_with(&real, "jti-1", 500);
	let link = dir.path().join("link");
	std::os::unix::fs::symlink(&real, &link).expect("symlink");
	assert!(!is_live(&link, "jti-1", 100));
}
