//! A key whose file was lost or altered gets a new secret and keeps its row.

use super::*;
use crate::api::api_keys::sha256_hash;

#[test]
fn a_lost_file_gets_a_new_secret_for_the_same_key_and_the_same_expiry() {
	let layout = layout();
	run(&layout, NOW);
	let token = api_token_path(&layout.data);
	let (old_secret, old_row) = (text(&token), row(&layout));
	std::fs::remove_file(&token).expect("remove");
	let report = run(&layout, NOW + 10 * DAY);
	assert!(
		kinds(&report).contains(&("wrote", token.clone())),
		"{report:?}"
	);
	let new_secret = text(&token);
	assert_ne!(new_secret, old_secret);
	let key = row(&layout);
	assert_eq!(key.hash, sha256_hash(&new_secret));
	assert_ne!(key.hash, old_row.hash);
	assert_eq!(
		key.expires_at, old_row.expires_at,
		"a lost file is not a renewal"
	);
	assert_eq!(count_keys(&layout), 1);
}

#[test]
fn a_file_that_no_longer_matches_the_stored_key_is_replaced() {
	let layout = layout();
	run(&layout, NOW);
	let token = api_token_path(&layout.data);
	std::fs::write(&token, "not-the-secret").expect("tamper");
	let report = run(&layout, NOW + DAY);
	assert!(
		kinds(&report).contains(&("updated", token.clone())),
		"{report:?}"
	);
	assert_eq!(row(&layout).hash, sha256_hash(&text(&token)));
	assert_ne!(text(&token), "not-the-secret");
}

#[test]
fn a_line_ending_an_editor_added_does_not_make_the_file_a_mismatch() {
	let layout = layout();
	run(&layout, NOW);
	let token = api_token_path(&layout.data);
	let secret = text(&token);
	std::fs::write(&token, format!("{secret}\n")).expect("edit");
	let report = run(&layout, NOW + DAY);
	assert!(
		kinds(&report).contains(&("reused", token.clone())),
		"{report:?}"
	);
	assert_eq!(text(&token), format!("{secret}\n"));
}

#[test]
fn a_file_whose_row_was_revoked_gets_a_new_key() {
	let layout = layout();
	run(&layout, NOW);
	let token = api_token_path(&layout.data);
	let old_secret = text(&token);
	ApiKeyStore::open(&layout.data)
		.expect("open")
		.remove(LABEL)
		.expect("revoke");
	run(&layout, NOW + DAY);
	assert_ne!(text(&token), old_secret);
	assert_eq!(row(&layout).hash, sha256_hash(&text(&token)));
}
