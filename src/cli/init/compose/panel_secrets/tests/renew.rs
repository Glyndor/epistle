//! The key is replaced when fewer than 30 days remain, and only then.

use super::*;
use crate::api::api_keys::sha256_hash;

/// A layout whose key was created at `NOW`, run again `elapsed` seconds later.
fn after(elapsed: u64) -> (Layout, Report, String) {
	let layout = layout();
	run(&layout, NOW);
	let before = text(&api_token_path(&layout.data));
	let report = run(&layout, NOW + elapsed);
	(layout, report, before)
}

#[test]
fn a_key_with_31_days_left_is_reused() {
	let (layout, report, before) = after(365 * DAY - 31 * DAY);
	assert!(
		kinds(&report).contains(&("reused", api_token_path(&layout.data))),
		"{report:?}"
	);
	assert_eq!(text(&api_token_path(&layout.data)), before);
}

#[test]
fn a_key_with_exactly_30_days_left_is_reused() {
	let (layout, report, before) = after(365 * DAY - 30 * DAY);
	assert!(kinds(&report).contains(&("reused", api_token_path(&layout.data))));
	assert_eq!(text(&api_token_path(&layout.data)), before);
}

#[test]
fn a_key_with_under_30_days_left_gets_a_new_secret_and_a_new_year() {
	let elapsed = 365 * DAY - 29 * DAY;
	let (layout, report, before) = after(elapsed);
	let token = api_token_path(&layout.data);
	assert!(
		kinds(&report).contains(&("updated", token.clone())),
		"{report:?}"
	);
	let after = text(&token);
	assert_ne!(after, before);
	let key = row(&layout);
	assert_eq!(
		key.hash,
		sha256_hash(&after),
		"the new secret is the stored one"
	);
	assert_eq!(key.expires_at, Some(NOW + elapsed + 365 * DAY));
	assert_eq!(key.scopes, ["read", "write"]);
	assert_eq!(count_keys(&layout), 1);
}

#[test]
fn a_key_that_already_expired_is_renewed_the_same_way() {
	let (layout, _, before) = after(400 * DAY);
	assert_ne!(text(&api_token_path(&layout.data)), before);
	assert_eq!(row(&layout).expires_at, Some(NOW + 400 * DAY + 365 * DAY));
}

#[test]
fn a_panel_key_with_no_expiry_is_given_one() {
	let layout = layout();
	run(&layout, NOW);
	// A key an older hand-made file may have: no expiry at all.
	let text_before = std::fs::read_to_string(layout.data.join("api_keys.toml")).expect("read");
	let stripped: String = text_before
		.lines()
		.filter(|line| !line.starts_with("expires_at"))
		.map(|line| format!("{line}\n"))
		.collect();
	std::fs::write(layout.data.join("api_keys.toml"), stripped).expect("write");
	let store = ApiKeyStore::open(&layout.data).expect("reopen");
	assert_eq!(store.keys()[0].expires_at, None);
	run(&layout, NOW + DAY);
	assert_eq!(row(&layout).expires_at, Some(NOW + DAY + 365 * DAY));
}
