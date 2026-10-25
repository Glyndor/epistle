//! A masked address that is switched off resolves like an unknown user, but
//! the rebuilt directory knows it is only paused, so a report to it is not
//! given up on.

use super::*;
use crate::smtp::address::Address;
use crate::smtp::directory::Resolution;

#[test]
fn a_disabled_mask_is_paused_not_gone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = AccountStore::open(
		dir.path(),
		vec!["example.org".to_string()],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open store");
	let text = r#"{
		"addresses": {
			"shop.abcd1234@example.org": {
				"address": "shop.abcd1234@example.org",
				"account": "alice",
				"label": "shop",
				"created_at": 1700000000,
				"enabled": false
			}
		}
	}"#;
	store.reload_masked_from(text).expect("reload");
	let directory = store.handle().current();
	let masked = Address::parse("shop.abcd1234@example.org").expect("address");
	let other = Address::parse("nobody@example.org").expect("address");
	assert_eq!(directory.resolve(&masked), Resolution::UnknownUser);
	assert!(directory.is_paused(&masked));
	assert!(!directory.is_paused(&other));
}
