//! Which records of the shared key are left at the domains that moved.

use std::collections::HashMap;

use super::*;
use crate::dkim::test_support::KeyDns;

fn config(dir: &std::path::Path, extra: &str) -> Config {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let key = dir.join("default.pem");
	std::fs::write(&key, pem).expect("write");
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\n\
		 domains = ['keep.example', 'moved.example']\n\
		 [dkim]\nselector = 's1'\nkey_file = {key:?}\nrsa_selector = 's2'\nrsa_key_file = '/x/rsa.pem'\n{extra}\n\
		 [[dkim.domain]]\nname = 'moved.example'\nselector = 'own1'\nkey_file = '/x/own.pem'\n"
	))
	.expect("config")
}

fn names(list: Vec<Stale>) -> Vec<String> {
	list.into_iter().map(|s| s.name).collect()
}

#[test]
fn the_default_pair_is_stale_at_a_moved_domain_and_never_at_the_keeper() {
	let dir = tempfile::tempdir().expect("dir");
	let found = names(super::names(&config(dir.path(), "")).expect("names"));
	assert_eq!(
		found,
		["s1._domainkey.moved.example", "s2._domainkey.moved.example"]
	);
	assert!(
		found.iter().all(|name| !name.ends_with("keep.example")),
		"the domain that keeps the key is never listed"
	);
}

#[test]
fn rotated_selectors_in_service_and_retiring_are_listed_too() {
	let dir = tempfile::tempdir().expect("dir");
	let state = serde_json::json!({
		"selector": "ed100", "key_file": "dkim-ed100.key", "rotated_at": 1,
		"previous": { "selector": "ed90", "key_file": "", "retire_at": 9,
			"rsa": { "selector": "rsa90", "key_file": "" } },
		"rsa": { "selector": "rsa100", "key_file": "dkim-rsa100.key" }
	});
	std::fs::write(dir.path().join("dkim-rotation.json"), state.to_string()).expect("state");
	let found = names(super::names(&config(dir.path(), "")).expect("names"));
	for selector in ["ed100", "ed90", "rsa100", "rsa90", "s1", "s2"] {
		assert!(
			found.contains(&format!("{selector}._domainkey.moved.example")),
			"{selector}: {found:?}"
		);
	}
}

#[test]
fn a_selector_the_domain_uses_itself_is_not_stale() {
	let dir = tempfile::tempdir().expect("dir");
	let found = names(
		super::names_for(&config(dir.path(), ""), "moved.example", &["s1".into()]).expect("names"),
	);
	assert_eq!(found, ["s2._domainkey.moved.example"]);
}

#[tokio::test]
async fn only_the_records_that_are_published_are_reported() {
	let dir = tempfile::tempdir().expect("dir");
	let dns = KeyDns(HashMap::from([(
		"s1._domainkey.moved.example".to_string(),
		vec!["v=DKIM1; k=ed25519; p=AAAA".to_string()],
	)]));
	let candidates = super::names(&config(dir.path(), "")).expect("names");
	let found = published(&dns, candidates).await;
	assert_eq!(names(found), ["s1._domainkey.moved.example"]);
}
