//! `dkim show` says the split is incomplete while the shared key is published
//! at a domain that has a key of its own.

use std::collections::HashMap;

use super::*;
use crate::dkim::test_support::KeyDns;

fn config(dir: &std::path::Path) -> Config {
	let (shared, _) = crate::dkim::generate_key().expect("key");
	let (own, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.join("shared.pem"), shared).expect("write");
	std::fs::write(dir.join("own.pem"), own).expect("write");
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['keep.example', 'moved.example']\n\
		 [dkim]\nselector = 'mail'\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = 'moved.example'\nselector = 'own1'\nkey_file = {:?}\n",
		dir.join("shared.pem"),
		dir.join("own.pem"),
	))
	.expect("config")
}

#[tokio::test]
async fn a_shared_record_at_a_moved_domain_is_listed_and_the_keepers_is_not() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path());
	let shared = crate::dkim::Signer::load("mail", &dir.path().join("shared.pem"))
		.expect("loads")
		.dns_record_value();
	let dns = KeyDns(HashMap::from([
		(
			"mail._domainkey.moved.example".to_string(),
			vec![shared.clone()],
		),
		("mail._domainkey.keep.example".to_string(), vec![shared]),
	]));
	let view = build(&config, Some(&dns)).await.expect("view");
	assert_eq!(view.stale_records, ["mail._domainkey.moved.example"]);
	let mut out = Vec::new();
	assert_eq!(render(&view, false, &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8(out).expect("utf-8");
	assert!(text.contains("split incomplete"), "{text}");
}

#[tokio::test]
async fn a_lookup_that_fails_is_not_read_as_a_finished_split() {
	let dir = tempfile::tempdir().expect("dir");
	let dns = crate::dkim::test_support::FailingDns;
	let view = build(&config(dir.path()), Some(&dns)).await.expect("view");
	assert!(view.stale_records.is_empty());
	assert_eq!(view.stale_unchecked.len(), 1, "{:?}", view.stale_unchecked);
	let mut out = Vec::new();
	assert_eq!(render(&view, false, &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8(out).expect("utf-8");
	assert!(
		text.contains("could not check whether the shared key"),
		"{text}"
	);
}

#[tokio::test]
async fn a_foreign_record_at_the_name_is_not_listed_as_the_shared_key() {
	let dir = tempfile::tempdir().expect("dir");
	let dns = KeyDns(HashMap::from([(
		"mail._domainkey.moved.example".to_string(),
		vec!["v=DKIM1; k=ed25519; p=AAAA".to_string()],
	)]));
	let view = build(&config(dir.path()), Some(&dns)).await.expect("view");
	assert!(view.stale_records.is_empty());
}

#[tokio::test]
async fn nothing_is_listed_once_the_record_is_gone() {
	let dir = tempfile::tempdir().expect("dir");
	let dns = KeyDns(HashMap::new());
	let view = build(&config(dir.path()), Some(&dns)).await.expect("view");
	assert!(view.stale_records.is_empty());
}
