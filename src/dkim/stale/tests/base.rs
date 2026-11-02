//! Which records of the shared key are left at the domains that moved, and
//! what a lookup of them does and does not prove.

use std::collections::HashMap;
use std::pin::Pin;

use super::*;
use crate::dkim::test_support::KeyDns;
use crate::spf::DnsFailure;

/// Returns the config and the record value the shared key publishes.
fn config(dir: &std::path::Path) -> (Config, String) {
	let (pem, record) = crate::dkim::generate_key().expect("key");
	let key = dir.join("default.pem");
	std::fs::write(&key, pem).expect("write");
	let config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\n\
		 domains = ['keep.example', 'moved.example']\n\
		 [dkim]\nselector = 's1'\nkey_file = {key:?}\nrsa_selector = 's2'\nrsa_key_file = '/x/rsa.pem'\n\
		 [[dkim.domain]]\nname = 'moved.example'\nselector = 'own1'\nkey_file = '/x/own.pem'\n"
	))
	.expect("config");
	(config, record)
}

fn names(list: Vec<Stale>) -> Vec<String> {
	list.into_iter().map(|s| s.name).collect()
}

fn stale(config: &Config) -> Stale {
	super::names(config)
		.expect("names")
		.into_iter()
		.next()
		.expect("one name")
}

#[test]
fn the_shared_selector_is_stale_at_a_moved_domain_and_never_at_the_keeper() {
	let dir = tempfile::tempdir().expect("dir");
	let found = names(super::names(&config(dir.path()).0).expect("names"));
	assert_eq!(
		found,
		["s1._domainkey.moved.example", "s2._domainkey.moved.example"]
	);
	assert!(found.iter().all(|name| !name.ends_with("keep.example")));
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
	let found = names(super::names(&config(dir.path()).0).expect("names"));
	for selector in ["ed100", "ed90", "rsa100", "rsa90", "s1"] {
		assert!(
			found.contains(&format!("{selector}._domainkey.moved.example")),
			"{selector}: {found:?}"
		);
	}
}

#[test]
fn a_selector_the_domain_uses_itself_is_not_stale() {
	let dir = tempfile::tempdir().expect("dir");
	let (config, _) = config(dir.path());
	let found = super::names_for(&config, "moved.example", &["s1".into()]).expect("names");
	let found = names(found);
	assert_eq!(found, ["s2._domainkey.moved.example"]);
}

#[tokio::test]
async fn the_shared_key_is_recognised_by_its_public_key() {
	let dir = tempfile::tempdir().expect("dir");
	let (config, record) = config(dir.path());
	let dns = KeyDns(HashMap::from([(
		"s1._domainkey.moved.example".to_string(),
		vec![record.clone()],
	)]));
	assert_eq!(
		presence(&dns, &stale(&config)).await,
		Presence::Shared {
			shared: vec![record],
			others: Vec::new()
		}
	);
}

#[tokio::test]
async fn another_key_at_the_same_name_is_not_ours_and_is_not_marked_shared() {
	let dir = tempfile::tempdir().expect("dir");
	let (config, _) = config(dir.path());
	let (_, foreign) = crate::dkim::generate_key().expect("key");
	let dns = KeyDns(HashMap::from([(
		"s1._domainkey.moved.example".to_string(),
		vec![foreign],
	)]));
	let found = survey(&dns, super::names(&config).expect("names")).await;
	assert!(found.shared.is_empty(), "{found:?}");
	assert_eq!(found.not_ours.len(), 1);
}

#[tokio::test]
async fn a_dkim_prefix_alone_proves_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	let (config, _) = config(dir.path());
	let dns = KeyDns(HashMap::from([(
		"s1._domainkey.moved.example".to_string(),
		vec!["v=DKIM1; k=ed25519; p=AAAA".to_string()],
	)]));
	assert!(matches!(
		presence(&dns, &stale(&config)).await,
		Presence::NotOurs(_)
	));
}

#[tokio::test]
async fn a_record_with_no_p_tag_is_unknown_not_gone() {
	let dir = tempfile::tempdir().expect("dir");
	let (config, _) = config(dir.path());
	let dns = KeyDns(HashMap::from([(
		"s1._domainkey.moved.example".to_string(),
		vec!["v=DKIM1; k=ed25519".to_string()],
	)]));
	assert!(matches!(
		presence(&dns, &stale(&config)).await,
		Presence::Unknown(_)
	));
}

#[tokio::test]
async fn nothing_published_is_absent() {
	let dir = tempfile::tempdir().expect("dir");
	let (config, _) = config(dir.path());
	let dns = KeyDns(HashMap::new());
	assert_eq!(presence(&dns, &stale(&config)).await, Presence::Absent);
}

/// A resolver that cannot answer.
struct Failing;

impl DnsLookup for Failing {
	fn txt(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Err(DnsFailure::Temporary) })
	}

	fn addresses(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(
		&self,
		_name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

#[tokio::test]
async fn a_lookup_that_fails_is_unknown_never_absent() {
	let dir = tempfile::tempdir().expect("dir");
	let (config, _) = config(dir.path());
	let found = survey(&Failing, super::names(&config).expect("names")).await;
	assert_eq!(found.unknown.len(), 2);
	assert!(found.shared.is_empty() && found.not_ours.is_empty());
}

#[tokio::test]
async fn every_value_of_the_shared_key_is_returned_and_the_others_are_kept_apart() {
	let dir = tempfile::tempdir().expect("dir");
	let (config, record) = config(dir.path());
	let p = public_part(&record).expect("p");
	let variant = format!("v=DKIM1;k=ed25519;p={p}");
	let (_, foreign) = crate::dkim::generate_key().expect("key");
	let dns = KeyDns(HashMap::from([(
		"s1._domainkey.moved.example".to_string(),
		vec![record.clone(), variant.clone(), foreign.clone()],
	)]));
	assert_eq!(
		presence(&dns, &stale(&config)).await,
		Presence::Shared {
			shared: vec![record, variant],
			others: vec![foreign]
		}
	);
}

#[tokio::test]
async fn a_record_is_unknown_when_the_shared_key_is_not_on_this_host() {
	let dir = tempfile::tempdir().expect("dir");
	let (config, _) = config(dir.path());
	let candidate = stale(&config);
	std::fs::remove_file(dir.path().join("default.pem")).expect("remove");
	let candidate = Stale {
		unreadable: super::names(&config).expect("names")[0].unreadable.clone(),
		..candidate
	};
	let (_, foreign) = crate::dkim::generate_key().expect("key");
	let dns = KeyDns(HashMap::from([(
		"s1._domainkey.moved.example".to_string(),
		vec![foreign],
	)]));
	match presence(&dns, &candidate).await {
		Presence::Unknown(why) => assert!(why.contains("is not on this host"), "{why}"),
		other => panic!("{other:?}"),
	}
}

#[test]
fn a_key_file_that_is_there_and_does_not_load_is_told_apart_from_a_missing_one() {
	let dir = tempfile::tempdir().expect("dir");
	let (config, _) = config(dir.path());
	std::fs::write(dir.path().join("default.pem"), "not a key").expect("write");
	let why = super::names(&config).expect("names")[0]
		.unreadable
		.clone()
		.expect("unreadable");
	assert!(
		why.contains("cannot read") && !why.contains("not on this host"),
		"{why}"
	);
}

#[test]
fn a_selector_published_with_two_keys_over_time_expects_both() {
	let dir = tempfile::tempdir().expect("dir");
	let (config, record) = config(dir.path());
	// The rotation put another key in service under the same selector name.
	let (pem, other) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.path().join("dkim-s1.key"), pem).expect("write");
	let state = serde_json::json!({
		"selector": "s1", "key_file": "dkim-s1.key", "rotated_at": 1, "previous": null
	});
	std::fs::write(dir.path().join("dkim-rotation.json"), state.to_string()).expect("state");
	let expected = super::names(&config).expect("names")[0].expected.clone();
	assert_eq!(expected.len(), 2, "{expected:?}");
	for value in [record, other] {
		assert!(expected.contains(&public_part(&value).expect("p")));
	}
}
