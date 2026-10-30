//! A removed account takes the API keys bound to it along.

use super::base::{seed, store_and_spool};
use super::*;
use crate::api::api_keys::{ApiKey, ApiKeyStore, sha256_hash};

fn key(label: &str, account: Option<&str>) -> ApiKey {
	ApiKey {
		label: label.to_string(),
		hash: sha256_hash(label),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".to_string()],
		domains: Vec::new(),
		account: account.map(str::to_string),
	}
}

#[tokio::test]
async fn keys_bound_to_a_removed_account_are_retired() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "dora");
	let mut keys = ApiKeyStore::open(dir.path()).expect("open keys");
	keys.add(key("dora-key", Some("dora"))).expect("add");
	keys.add(key("dora-upper", Some("DORA"))).expect("add");
	keys.add(key("erin-key", Some("erin"))).expect("add");
	keys.add(key("admin-key", None)).expect("add");

	remove_account(&store, &spool, dir.path(), "dora", QueuePolicy::Drain, None)
		.await
		.expect("remove");

	let left: Vec<String> = ApiKeyStore::open(dir.path())
		.expect("reopen")
		.keys()
		.iter()
		.map(|key| key.label.clone())
		.collect();
	assert_eq!(left, vec!["erin-key", "admin-key"]);
}

#[tokio::test]
async fn removing_an_account_without_a_key_file_creates_none() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "dora");
	remove_account(&store, &spool, dir.path(), "dora", QueuePolicy::Drain, None)
		.await
		.expect("remove");
	assert!(!dir.path().join("api_keys.toml").exists());
}

#[tokio::test]
async fn blobs_uploaded_under_a_removed_account_are_dropped() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (store, spool) = store_and_spool(dir.path());
	seed(dir.path(), &store, &spool, "dora");
	let own = dir.path().join("blobs/accounts/dora/ab/cd");
	let other = dir.path().join("blobs/accounts/erin/ab/cd");
	for partition in [&own, &other] {
		std::fs::create_dir_all(partition).expect("mkdir");
		std::fs::write(partition.join("blob"), b"payload").expect("write");
	}

	remove_account(&store, &spool, dir.path(), "dora", QueuePolicy::Drain, None)
		.await
		.expect("remove");

	assert!(!dir.path().join("blobs/accounts/dora").exists());
	assert!(other.join("blob").exists());
}
