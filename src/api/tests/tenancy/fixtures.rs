//! The two-tenant world the isolation tests drive: one account each,
//! one queued message, one key confined to the first.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::base::TOKEN;
use super::*;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::imap::mailbox::{self, Flag, Snapshot};
use crate::queue::SuppressionList;
use crate::smtp::session::AcceptedMessage;
use crate::storage::{FsSpool, MessageCrypto};
use crate::test_support::fixtures;

pub(super) fn tenant_key() -> &'static str {
	fixtures::api_key()
}

pub(super) fn account(name: &str, address: &str) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: crate::smtp::auth::tests::base::hash(fixtures::password()),
		..DynamicAccount::default()
	}
}

pub(super) fn queue_message(spool: &FsSpool, reverse_path: &str) -> uuid::Uuid {
	spool
		.store(
			&AcceptedMessage {
				reverse_path: reverse_path.to_string(),
				recipients: vec!["someone@elsewhere.test".to_string()],
				data: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("queue message")
}

/// What the fixture put in each tenant, for the assertions.
pub(super) struct World {
	_dir: tempfile::TempDir,
	pub(super) state: ApiState,
	pub(super) store: Arc<AccountStore>,
	pub(super) alice_entry: uuid::Uuid,
	pub(super) carol_entry: uuid::Uuid,
	pub(super) null_path_entry: uuid::Uuid,
	pub(super) carol_archived: uuid::Uuid,
}

pub(super) fn world() -> World {
	let dir = tempfile::tempdir().expect("tempdir");
	let domains = vec!["a.test".to_string(), "b.test".to_string()];
	let store = Arc::new(
		AccountStore::open(
			dir.path(),
			domains.clone(),
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	store.add(account("alice", "alice@a.test")).expect("alice");
	store.add(account("carol", "carol@b.test")).expect("carol");
	let mut keys = crate::api::ApiKeyStore::open(dir.path()).expect("key store");
	keys.add(crate::api::api_keys::ApiKey {
		label: "tenant-a".to_string(),
		hash: crate::api::api_keys::sha256_hash(tenant_key()),
		expires_at: None,
		ip_cidr: None,
		scopes: vec!["read".to_string(), "write".to_string()],
		domains: vec!["a.test".to_string()],
		account: None,
	})
	.expect("add key");
	drop(keys);
	let spool = FsSpool::open(dir.path()).expect("spool");
	let alice_entry = queue_message(&spool, "alice@a.test");
	let carol_entry = queue_message(&spool, "carol@b.test");
	let null_path_entry = queue_message(&spool, "");
	let suppression = SuppressionList::open(dir.path()).expect("suppression");
	suppression.suppress("victim@b.test");
	suppression.suppress_for("alice", "alice-gone@elsewhere.test");
	suppression.suppress_for("carol", "carol-gone@elsewhere.test");
	store
		.add_masked("carol", "shop", "b.test", 1)
		.expect("carol mask");
	let id = mailbox::append(
		dir.path(),
		"carol",
		"INBOX",
		&[],
		b"Subject: private\r\n\r\nbody\r\n",
		&MessageCrypto::disabled(),
	)
	.expect("append");
	let mut snapshot = Snapshot::open_at(
		dir.path(),
		"carol",
		"INBOX",
		&MessageCrypto::disabled(),
		30,
		1_000,
	)
	.expect("snapshot");
	snapshot.store_flags(1, vec![Flag::Deleted]).expect("flag");
	snapshot.expunge().expect("expunge");
	let state = ApiState::new(
		&crate::smtp::auth::tests::base::hash(TOKEN.as_str()),
		dir.path().to_path_buf(),
		domains,
		store.clone(),
		spool,
	)
	.with_directory(store.handle());
	World {
		_dir: dir,
		state,
		store,
		alice_entry,
		carol_entry,
		null_path_entry,
		carol_archived: id,
	}
}

pub(super) fn queue_ids(body: &serde_json::Value) -> Vec<String> {
	body["entries"]
		.as_array()
		.expect("entries")
		.iter()
		.map(|entry| entry["id"].as_str().expect("id").to_string())
		.collect()
}
