//! A key confined to one tenant's domains reaches only that tenant's data on
//! every route that holds per-tenant data: the queue, the suppression lists,
//! masked addresses, the archive, credential verification and the status
//! counters. Two tenants, `a.test` and `b.test`; the key is confined to `a.test`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;

use super::tests::{TOKEN, request, request_with_body};
use super::*;
use crate::directory_store::{AccountStore, DynamicAccount};
use crate::imap::mailbox::{self, Flag, Snapshot};
use crate::queue::SuppressionList;
use crate::smtp::session::AcceptedMessage;
use crate::storage::{FsSpool, MessageCrypto};
use crate::test_fixtures as fixtures;

fn tenant_key() -> &'static str {
	fixtures::api_key()
}

fn account(name: &str, address: &str) -> DynamicAccount {
	DynamicAccount {
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: crate::smtp::auth::tests::base::hash(fixtures::password()),
		..DynamicAccount::default()
	}
}

fn queue_message(spool: &FsSpool, reverse_path: &str) -> uuid::Uuid {
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
struct World {
	_dir: tempfile::TempDir,
	state: ApiState,
	store: Arc<AccountStore>,
	alice_entry: uuid::Uuid,
	carol_entry: uuid::Uuid,
	null_path_entry: uuid::Uuid,
	carol_archived: uuid::Uuid,
}

fn world() -> World {
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

fn queue_ids(body: &serde_json::Value) -> Vec<String> {
	body["entries"]
		.as_array()
		.expect("entries")
		.iter()
		.map(|entry| entry["id"].as_str().expect("id").to_string())
		.collect()
}

#[tokio::test]
async fn the_queue_lists_only_the_tenants_own_messages() {
	let world = world();
	let app = router(world.state.clone());
	let (status, body) = request(&app, "GET", "/api/v1/queue", Some(tenant_key())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(queue_ids(&body), [world.alice_entry.to_string()]);
	let (_, all) = request(&app, "GET", "/api/v1/queue", Some(TOKEN.as_str())).await;
	assert_eq!(
		queue_ids(&all).len(),
		3,
		"the configured token sees all three"
	);
}

#[tokio::test]
async fn another_tenants_queue_entry_cannot_be_removed() {
	let world = world();
	let app = router(world.state.clone());
	for id in [world.carol_entry, world.null_path_entry] {
		let (status, _) = request(
			&app,
			"DELETE",
			&format!("/api/v1/queue/{id}"),
			Some(tenant_key()),
		)
		.await;
		assert_eq!(status, StatusCode::NOT_FOUND, "entry {id}");
		assert!(
			world.state.spool().load(id).is_ok(),
			"entry {id} must stay queued"
		);
	}
	let own = world.alice_entry;
	let (status, _) = request(
		&app,
		"DELETE",
		&format!("/api/v1/queue/{own}"),
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_shared_suppression_list_is_not_for_a_confined_key() {
	let world = world();
	let app = router(world.state.clone());
	let (status, _) = request(&app, "GET", "/api/v1/suppression", Some(tenant_key())).await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let (status, _) = request(
		&app,
		"DELETE",
		"/api/v1/suppression/victim%40b.test",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::FORBIDDEN);
	let (_, listed) = request(&app, "GET", "/api/v1/suppression", Some(TOKEN.as_str())).await;
	assert_eq!(listed["addresses"], json!(["victim@b.test"]));
}

#[tokio::test]
async fn an_account_suppression_list_follows_the_account_scope() {
	let world = world();
	let app = router(world.state.clone());
	let (status, own) = request(
		&app,
		"GET",
		"/api/v1/suppression?account=alice",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(own["addresses"], json!(["alice-gone@elsewhere.test"]));
	let (status, _) = request(
		&app,
		"GET",
		"/api/v1/suppression?account=carol",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let path = "/api/v1/suppression/carol-gone%40elsewhere.test?account=carol";
	let (status, _) = request(&app, "DELETE", path, Some(tenant_key())).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(
		SuppressionList::open(world.state.data_dir())
			.expect("list")
			.list_for("carol"),
		["carol-gone@elsewhere.test"]
	);
}

#[tokio::test]
async fn masked_addresses_of_another_tenants_account_are_out_of_reach() {
	let world = world();
	let app = router(world.state.clone());
	let (status, _) = request(
		&app,
		"GET",
		"/api/v1/accounts/carol/masked",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/carol/masked",
		Some(tenant_key()),
		Some(json!({"label": "evil"})),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(
		world.store.list_masked("carol").len(),
		1,
		"no alias was minted"
	);
	let address = world.store.list_masked("carol")[0].address.clone();
	let path = format!("/api/v1/accounts/carol/masked/{address}");
	let off = Some(json!({"enabled": false}));
	let (status, _) = request_with_body(&app, "PATCH", &path, Some(tenant_key()), off).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, _) = request(&app, "DELETE", &path, Some(tenant_key())).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert!(
		world.store.list_masked("carol")[0].enabled,
		"the alias is untouched"
	);
	let (status, _) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts/alice/masked",
		Some(tenant_key()),
		Some(json!({"label": "shop"})),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn the_archive_of_another_tenants_account_is_out_of_reach() {
	let world = world();
	let app = router(world.state.clone());
	let (status, _) = request(
		&app,
		"GET",
		"/api/v1/accounts/carol/archive",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let path = format!(
		"/api/v1/accounts/carol/archive/{}/restore",
		world.carol_archived
	);
	let (status, _) = request(&app, "POST", &path, Some(tenant_key())).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, listed) = request(
		&app,
		"GET",
		"/api/v1/accounts/carol/archive",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		listed["entries"].as_array().expect("entries").len(),
		1,
		"still archived"
	);
}

#[tokio::test]
async fn credential_verification_does_not_confirm_another_tenants_password() {
	let world = world();
	let app = router(world.state.clone());
	let verify = |name: &str| Some(json!({"name": name, "password": fixtures::password()}));
	for name in ["carol", "carol@b.test"] {
		let (status, body) = request_with_body(
			&app,
			"POST",
			"/api/v1/auth/verify",
			Some(tenant_key()),
			verify(name),
		)
		.await;
		assert_eq!(status, StatusCode::OK);
		assert_eq!(body["valid"], false, "{name} is not this key's to check");
	}
	let (_, own) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(tenant_key()),
		verify("alice"),
	)
	.await;
	assert_eq!(own["valid"], true);
	let (_, any) = request_with_body(
		&app,
		"POST",
		"/api/v1/auth/verify",
		Some(TOKEN.as_str()),
		verify("carol"),
	)
	.await;
	assert_eq!(any["valid"], true, "the configured token verifies anyone");
}

#[tokio::test]
async fn the_status_counters_cover_only_the_tenants_own_scope() {
	let world = world();
	let app = router(world.state.clone());
	let (status, own) = request(&app, "GET", "/api/v1/status", Some(tenant_key())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(own["domains"], 1);
	assert_eq!(own["accounts"], 1);
	assert!(
		own.get("queue_size").is_none(),
		"the queue is shared: {own}"
	);
	let (_, all) = request(&app, "GET", "/api/v1/status", Some(TOKEN.as_str())).await;
	assert_eq!(all["domains"], 2);
	assert_eq!(all["accounts"], 2);
	assert_eq!(all["queue_size"], 3);
}

#[tokio::test]
async fn two_factor_and_display_name_of_another_tenants_account_are_out_of_reach() {
	let world = world();
	let app = router(world.state.clone());
	let (status, _) = request(
		&app,
		"POST",
		"/api/v1/accounts/carol/totp",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, _) = request(
		&app,
		"DELETE",
		"/api/v1/accounts/carol/totp",
		Some(tenant_key()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert!(
		world
			.store
			.dynamic("carol")
			.expect("carol")
			.totp_secret
			.is_none()
	);
	let (status, _) = request_with_body(
		&app,
		"PUT",
		"/api/v1/accounts/carol/display_name",
		Some(tenant_key()),
		Some(json!({"display_name": "CEO"})),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(
		world.store.dynamic("carol").expect("carol").display_name,
		None
	);
}

#[tokio::test]
async fn an_account_name_held_by_another_tenant_answers_like_an_unusable_one() {
	let world = world();
	let app = router(world.state.clone());
	let create = |name: &str| {
		Some(json!({
			"name": name,
			"addresses": ["new@a.test"],
			"password": "correct horse battery staple",
		}))
	};
	let (taken_status, taken) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(tenant_key()),
		create("carol"),
	)
	.await;
	let (bad_status, bad) = request_with_body(
		&app,
		"POST",
		"/api/v1/accounts",
		Some(tenant_key()),
		create("Not A Name!"),
	)
	.await;
	assert_eq!(taken_status, bad_status);
	assert_eq!(
		taken, bad,
		"the answer must not say the name exists elsewhere"
	);
}
