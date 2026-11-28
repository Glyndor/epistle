//! The suspension and the key are asked about again in the write, under the
//! account store's lock: what the request found when it arrived is not enough.

use std::collections::HashMap;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::Value;
use tracing::instrument::WithSubscriber;

use crate::api::api_keys::{self, ApiKey, ApiKeyStore, Scope};
use crate::api::audit::tests::base::{audit_events, run_with_capture};
use crate::directory_store::AccountStore;
use crate::storage::lock::{FileLock, reached};

use super::base::app;
use super::suspended::{MAIN, OTHER, Request, World, leaving, refusal_differences, undoing, world};
use super::tenants::{call, tenant_key, unconfined_key};

/// A second handle on the same files, the way a command run beside the server
/// writes: the file changes and the server's copy does not.
fn beside_the_server(world: &World) -> AccountStore {
	AccountStore::open(
		world.dir.path(),
		vec!["a.test".to_string(), "b.test".to_string()],
		HashMap::new(),
		Vec::new(),
	)
	.expect("second handle")
}

/// Suspend `alice` beside the server.
fn suspend_beside_the_server(world: &World) {
	let other = beside_the_server(world);
	other.set_disabled("alice", true).expect("suspend");
	assert!(
		!world.store.is_disabled("alice"),
		"the server's copy is old"
	);
}

/// Send `request` with `key`: the status, the body and the audit events. With
/// `change`, the write is held at the account file's lock while it runs.
/// Nothing here waits for a time to pass; the deadlines only turn a hang into
/// a failure.
fn send_captured(
	world: &World,
	key: &'static str,
	request: &Request,
	change: Option<&dyn Fn()>,
) -> (StatusCode, Value, Vec<String>) {
	let app = app(world.state.clone());
	let (method, body) = (request.method, request.body.clone());
	let mut answer = None;
	let events = run_with_capture(async {
		let sent =
			async move { call(&app, method, "/scim/v2/Users/alice", key, body.as_ref()).await };
		let Some(change) = change else {
			answer = Some(sent.await);
			return;
		};
		let deadline = Duration::from_secs(60);
		let lock = crate::storage::locked::lock_path(world.store.store_path());
		let held = FileLock::acquire(&lock).expect("hold the lock");
		let asked = reached::watch(&lock);
		let task = tokio::spawn(sent.with_current_subscriber());
		tokio::time::timeout(deadline, asked.acquire())
			.await
			.expect("the write never asked for the lock")
			.expect("open")
			.forget();
		change();
		drop(held);
		let ended = tokio::time::timeout(deadline, task).await;
		answer = Some(ended.expect("the request never ended").expect("task"));
	});
	let (status, body) = answer.expect("an answer");
	let kinds = audit_events(&events)
		.iter()
		.map(|event| event.fields.get("event").cloned().unwrap_or_default())
		.collect();
	(status, body, kinds)
}

/// The addresses a suspended account is compared by are the ones the write
/// finds, not the ones the server held when the request arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_addresses_the_write_finds_are_the_ones_kept() {
	let named = naming_the_old_copy();
	let mut wrong = Vec::new();
	for (key, allowed) in [(tenant_key(), false), (unconfined_key(), true)] {
		let world = world(true);
		beside_the_server(&world)
			.add_address("alice", "alice.third@a.test")
			.expect("third address");
		let held = world.store.dynamic("alice").expect("alice").addresses;
		assert_eq!(held, [MAIN, OTHER], "the server's copy is old");
		let before = world.file();
		let answer = send_captured(&world, key, &named, None);
		if allowed {
			if answer.0 != StatusCode::OK || world.file() == before {
				wrong.push(format!("unconfined: {} {}", answer.0, answer.1));
			}
		} else {
			wrong.extend(refusal_differences(
				&world,
				&named,
				&before,
				answer,
				StatusCode::NOT_FOUND,
				"no such user",
			));
		}
	}
	assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The `PUT` that names the addresses the server's old copy holds.
fn naming_the_old_copy() -> Request {
	leaving()
		.into_iter()
		.find(|request| request.what == "PUT as it is")
		.expect("the request")
}

/// Replace the unconfined key with one confined to `domains`, and load the
/// file as the watcher does.
fn confine_the_key(world: &World, domains: &[&str]) {
	let data_dir = world.dir.path();
	let mut keys = ApiKeyStore::open(data_dir).expect("key store");
	keys.remove("scim-all").expect("remove key");
	keys.add(ApiKey {
		grants: Vec::new(),
		label: "scim-all".to_string(),
		hash: api_keys::sha256_hash(unconfined_key()),
		expires_at: None,
		ip_cidr: None,
		scopes: vec![Scope::Scim.as_str().to_string()],
		domains: domains.iter().map(|domain| (*domain).to_string()).collect(),
		account: None,
		auto_submitted: false,
	})
	.expect("add key");
	let text = std::fs::read_to_string(data_dir.join("api_keys.toml")).expect("key file");
	world.state.api_keys().reload_from(&text).expect("reload");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_suspension_the_write_finds_stops_a_confined_key() {
	// Every request is tried before judging, so a failure names all that differ.
	let mut wrong = Vec::new();
	for (request, _) in undoing() {
		let world = world(false);
		suspend_beside_the_server(&world);
		let before = world.file();
		let answer = send_captured(&world, tenant_key(), &request, None);
		wrong.extend(refusal_differences(
			&world,
			&request,
			&before,
			answer,
			StatusCode::NOT_FOUND,
			"no such user",
		));
	}
	assert!(wrong.is_empty(), "{wrong:#?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_suspension_the_write_finds_leaves_the_other_changes() {
	let mut wrong = Vec::new();
	for request in leaving() {
		// A request that asks for `active` false writes it either way; what
		// matters is that none of these is refused.
		let world = world(false);
		suspend_beside_the_server(&world);
		let (status, body, _) = send_captured(&world, tenant_key(), &request, None);
		let kept = world.store.dynamic("alice").expect("alice");
		if status != StatusCode::OK || !kept.disabled || kept.addresses != [MAIN, OTHER] {
			wrong.push(format!("{}: {status} {body}", request.what));
		}
	}
	for (request, _) in undoing() {
		let world = world(false);
		suspend_beside_the_server(&world);
		let before = world.file();
		let (status, body, _) = send_captured(&world, unconfined_key(), &request, None);
		if !status.is_success() || world.file() == before {
			wrong.push(format!("unconfined, {}: {status} {body}", request.what));
		}
	}
	assert!(wrong.is_empty(), "{wrong:#?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_confined_while_the_write_waits_does_not_undo_a_suspension() {
	let mut wrong = Vec::new();
	for (request, _) in undoing() {
		let world = world(true);
		let before = world.file();
		// Still inside the account's own domain: only the suspension is closed
		// to it.
		let confine = || confine_the_key(&world, &["a.test"]);
		let answer = send_captured(&world, unconfined_key(), &request, Some(&confine));
		wrong.extend(refusal_differences(
			&world,
			&request,
			&before,
			answer,
			StatusCode::NOT_FOUND,
			"no such user",
		));
	}
	assert!(wrong.is_empty(), "{wrong:#?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_still_unconfined_after_the_wait_undoes_a_suspension() {
	let mut wrong = Vec::new();
	for (request, _) in undoing() {
		let world = world(true);
		let before = world.file();
		let reload = || confine_the_key(&world, &[]);
		let (status, body, _) = send_captured(&world, unconfined_key(), &request, Some(&reload));
		if !status.is_success() || world.file() == before {
			wrong.push(format!("{}: {status} {body}", request.what));
		}
	}
	assert!(wrong.is_empty(), "{wrong:#?}");
}
