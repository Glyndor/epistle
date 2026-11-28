//! The key and the account change between the checks of a request and its
//! write, while the write waits for the account file's lock. The write decides
//! from what it reads there: it changes nothing and writes no audit line when
//! it may not. Nothing here waits for a time to pass; the deadlines only turn
//! a hang into a failure.

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};
use tracing::instrument::WithSubscriber;

use super::fixture::*;
use crate::api::api_keys::ApiKey;
use crate::storage::lock::{FileLock, reached};

const DEADLINE: Duration = Duration::from_secs(60);
const ADD: &str = "/api/v1/accounts/alice/addresses";
const REMOVE: &str = "/api/v1/accounts/alice/addresses/alice2@a.test";
const BEFORE: [&str; 2] = ["alice2@a.test", "alice@a.test"];

/// One request: its method, its path and its body.
#[derive(Clone)]
struct Sent {
	method: &'static str,
	path: String,
	body: Option<Value>,
}

fn adding(address: &str) -> Sent {
	Sent {
		method: "POST",
		path: ADD.to_string(),
		body: Some(json!({ "address": address })),
	}
}

fn removing() -> Sent {
	Sent {
		method: "DELETE",
		path: REMOVE.to_string(),
		body: None,
	}
}

fn both() -> [Sent; 2] {
	[adding("late@a.test"), removing()]
}

/// Send `sent` for `bearer`, and run `change` once the request has passed
/// every check made before the write and is waiting for the account file's
/// lock, which this holds until `change` is done.
async fn while_the_write_waits(
	world: &World,
	sent: Sent,
	bearer: &'static str,
	change: impl FnOnce(),
) -> (StatusCode, Value, Capture) {
	let capture = Capture::default();
	let lock = crate::storage::locked::lock_path(world.store.store_path());
	let held = FileLock::acquire(&lock).expect("lock");
	let asked = reached::watch(&lock);
	let state = world.state.clone();
	let request = tokio::spawn(
		async move { call(&state, sent.method, &sent.path, bearer, sent.body).await }
			.with_subscriber(capture.dispatch()),
	);
	tokio::time::timeout(DEADLINE, asked.acquire())
		.await
		.expect("the write never asked for the lock")
		.expect("open")
		.forget();
	change();
	drop(held);
	let (status, body) = tokio::time::timeout(DEADLINE, request)
		.await
		.expect("the request never ended")
		.expect("request task");
	(status, body, capture)
}

/// Replace the key labelled `label` with `now`, or drop it when there is no
/// replacement, and load the file as the watcher does.
fn replace_key(world: &World, label: &str, now: Option<ApiKey>) {
	let data_dir = world.dir.path();
	let mut keys = crate::api::ApiKeyStore::open(data_dir).expect("key store");
	keys.remove(label).expect("remove key");
	if let Some(now) = now {
		keys.add(now).expect("add key");
	}
	let text = std::fs::read_to_string(data_dir.join("api_keys.toml")).expect("key file");
	world.state.api_keys().reload_from(&text).expect("reload");
}

/// Change the row of `name` in the account file only, as another process
/// would: what the server holds in memory stays as it was.
fn edit_on_disk(world: &World, name: &str, field: &str, value: toml::Value) {
	let path = world.store.store_path();
	let text = std::fs::read_to_string(path).expect("account file");
	let mut file: toml::Table = toml::from_str(&text).expect("account toml");
	let row = file["accounts"]
		.as_array_mut()
		.expect("accounts")
		.iter_mut()
		.find(|row| row["name"].as_str() == Some(name))
		.expect("row");
	row.as_table_mut()
		.expect("table")
		.insert(field.to_string(), value);
	std::fs::write(path, toml::to_string(&file).expect("serialize")).expect("write");
}

fn holds(world: &World, name: &str, addresses: &[&str]) {
	let value = addresses
		.iter()
		.map(|address| toml::Value::from(*address))
		.collect::<Vec<_>>();
	edit_on_disk(world, name, "addresses", toml::Value::Array(value));
}

/// The addresses of `name` as the file has them, sorted.
fn on_disk(world: &World, name: &str) -> Vec<String> {
	let rows = crate::directory_store::dynamic_addresses_on_disk(world.dir.path()).expect("file");
	let mut held = rows
		.into_iter()
		.find(|(account, _)| account == name)
		.expect("account")
		.1;
	held.sort();
	held
}

fn of_a(domains: &[&str]) -> ApiKey {
	key("of-a", OF_A, &["manage:write"], domains, None)
}

/// Every way the key `of-a` stops being one that may change `alice`.
fn withdrawn() -> Vec<(&'static str, Option<ApiKey>)> {
	let mut expired = of_a(&["a.test"]);
	expired.expires_at = Some(1);
	let mut elsewhere = of_a(&["a.test"]);
	elsewhere.ip_cidr = Some("10.0.0.0/8".to_string());
	let mut replaced = of_a(&["a.test"]);
	replaced.hash = crate::api::api_keys::sha256_hash("another secret");
	let mut bound = of_a(&[]);
	bound.scopes = vec!["mail:write".to_string()];
	bound.account = Some("alice".to_string());
	vec![
		("revoked", None),
		(
			"no scope to write",
			Some(key("of-a", OF_A, &["manage:read"], &["a.test"], None)),
		),
		("moved to another tenant", Some(of_a(&["b.test"]))),
		("expired", Some(expired)),
		("limited to another network", Some(elsewhere)),
		("replaced", Some(replaced)),
		("bound to the account", Some(bound)),
	]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_changed_while_the_write_waits_changes_nothing() {
	// Every case is tried before judging, so a failure names all that went on.
	let mut went_on = Vec::new();
	for sent in both() {
		for (what, now) in withdrawn() {
			let world = world();
			let (status, body, capture) = while_the_write_waits(&world, sent.clone(), OF_A, || {
				replace_key(&world, "of-a", now);
			})
			.await;
			if status != StatusCode::NOT_FOUND
				|| !body.to_string().contains("no such dynamic account")
				|| on_disk(&world, "alice") != BEFORE
				|| !capture.events().is_empty()
			{
				went_on.push(format!("{} {what}: {status} {body}", sent.method));
			}
		}
	}
	assert!(went_on.is_empty(), "writes that went on: {went_on:?}");
}

/// The same requests with a key that still may write: one change, one line.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_that_may_still_write_makes_the_change_after_waiting() {
	let mut network = of_a(&["a.test"]);
	network.ip_cidr = Some("127.0.0.0/8".to_string());
	let mut expiring = of_a(&["a.test"]);
	expiring.expires_at = Some(u64::MAX >> 1);
	for sent in both() {
		for now in [of_a(&["a.test"]), network.clone(), expiring.clone()] {
			let world = world();
			let (status, body, capture) = while_the_write_waits(&world, sent.clone(), OF_A, || {
				replace_key(&world, "of-a", Some(now));
			})
			.await;
			assert!(status.is_success(), "{}: {status} {body}", sent.method);
			assert_ne!(on_disk(&world, "alice"), BEFORE);
			let events = capture.events();
			assert_eq!(events.len(), 1, "{events:?}");
			assert_eq!(events[0]["key"], "of-a");
			assert_eq!(events[0]["client_ip"], "127.0.0.1");
		}
		// The configured token asks no key file.
		let world = world();
		let (status, body, capture) =
			while_the_write_waits(&world, sent.clone(), token(), || {}).await;
		assert!(status.is_success(), "{}: {status} {body}", sent.method);
		assert_eq!(capture.events().len(), 1);
	}
}

/// A key narrowed away from the domain of the new address, which still
/// reaches the account, gives it no such address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_narrowed_away_from_the_new_domain_adds_nothing() {
	for (now, expected) in [
		(&["a.test"][..], StatusCode::NOT_FOUND),
		(&["a.test", "c.test"][..], StatusCode::CREATED),
	] {
		let world = world();
		replace_key(&world, "of-a", Some(of_a(&["a.test", "c.test"])));
		let (status, body, capture) =
			while_the_write_waits(&world, adding("new@c.test"), OF_A, || {
				replace_key(&world, "of-a", Some(of_a(now)));
			})
			.await;
		assert_eq!(status, expected, "{now:?}: {body}");
		let written = expected == StatusCode::CREATED;
		assert_eq!(on_disk(&world, "alice").len(), 2 + usize::from(written));
		assert_eq!(capture.events().len(), usize::from(written));
	}
}

/// An account that gained an address in another tenant's domain while the write
/// waited is not a confined key's to change. An unconfined key still does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_that_left_the_keys_domains_is_not_changed() {
	let moved = ["alice2@a.test", "alice@a.test", "alice@b.test"];
	for sent in both() {
		let world = world();
		let (status, body, capture) = while_the_write_waits(&world, sent.clone(), OF_A, || {
			holds(&world, "alice", &moved);
		})
		.await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{}: {body}", sent.method);
		assert_eq!(on_disk(&world, "alice"), moved);
		assert!(capture.events().is_empty());
	}
	for sent in both() {
		let world = world();
		let (status, body, _) = while_the_write_waits(&world, sent, WRITER, || {
			holds(&world, "alice", &moved);
		})
		.await;
		assert!(status.is_success(), "{status} {body}");
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_suspended_while_the_write_waits_keeps_its_addresses() {
	for (sent, done, after) in [
		(removing(), StatusCode::OK, 1),
		(adding("more@a.test"), StatusCode::CREATED, 3),
	] {
		for (bearer, refused) in [(OF_A, true), (WRITER, false), (token(), false)] {
			let world = world();
			let (status, body, capture) =
				while_the_write_waits(&world, sent.clone(), bearer, || {
					edit_on_disk(&world, "alice", "disabled", toml::Value::Boolean(true));
				})
				.await;
			let expected = if refused { StatusCode::NOT_FOUND } else { done };
			assert_eq!(status, expected, "{body}");
			assert_eq!(
				on_disk(&world, "alice").len(),
				if refused { 2 } else { after }
			);
			assert_eq!(capture.events().len(), usize::from(!refused));
		}
	}
}

/// What the file says when the write reads it decides the refusal, and a
/// refused write leaves no line.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_write_decides_from_the_file_it_reads_under_the_lock() {
	type Change = fn(&World);
	let cases: [(&str, Sent, Change, StatusCode, &str); 6] = [
		(
			"the address was taken",
			adding("late@a.test"),
			|world| holds(world, "bob", &["bob@b.test", "late@a.test"]),
			StatusCode::CONFLICT,
			"already taken",
		),
		(
			"the account filled up",
			adding("late@a.test"),
			|world| {
				let full = ["alice@a.test", "alice2@a.test", "3@a.test", "4@a.test"];
				holds(world, "alice", &full);
			},
			StatusCode::CONFLICT,
			"limit_reached",
		),
		(
			"the tenant's last place went",
			adding("late@c.test"),
			|world| holds(world, "bob", &["bob@b.test", "bob@c.test"]),
			StatusCode::CONFLICT,
			"max_accounts",
		),
		(
			"the address was already taken off",
			removing(),
			|world| holds(world, "alice", &["alice@a.test", "other@a.test"]),
			StatusCode::BAD_REQUEST,
			"not assigned",
		),
		(
			"the address became the last one",
			removing(),
			|world| holds(world, "alice", &["alice2@a.test"]),
			StatusCode::BAD_REQUEST,
			"last address",
		),
		(
			"the account went away",
			removing(),
			|world| edit_on_disk(world, "alice", "name", toml::Value::from("renamed")),
			StatusCode::NOT_FOUND,
			"no such dynamic account",
		),
	];
	for (what, sent, change, expected, says) in cases {
		let world = world();
		let (status, body, capture) =
			while_the_write_waits(&world, sent, WRITER, || change(&world)).await;
		assert_eq!(status, expected, "{what}: {body}");
		assert!(body.to_string().contains(says), "{what}: {body}");
		assert!(capture.events().is_empty(), "{what}");
	}
}

/// The key is asked before anything is said about the address: one that lost
/// its reach learns neither that an address is taken nor that a domain is not
/// hosted here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_that_lost_its_reach_learns_nothing_of_the_address() {
	let wide = ["a.test", "nowhere.example"];
	for (address, taken, alive) in [
		("late@a.test", true, StatusCode::CONFLICT),
		("x@nowhere.example", false, StatusCode::BAD_REQUEST),
	] {
		for revoked in [true, false] {
			let world = world();
			replace_key(&world, "of-a", Some(of_a(&wide)));
			let (status, body, _) = while_the_write_waits(&world, adding(address), OF_A, || {
				if taken {
					holds(&world, "bob", &["bob@b.test", address]);
				}
				if revoked {
					replace_key(&world, "of-a", None);
				}
			})
			.await;
			let expected = if revoked {
				StatusCode::NOT_FOUND
			} else {
				alive
			};
			assert_eq!(status, expected, "{address}: {body}");
		}
	}
}

/// The write and its line are made together even when the client goes away
/// while the write waits for the lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_goes_away_leaves_the_change_written_and_recorded() {
	for sent in both() {
		let world = world();
		let capture = Capture::default();
		let lock = crate::storage::locked::lock_path(world.store.store_path());
		let held = FileLock::acquire(&lock).expect("lock");
		let asked = reached::watch(&lock);
		let state = world.state.clone();
		let method = sent.method;
		let request = tokio::spawn(
			async move { call(&state, sent.method, &sent.path, WRITER, sent.body).await }
				.with_subscriber(capture.dispatch()),
		);
		tokio::time::timeout(DEADLINE, asked.acquire())
			.await
			.expect("the write never asked for the lock")
			.expect("open")
			.forget();
		request.abort();
		assert!(request.await.expect_err("aborted").is_cancelled());
		drop(held);
		tokio::time::timeout(DEADLINE, async {
			while capture.events().is_empty() {
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		})
		.await
		.expect("the change was never recorded");
		assert_eq!(capture.events().len(), 1, "{method}");
		assert_ne!(on_disk(&world, "alice"), BEFORE, "{method}");
	}
}
