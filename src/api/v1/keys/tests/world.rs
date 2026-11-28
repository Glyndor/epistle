//! What the file is asked again under its lock: the world is read there too,
//! so a key whose reach the world no longer holds is not written.

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::*;

/// An account of the directory, with the address it has now.
fn account(name: &str, address: &str) -> crate::directory_store::DynamicAccount {
	crate::directory_store::DynamicAccount {
		name: name.to_string(),
		addresses: vec![address.to_string()],
		password_hash: crate::smtp::auth::tests::base::hash("a password"),
		..crate::directory_store::DynamicAccount::default()
	}
}

/// Wait until a thread has got as far as asking for the lock, which is the
/// signal that the request has already been checked against the world as it
/// was and is waiting for the file.
async fn wait_for(counter: &tokio::sync::Semaphore, what: &str) {
	tokio::time::timeout(std::time::Duration::from_secs(60), counter.acquire())
		.await
		.unwrap_or_else(|_| panic!("never happened: {what}"))
		.expect("open")
		.forget();
}

/// The reach of the new key is decided while the accounts are held, from the
/// file: an account that left the domains of the key that asks between the
/// request and the write is not bound, and nothing is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_account_that_left_the_callers_domains_is_not_bound_and_nothing_is_written() {
	let world = world();
	world
		.state
		.store()
		.add(account("carol", "carol@a.example"))
		.expect("add carol");
	// The write waits for the lock the test holds: the request has already
	// been checked against the world as it was.
	let accounts = world.state.data_dir().join("accounts.toml");
	let lock = crate::storage::locked::lock_path(&accounts);
	let held = crate::storage::lock::FileLock::acquire(&lock).expect("lock");
	let reached = crate::storage::lock::reached::watch(&lock);
	let state = world.state.clone();
	let request = tokio::spawn(async move {
		call(
			&state,
			"POST",
			"/api/v1/keys",
			MAKER_A,
			Some(json!({"label": "child", "scopes": ["read"], "account": "carol"})),
		)
		.await
	});
	wait_for(&reached, "the write asks for the lock").await;
	// Whoever holds the lock moves the account out of the domains of the key
	// that asks.
	let text = std::fs::read_to_string(&accounts).expect("read accounts");
	assert!(text.contains("carol@a.example"), "{text}");
	let moved = text.replace("carol@a.example", "carol@b.example");
	std::fs::write(&accounts, moved).expect("move carol");
	drop(held);
	let (status, _, body) = request.await.expect("answered");
	assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
	assert!(
		!labels(&world).contains(&"child".to_string()),
		"the key was written"
	);
}
