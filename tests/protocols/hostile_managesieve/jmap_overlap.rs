//! A stale JMAP writer must observe changes made by a live ManageSieve session.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use epistle::api::{ApiState, api_keys::sha256_hash};
use epistle::directory_store::AccountStore;
use epistle::storage::FsSpool;
use serde_json::{Value, json};
use tokio::time::timeout;
use tower::ServiceExt;

use super::harness::*;

const TOKEN: &str = "hostile-sieve-jmap-overlap";

fn api(server: &Harness) -> axum::Router {
	let domains = vec!["epistle.test".to_string()];
	let store = Arc::new(
		AccountStore::open(
			server.data.path(),
			domains.clone(),
			Default::default(),
			vec![epistle::config::Account {
				name: "tester".into(),
				addresses: vec!["tester@epistle.test".into()],
				password_hash: Some(epistle::smtp::auth::hash_password(&PASSWORD).expect("hash")),
				send: None,
				receive: None,
				display_name: None,
				catch_all: Vec::new(),
				quota_bytes: None,
				forward: Vec::new(),
				forward_keep_local: true,
				allowed_protocols: None,
			}],
		)
		.expect("shared account store"),
	);
	let state = ApiState::new(
		&sha256_hash(TOKEN),
		server.data.path().to_path_buf(),
		domains,
		store.clone(),
		FsSpool::open(server.data.path()).expect("spool"),
	)
	.with_directory(store.handle());
	epistle::api::router(state)
}

async fn jmap(api: &axum::Router, method: &str, arguments: Value) -> Value {
	timeout(IO_DEADLINE, async {
		let request = Request::builder()
			.method("POST")
			.uri("/jmap/api")
			.header("authorization", format!("Bearer {TOKEN}"))
			.header("content-type", "application/json")
			.extension(ConnectInfo(
				"127.0.0.1:1498"
					.parse::<std::net::SocketAddr>()
					.expect("peer"),
			))
			.body(Body::from(
				json!({"methodCalls": [[method, arguments, "overlap"]]}).to_string(),
			))
			.expect("JMAP request");
		let response = api.clone().oneshot(request).await.expect("JMAP response");
		assert_eq!(response.status(), StatusCode::OK);
		let bytes = to_bytes(response.into_body(), 65536)
			.await
			.expect("bounded body");
		let response: Value = serde_json::from_slice(&bytes).expect("JSON");
		response["methodResponses"][0].clone()
	})
	.await
	.expect("JMAP deadline")
}

async fn snapshot(api: &axum::Router) -> Value {
	let reply = jmap(api, "SieveScript/get", json!({"accountId": "tester"})).await;
	assert_eq!(reply[0], "SieveScript/get", "{reply}");
	reply[1].clone()
}

#[tokio::test]
async fn managesieve_activation_invalidates_jmap_state_and_protects_the_active_script() {
	let server = Harness::start(|s| s).await;
	let api = api(&server);
	let mut client = server.login("tester").await;
	put(&mut client, "canary", "keep;").await;
	expect(&mut client, "OK\r\n").await;
	let before = snapshot(&api).await;
	let scripts = before["list"].as_array().expect("scripts");
	assert_eq!(scripts.len(), 1);
	let id = scripts[0]["id"].as_str().expect("script id");
	assert_eq!(scripts[0]["isActive"], false);
	send(&mut client, b"SETACTIVE \"canary\"\r\n").await;
	expect(&mut client, "OK\r\n").await;
	let active = snapshot(&api).await;
	assert_ne!(before["state"], active["state"]);
	assert_eq!(active["list"][0]["id"], id);
	assert_eq!(active["list"][0]["isActive"], true);
	let stale = jmap(
		&api,
		"SieveScript/set",
		json!({
			"accountId": "tester", "ifInState": before["state"], "destroy": [id],
		}),
	)
	.await;
	assert_eq!(
		stale,
		json!(["error", {"type": "stateMismatch"}, "overlap"])
	);
	let refused = jmap(
		&api,
		"SieveScript/set",
		json!({
			"accountId": "tester", "ifInState": active["state"], "destroy": [id],
		}),
	)
	.await;
	assert_eq!(refused[0], "SieveScript/set", "{refused}");
	assert_eq!(refused[1]["notDestroyed"][id]["type"], "sieveIsActive");
	assert_eq!(snapshot(&api).await, active, "refusal changed shared state");
	assert_eq!(
		std::fs::read(
			server
				.data
				.path()
				.join("accounts/tester/sieve/canary.sieve")
		)
		.expect("protected script"),
		b"keep;"
	);
	// Switch off through ManageSieve, then delete through JMAP. The same
	// session must see the deletion, proving both protocols share the store.
	send(&mut client, b"SETACTIVE \"\"\r\n").await;
	expect(&mut client, "OK\r\n").await;
	let inactive = snapshot(&api).await;
	let deleted = jmap(
		&api,
		"SieveScript/set",
		json!({
			"accountId": "tester", "ifInState": inactive["state"], "destroy": [id],
		}),
	)
	.await;
	assert_eq!(deleted[0], "SieveScript/set", "{deleted}");
	assert_eq!(deleted[1]["destroyed"], json!([id]));
	send(&mut client, b"LISTSCRIPTS\r\n").await;
	expect(&mut client, "OK \"Listed.\"\r\n").await;
	assert!(
		snapshot(&api).await["list"]
			.as_array()
			.expect("scripts")
			.is_empty()
	);
	logout(&mut client).await;
	server.healthy().await;
}
