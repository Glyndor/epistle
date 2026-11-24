//! The edges the other files leave: requests that race for the last place of
//! a cap, a domain written as Unicode in a key against the same domain as
//! punycode in an alias, and two answers that must be the same answer.

use super::fixture::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

async fn post(world: &World, key: &str, body: Value) -> (StatusCode, Value) {
	call(world, "POST", "/api/v1/aliases", key, Some(body)).await
}

fn message(body: &Value) -> String {
	body["error"]["message"].as_str().unwrap_or("").to_string()
}

/// Several requests that start together for one place left under
/// `max_aliases_per_domain`: the lock of the state file lets one in, and the
/// others see the cap it filled. The file ends with the cap, never above it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_that_race_for_the_last_place_of_the_cap_get_one_created_and_the_rest_limit_reached()
 {
	const RACERS: usize = 6;
	let world = world_with("[limits]\nmax_aliases_per_domain = 2\n");
	let start = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
	let mut tasks = Vec::new();
	for n in 0..RACERS {
		let state = world.state.clone();
		let start = std::sync::Arc::clone(&start);
		tasks.push(tokio::spawn(async move {
			start.wait().await;
			crate::api::tests::base::request_with_body(
				&crate::api::router(state),
				"POST",
				"/api/v1/aliases",
				Some(TENANT_A),
				Some(json!({"alias": format!("racer{n}@a.example"), "members": ["abe@a.example"]})),
			)
			.await
		}));
	}
	let mut created = 0;
	for task in tasks {
		let (status, body) = task.await.expect("task");
		match status {
			StatusCode::CREATED => created += 1,
			StatusCode::CONFLICT => assert_eq!(body["error"]["code"], "limit_reached", "{body}"),
			other => panic!("unexpected {other}: {body}"),
		}
	}
	assert_eq!(created, 1, "one place was left");
	let on_disk = world.disk().expect("written");
	let in_a = on_disk
		.aliases
		.iter()
		.filter(|alias| alias.address.ends_with("@a.example"))
		.count();
	assert_eq!(in_a, 2, "the cap, exactly: {:?}", on_disk.aliases);
}

/// A key's domains are compared as they are written, in ASCII and lowercase.
/// A key made with `--domain bücher.example` does not reach the alias of the
/// hosted `xn--bcher-kva.example`: the answer is the one for a domain that is
/// not the key's, and nothing is written. The same domain as punycode works.
#[tokio::test]
async fn a_unicode_domain_in_a_key_does_not_reach_the_punycode_domain_of_an_alias() {
	let world = world();
	let body =
		json!({"alias":"shop@xn--bcher-kva.example","members":["ida@xn--bcher-kva.example"]});
	let (status, refused) = post(&world, IDN_UNICODE, body.clone()).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
	assert!(
		message(&refused).contains("not an address of the domains this key may use"),
		"{refused}"
	);
	assert!(world.disk().is_none(), "nothing was written");
	let (status, listed) = call(&world, "GET", "/api/v1/aliases", IDN_UNICODE, None).await;
	assert_eq!(status, StatusCode::OK);
	assert!(addresses(&listed).is_empty(), "{listed}");
	let (status, hidden) = call(
		&world,
		"GET",
		"/api/v1/aliases?domain=xn--bcher-kva.example",
		IDN_UNICODE,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND, "{hidden}");
	let (status, created) = post(&world, IDN_ASCII, body).await;
	assert_eq!(status, StatusCode::CREATED, "{created}");
	let (_, listed) = call(&world, "GET", "/api/v1/aliases", IDN_ASCII, None).await;
	assert_eq!(addresses(&listed), ["shop@xn--bcher-kva.example"]);
}

/// An alias address written in Unicode is stored as its punycode form, and
/// the key's domains are compared with that form: a key that lists the domain
/// as punycode may make it, and one that lists it as Unicode may not.
#[tokio::test]
async fn an_alias_address_in_unicode_is_stored_as_punycode_and_judged_as_punycode() {
	let body = json!({"alias":"shop@b\u{fc}cher.example","members":["ida@xn--bcher-kva.example"]});
	for key in [IDN_ASCII, ALL] {
		let world = world();
		let (status, created) = post(&world, key, body.clone()).await;
		assert_eq!(status, StatusCode::CREATED, "{created}");
		assert_eq!(created["alias"]["address"], "shop@xn--bcher-kva.example");
		assert_eq!(
			world.disk().unwrap().aliases.last().unwrap().address,
			"shop@xn--bcher-kva.example"
		);
	}
	let world = world();
	let (status, refused) = post(&world, IDN_UNICODE, body).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
	assert!(world.disk().is_none());
}

fn account(name: &str, addresses: &[&str]) -> String {
	let list: Vec<String> = addresses
		.iter()
		.map(|address| format!("{address:?}"))
		.collect();
	format!(
		"[[accounts]]\nname = {name:?}\naddresses = [{}]\npassword_hash = \"{HASH}\"\n\n",
		list.join(", ")
	)
}

/// Everything a client sees of the answer, for two worlds that differ only in
/// what the key must not be able to tell.
async fn seen(
	world: &World,
	method: &str,
	path: &str,
	key: &str,
	body: Option<Value>,
) -> (StatusCode, Vec<(String, String)>, Vec<u8>) {
	call_full(
		world,
		method,
		path,
		key,
		body.map(|body| body.to_string()).unwrap_or_default(),
	)
	.await
}

/// The same request against a world where the thing is not there and one
/// where it is but belongs to another tenant: the status, the headers and the
/// bytes of the body are the same.
#[tokio::test]
async fn what_does_not_exist_and_what_is_not_the_key_s_get_the_same_answer_byte_for_byte() {
	let creates = [
		(
			"an account of another tenant",
			account("zed", &["zed@b.example"]),
			json!({"alias":"x@a.example","members":["zed@b.example"]}),
		),
		(
			"an account with an address outside the key's domains",
			account("dave", &["dave@a.example", "dave@b.example"]),
			json!({"alias":"x@a.example","members":["dave@a.example"]}),
		),
	];
	for (what, extra, body) in creates {
		let (nothing, there) = (world(), world_with(&extra));
		let absent = seen(
			&nothing,
			"POST",
			"/api/v1/aliases",
			TENANT_A,
			Some(body.clone()),
		)
		.await;
		let theirs = seen(&there, "POST", "/api/v1/aliases", TENANT_A, Some(body)).await;
		assert_eq!(absent.0, StatusCode::BAD_REQUEST, "{what}");
		assert!(!absent.2.is_empty(), "{what}");
		assert_eq!(absent, theirs, "{what}");
		assert!(nothing.disk().is_none() && there.disk().is_none());
	}
	let split_alias = format!(
		"{}[[alias]]\naddress = \"split@a.example\"\nmembers = [\"dave@a.example\"]\n",
		account("dave", &["dave@a.example", "dave@b.example"])
	);
	let removals = [
		(
			"an alias with a member of another tenant",
			"[[alias]]\naddress = \"mixed@a.example\"\nmembers = [\"ann@a.example\", \"bob@b.example\"]\n",
			"mixed@a.example",
		),
		(
			"an alias with a sender of another tenant",
			"[[alias]]\naddress = \"sent@a.example\"\nmembers = [\"ann@a.example\"]\nsenders = [\"bob@b.example\"]\n",
			"sent@a.example",
		),
		(
			"an alias whose member's account has an address outside the key's domains",
			&split_alias,
			"split@a.example",
		),
		(
			"an alias in another tenant's domain",
			"[[alias]]\naddress = \"theirs@b.example\"\nmembers = [\"bob@b.example\"]\n",
			"theirs@b.example",
		),
	];
	for (what, extra, address) in removals {
		let (nothing, there) = (world(), world_with(extra));
		let path = format!("/api/v1/aliases/{address}");
		let absent = seen(&nothing, "DELETE", &path, TENANT_A, None).await;
		let theirs = seen(&there, "DELETE", &path, TENANT_A, None).await;
		assert_eq!(absent.0, StatusCode::NOT_FOUND, "{what}");
		assert!(!absent.2.is_empty(), "{what}");
		assert_eq!(absent, theirs, "{what}");
		assert!(there.disk().is_none(), "{what}: nothing was removed");
	}
}
