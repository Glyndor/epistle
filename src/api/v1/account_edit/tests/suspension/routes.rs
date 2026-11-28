//! What the two routes do, who they refuse, what they record, and that they
//! agree with the command.

use std::process::ExitCode;

use axum::http::StatusCode;
use serde_json::json;
use tracing::instrument::WithSubscriber;

use super::fixture::*;

const NOT_FOR_RESUMING: &str =
	"resuming an account is for a key that is not confined to an account or some domains.";

#[tokio::test]
async fn an_account_is_suspended_and_resumed_and_a_repeat_says_nothing_changed() {
	let world = world();
	let (status, body) = post(&world, token(), "alice", "disable").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body,
		json!({"result": "saved", "action": "disable", "account": "alice", "disabled": true})
	);
	assert!(disabled(&world, "alice"));
	let (status, body) = post(&world, WRITER, "alice", "disable").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["result"], "unchanged");
	let (status, body) = post(&world, WRITER, "alice", "enable").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body,
		json!({"result": "saved", "action": "enable", "account": "alice", "disabled": false})
	);
	assert!(!disabled(&world, "alice"));
	let (_, body) = post(&world, token(), "alice", "enable").await;
	assert_eq!(body["result"], "unchanged");
}

#[tokio::test]
async fn a_suspended_account_does_not_authenticate() {
	let world = world();
	let login = json!({"name": "alice", "password": PASSWORD});
	let verify = "/api/v1/auth/verify";
	let (status, body) = call(&world.state, "POST", verify, token(), Some(login.clone())).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["valid"], true, "{body}");
	post(&world, token(), "alice", "disable").await;
	let (_, body) = call(&world.state, "POST", verify, token(), Some(login)).await;
	assert_eq!(body["valid"], false, "{body}");
}

/// A confined key suspends what lives in its domains and nothing else, and an
/// account outside answers like one that does not exist.
#[tokio::test]
async fn a_confined_key_suspends_the_accounts_of_its_own_domains_only() {
	let world = world();
	let mut answers = Vec::new();
	for name in ["bob", "split", "nobody"] {
		let (status, body) = post(&world, OF_A, name, "disable").await;
		assert_eq!(status, StatusCode::NOT_FOUND, "{name}: {body}");
		assert_eq!(body["error"]["message"], "no such account", "{body}");
		answers.push(body);
	}
	assert!(
		answers.windows(2).all(|pair| pair[0] == pair[1]),
		"{answers:?}"
	);
	assert!(!disabled(&world, "bob") && !disabled(&world, "split"));
	let (status, body) = post(&world, OF_A, "alice", "disable").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(disabled(&world, "alice"));
}

/// An account the operator suspended is not for a tenant's key to bring back,
/// and the answer does not depend on the account.
#[tokio::test]
async fn a_confined_key_does_not_resume_an_account() {
	let world = world();
	post(&world, token(), "alice", "disable").await;
	let mut answers = Vec::new();
	for name in ["alice", "bob", "split", "nobody"] {
		let (status, body) = post(&world, OF_A, name, "enable").await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{name}: {body}");
		assert_eq!(body["error"]["message"], NOT_FOR_RESUMING, "{body}");
		answers.push(body);
	}
	assert!(
		answers.windows(2).all(|pair| pair[0] == pair[1]),
		"{answers:?}"
	);
	assert!(disabled(&world, "alice"), "it stays suspended");
}

#[tokio::test]
async fn a_key_without_the_scope_or_bound_to_an_account_changes_nothing() {
	let world = world();
	post(&world, token(), "bob", "disable").await;
	for (name, verb) in [("alice", "disable"), ("bob", "enable")] {
		for bearer in [READER, OF_ALICE] {
			let (status, body) = post(&world, bearer, name, verb).await;
			assert_eq!(status, StatusCode::FORBIDDEN, "{verb}: {body}");
			// A key bound to an account never holds a management scope, so
			// both are refused for the scope.
			assert_eq!(
				body["error"]["message"], "This API key does not have the scope this route needs.",
				"{verb}"
			);
		}
		let (status, body) = post(&world, "not-a-key", name, verb).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED, "{verb}: {body}");
	}
	assert!(!disabled(&world, "alice"));
	assert!(disabled(&world, "bob"));
}

#[tokio::test]
async fn only_an_account_made_through_the_api_is_suspended() {
	let world = world();
	for name in ["carol", "nobody"] {
		for verb in ["disable", "enable"] {
			let (status, body) = post(&world, token(), name, verb).await;
			assert_eq!(status, StatusCode::NOT_FOUND, "{name} {verb}: {body}");
			assert_eq!(body["error"]["message"], "no such dynamic account");
		}
	}
}

#[tokio::test]
async fn only_a_change_is_audited() {
	let world = world();
	let capture = Capture::default();
	async {
		post(&world, READER, "alice", "disable").await;
		post(&world, OF_B, "alice", "disable").await;
		post(&world, OF_A, "alice", "enable").await;
		post(&world, token(), "nobody", "disable").await;
		post(&world, OF_A, "alice", "disable").await;
		post(&world, OF_A, "alice", "disable").await;
		post(&world, WRITER, "alice", "enable").await;
		post(&world, WRITER, "alice", "enable").await;
		post(&world, token(), "alice", "disable").await;
	}
	.with_subscriber(capture.dispatch())
	.await;
	assert_eq!(
		capture.kinds(),
		["account.disabled", "account.enabled", "account.disabled"]
	);
	let events = capture.events();
	let who: Vec<&str> = events.iter().map(|event| event["key"].as_str()).collect();
	assert_eq!(who, ["of-a", "writer", "configured-token"]);
	assert_eq!(events[0]["client_ip"], "127.0.0.1");
	assert!(!format!("{events:?}").contains("alice"));
}

/// Many requests to suspend one account: it is suspended once, and one line
/// says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_suspensions_of_one_account_are_one_change() {
	let world = world();
	let capture = Capture::default();
	let dispatch = capture.dispatch();
	let mut tasks = tokio::task::JoinSet::new();
	for _ in 0..8 {
		let state = world.state.clone();
		tasks.spawn(
			async move {
				let path = "/api/v1/accounts/alice/disable";
				call(&state, "POST", path, WRITER, None).await.1["result"]
					.as_str()
					.map(str::to_owned)
			}
			.with_subscriber(dispatch.clone()),
		);
	}
	let mut saved = 0;
	while let Some(result) = tasks.join_next().await {
		if result.expect("task").as_deref() == Some("saved") {
			saved += 1;
		}
	}
	assert_eq!(saved, 1);
	assert_eq!(capture.kinds(), ["account.disabled"]);
}

#[tokio::test]
async fn the_command_and_the_route_agree_on_every_step() {
	use crate::cli::account::actions::{disable_with_store, enable_with_store};
	let by_command = world();
	let by_route = world();
	for (verb, name) in [
		("disable", "alice"),
		("disable", "alice"),
		("enable", "alice"),
		("enable", "alice"),
		("disable", "bob"),
		("enable", "nobody"),
		("disable", "carol"),
	] {
		let mut out = Vec::new();
		let code = match verb {
			"disable" => disable_with_store(&by_command.store, name, &mut out, true),
			_ => enable_with_store(&by_command.store, name, &mut out, true),
		};
		let (status, body) = post(&by_route, token(), name, verb).await;
		assert_eq!(
			code == ExitCode::SUCCESS,
			status == StatusCode::OK,
			"{verb} {name}"
		);
		if status == StatusCode::OK {
			let mut printed: serde_json::Value = serde_json::from_slice(&out).expect("json");
			// The command waits for the running server to load the change and
			// says how that went; the route is the running server.
			printed.as_object_mut().expect("object").remove("reload");
			assert_eq!(printed, body, "{verb} {name}");
		}
		for account in ["alice", "bob"] {
			assert_eq!(
				disabled(&by_command, account),
				disabled(&by_route, account),
				"{verb} {name}"
			);
		}
	}
}
