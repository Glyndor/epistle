//! `epistle ban` against `/api/v1/bans` on the same store: the route says
//! what the command says.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::super::*;
use crate::antispam::bans::operator::tests::fake::FakeAdmin;

const TOKEN: &str = "ban-parity-token";

fn router(store: Arc<FakeAdmin>) -> (axum::Router, tempfile::TempDir) {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().canonicalize().expect("canonical");
	let accounts = Arc::new(
		crate::directory_store::AccountStore::open(
			&data_dir,
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	let state = crate::api::ApiState::new(
		&crate::api::api_keys::sha256_hash(TOKEN),
		data_dir.clone(),
		vec!["example.org".to_string()],
		accounts.clone(),
		crate::storage::FsSpool::open(&data_dir).expect("spool"),
	)
	.with_directory(accounts.handle())
	.with_ban_admin(store);
	(crate::api::router(state), dir)
}

async fn route(
	app: &axum::Router,
	method: &str,
	path: &str,
	body: Option<Value>,
) -> (StatusCode, Value) {
	let mut request = axum::http::Request::builder()
		.method(method)
		.uri(path)
		.header("authorization", format!("Bearer {TOKEN}"));
	let body = match body {
		Some(json) => {
			request = request.header("content-type", "application/json");
			axum::body::Body::from(json.to_string())
		}
		None => axum::body::Body::empty(),
	};
	let response = app
		.clone()
		.oneshot(request.body(body).expect("request"))
		.await
		.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(
		status,
		serde_json::from_slice(&bytes).unwrap_or(Value::Null),
	)
}

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs()
}

async fn command(store: &FakeAdmin, action: BanCli) -> Value {
	let (mut out, mut err) = (Vec::new(), Vec::new());
	let code = execute(store, action, true, now(), &mut out, &mut err)
		.await
		.expect("the store answers");
	assert_eq!(code, ExitCode::SUCCESS, "{}", String::from_utf8_lossy(&err));
	serde_json::from_slice(&out).expect("the command prints JSON")
}

#[tokio::test]
async fn the_listing_holds_the_rows_the_command_prints() {
	let rows = [
		("ip:203.0.113.9", "manual ban", u64::MAX / 2),
		("cidr:198.51.100.0/24", "manual ban", u64::MAX / 2),
		(
			"account:alice@example.org",
			"too many failures",
			u64::MAX / 2,
		),
	];
	let store = Arc::new(FakeAdmin::with(&rows, &[]));
	let (app, _dir) = router(store.clone());
	let printed = command(&store, BanCli::List { json: true }).await;
	let (status, body) = route(&app, "GET", "/api/v1/bans", None).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["bans"], printed);
	let (_, allow) = route(&app, "GET", "/api/v1/bans/allow", None).await;
	let printed = command(
		&store,
		BanCli::Allow {
			action: AllowCli::List { json: true },
		},
	)
	.await;
	assert_eq!(allow["allow"], printed);
}

#[tokio::test]
async fn a_ban_made_by_the_route_is_the_ban_the_command_makes() {
	let by_route = Arc::new(FakeAdmin::default());
	let by_command = Arc::new(FakeAdmin::default());
	let (app, _dir) = router(by_route.clone());
	for (spec, duration, text) in [
		("203.0.113.9", None, None),
		("203.0.113.0/24", Some(5_400), Some("90m")),
		("2001:db8::1", Some(60), Some("60s")),
	] {
		let (status, body) = route(
			&app,
			"POST",
			"/api/v1/bans",
			Some(match text {
				Some(text) => json!({"target": spec, "for": text}),
				None => json!({"target": spec}),
			}),
		)
		.await;
		assert_eq!(status, StatusCode::CREATED, "{spec}: {body}");
		let printed = command(
			&by_command,
			BanCli::Add {
				target: BanTarget::parse(spec).expect("target"),
				duration,
			},
		)
		.await;
		assert_eq!(body["target"], printed["target"], "{spec}");
		let skew = body["until"]
			.as_u64()
			.expect("until")
			.abs_diff(printed["until"].as_u64().expect("until"));
		assert!(skew <= 5, "{spec}: the end differs by {skew} seconds");
	}
	assert_eq!(by_route.ban_subjects(), by_command.ban_subjects());
}

#[tokio::test]
async fn lifting_by_the_route_clears_what_the_command_clears() {
	let build = || {
		Arc::new(FakeAdmin::with(
			&[
				("pair:alice@example.org|203.0.113.9", "x", u64::MAX / 2),
				("ip:203.0.113.9", "x", u64::MAX / 2),
			],
			&[
				("pair:alice@example.org|203.0.113.9", 2),
				("ip:203.0.113.9", 3),
			],
		))
	};
	let (by_route, by_command) = (build(), build());
	let (app, _dir) = router(by_route.clone());
	for (subject, path) in [
		(
			"pair:alice@example.org|203.0.113.9",
			"pair%3Aalice%40example.org%7C203.0.113.9",
		),
		("203.0.113.9", "203.0.113.9"),
	] {
		let (status, body) = route(&app, "DELETE", &format!("/api/v1/bans/{path}"), None).await;
		assert_eq!(status, StatusCode::OK, "{subject}: {body}");
		let printed = command(
			&by_command,
			BanCli::Remove {
				target: Some(UnbanTarget::parse(subject).expect("subject")),
				account: None,
				ip: None,
			},
		)
		.await;
		for field in ["target", "bans", "failures"] {
			assert_eq!(body[field], printed[field], "{subject}: {field}");
		}
	}
	assert_eq!(by_route.ban_subjects(), by_command.ban_subjects());
	assert!(by_route.ban_subjects().is_empty());
}

#[tokio::test]
async fn the_allow_list_changes_the_same_way_by_route_and_by_command() {
	let (by_route, by_command) = (
		Arc::new(FakeAdmin::default()),
		Arc::new(FakeAdmin::default()),
	);
	let (app, _dir) = router(by_route.clone());
	let cidr = parse_allow("10.1.0.0/16").expect("block");
	for round in 0..2 {
		let (status, body) = route(
			&app,
			"POST",
			"/api/v1/bans/allow",
			Some(json!({"cidr": "10.1.0.0/16"})),
		)
		.await;
		let printed = command(
			&by_command,
			BanCli::Allow {
				action: AllowCli::Add { cidr },
			},
		)
		.await;
		assert_eq!(body["cidr"], printed["cidr"], "round {round}");
		assert_eq!(
			body["changed"] == true,
			printed["result"] == "saved",
			"round {round}"
		);
		assert_eq!(
			status,
			if round == 0 {
				StatusCode::CREATED
			} else {
				StatusCode::OK
			}
		);
	}
	let (status, body) = route(&app, "DELETE", "/api/v1/bans/allow/10.1.0.0%2F16", None).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	command(
		&by_command,
		BanCli::Allow {
			action: AllowCli::Remove { cidr },
		},
	)
	.await;
	assert_eq!(by_route.allowed(), by_command.allowed());
	assert_eq!(by_route.writes(), by_command.writes());
}
