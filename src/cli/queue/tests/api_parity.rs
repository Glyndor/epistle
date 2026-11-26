//! `epistle queue` against `/api/v1/queue` on the same spool: the routes say
//! and do what the command does.

use std::sync::Arc;

use axum::http::StatusCode;
use tower::ServiceExt;

use super::base::spool_with;
use super::*;

const TOKEN: &str = "queue-parity-token";

fn router(dir: &Path) -> axum::Router {
	let accounts = Arc::new(
		crate::directory_store::AccountStore::open(
			dir,
			vec!["example.org".to_string()],
			std::collections::HashMap::new(),
			Vec::new(),
		)
		.expect("store"),
	);
	let state = crate::api::ApiState::new(
		&crate::api::api_keys::sha256_hash(TOKEN),
		dir.to_path_buf(),
		vec!["example.org".to_string()],
		accounts.clone(),
		FsSpool::open(dir).expect("spool"),
	)
	.with_directory(accounts.handle());
	crate::api::router(state)
}

async fn route(app: &axum::Router, method: &str, path: &str) -> (StatusCode, serde_json::Value) {
	let request = axum::http::Request::builder()
		.method(method)
		.uri(path)
		.header("authorization", format!("Bearer {TOKEN}"))
		.body(axum::body::Body::empty())
		.expect("request");
	let response = app.clone().oneshot(request).await.expect("response");
	let status = response.status();
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body");
	(status, serde_json::from_slice(&bytes).unwrap_or_default())
}

fn printed(dir: &Path, args: &[&str]) -> serde_json::Value {
	let (_, out) = super::base::run_args(dir, args, 1_800_000_000);
	serde_json::from_str(&out).expect("the command prints JSON")
}

#[tokio::test]
async fn showing_an_entry_is_what_the_command_shows() {
	let (dir, _spool, ids) = spool_with(2);
	let app = router(dir.path());
	for id in ids {
		let (status, body) = route(&app, "GET", &format!("/api/v1/queue/{id}")).await;
		assert_eq!(status, StatusCode::OK, "{body}");
		let dir_path = dir.path().to_path_buf();
		let shown = tokio::task::spawn_blocking(move || {
			printed(&dir_path, &["show", &id.to_string(), "--json"])
		})
		.await
		.expect("ran");
		assert_eq!(body, shown);
	}
}

#[tokio::test]
async fn hold_and_release_by_route_leave_the_entry_as_the_command_does() {
	let (by_route_dir, by_route, ids) = spool_with(1);
	let (by_command_dir, by_command, _) = spool_with(1);
	let app = router(by_route_dir.path());
	let route_id = ids[0];
	let command_id = by_command.list().expect("list")[0];
	for (action, cli_action) in [("hold", "hold"), ("release", "release"), ("retry", "retry")] {
		let (status, body) =
			route(&app, "POST", &format!("/api/v1/queue/{route_id}/{action}")).await;
		assert_eq!(status, StatusCode::OK, "{body}");
		let dir_path = by_command_dir.path().to_path_buf();
		let id = command_id.to_string();
		let (code, _) = tokio::task::spawn_blocking(move || {
			super::base::run_args(&dir_path, &[cli_action, &id], 1_800_000_000)
		})
		.await
		.expect("ran");
		assert_eq!(code, ExitCode::SUCCESS);
		let (left, expected) = (
			by_route.load_envelope(route_id).expect("entry"),
			by_command.load_envelope(command_id).expect("entry"),
		);
		assert_eq!(
			(left.held.is_some(), left.next_attempt),
			(expected.held.is_some(), expected.next_attempt),
			"{action}"
		);
	}
}

#[tokio::test]
async fn the_destinations_are_the_rows_the_command_prints() {
	let (dir, spool, _) = spool_with(1);
	let until = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs()
		+ 3600;
	let id = spool.list().expect("list")[0];
	spool
		.update_envelope(id, |envelope| {
			let recipient = envelope.recipients[0].clone();
			let mut state = envelope.recipient_state(&recipient);
			state.next_attempt = until;
			state.throttled = 2;
			state.attempts = 2;
			state.last_error = Some("421 4.7.0 slow down".into());
			state.remote = Some("mx.remote.example".into());
			envelope.set_recipient_state(&recipient, state);
			envelope.settle();
		})
		.expect("throttle");
	let app = router(dir.path());
	let (status, body) = route(&app, "GET", "/api/v1/queue/destinations").await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let rows = body["destinations"].as_array().expect("rows");
	assert!(!rows.is_empty(), "{body}");
	let dir_path = dir.path().to_path_buf();
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs();
	let printed = tokio::task::spawn_blocking(move || {
		let spool = FsSpool::open(&dir_path).expect("spool");
		let mut out = Vec::new();
		let _ = crate::cli::queue::destinations::list(&spool, now, true, &mut out);
		serde_json::from_slice::<serde_json::Value>(&out).expect("JSON")
	})
	.await
	.expect("ran");
	assert_eq!(serde_json::Value::Array(rows.clone()), printed);
}
