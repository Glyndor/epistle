//! An account name with a path separator is refused by the API, and reaches
//! no directory.

use axum::http::StatusCode;

use super::tests::archive_test_state;
use crate::api::tests::{TOKEN, request, request_with_body};

fn entries(dir: &std::path::Path) -> Vec<String> {
	let mut names: Vec<String> = std::fs::read_dir(dir)
		.expect("read_dir")
		.flatten()
		.map(|entry| entry.file_name().to_string_lossy().into_owned())
		.collect();
	names.sort();
	names
}

#[tokio::test]
async fn creating_an_account_with_a_separator_is_refused_and_creates_nothing() {
	let (dir, state) = archive_test_state().await;
	let before = entries(dir.path());
	let app = super::super::super::router(state);
	for name in ["a/b", "../x", "..", "a\\b", ""] {
		let (status, body) = request_with_body(
			&app,
			"POST",
			"/api/v1/accounts",
			Some(TOKEN.as_str()),
			Some(serde_json::json!({
				"name": name,
				"addresses": ["new@example.org"],
				"password": "a-long-password-1",
			})),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "name {name:?}");
		assert_eq!(body["error"]["code"], "invalid_input", "name {name:?}");
		assert_eq!(
			body["error"]["message"],
			format!("account name \"{name}\" must be lowercase alphanumeric/hyphen"),
			"name {name:?}"
		);
	}
	assert_eq!(entries(dir.path()), before, "no account directory appears");
}

#[tokio::test]
async fn archive_routes_answer_404_for_a_name_with_a_separator() {
	let (dir, state) = archive_test_state().await;
	let before = entries(dir.path());
	let app = super::super::super::router(state);
	let id = uuid::Uuid::now_v7();
	for name in ["..%2Fvictim", "a%2Fb", "%2E%2E"] {
		let (status, body) = request(
			&app,
			"GET",
			&format!("/api/v1/accounts/{name}/archive"),
			Some(TOKEN.as_str()),
		)
		.await;
		assert_eq!(status, StatusCode::NOT_FOUND, "list {name}");
		assert_eq!(body["error"]["message"], "no such account", "list {name}");
		let (status, body) = request(
			&app,
			"POST",
			&format!("/api/v1/accounts/{name}/archive/{id}/restore"),
			Some(TOKEN.as_str()),
		)
		.await;
		assert_eq!(status, StatusCode::NOT_FOUND, "restore {name}");
		assert_eq!(
			body["error"]["message"], "no such account",
			"restore {name}"
		);
	}
	assert_eq!(entries(dir.path()), before);
}
