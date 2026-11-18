//! Who reads a domain: the answer, the scope it needs and what a key
//! confined to some domains sees.

use axum::http::StatusCode;
use serde_json::json;

use super::fixture::{CONFINED, ELSEWHERE, READER, SENDER, get, token, world};

#[tokio::test]
async fn a_domain_reads_with_its_role_overrides_and_what_relies_on_it() {
	let world = world();
	let (status, body) = get(&world, "/api/v1/domains/a.example", token()).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body,
		json!({
			"domain": "a.example",
			"enabled": true,
			"role": "full",
			"quota": 1000,
			"submission_rate": 7,
			"aliases_to": ["alias.example"],
			"aliases_from": [],
			"accounts": ["ann@a.example"],
			"aliases": ["team@a.example"],
		})
	);
	let (status, body) = get(&world, "/api/v1/domains/b.example", token()).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["enabled"], false, "{body}");
	assert_eq!(body["role"], "disabled", "{body}");
	let (_, body) = get(&world, "/api/v1/domains/xn--bcher-kva.example", token()).await;
	assert_eq!(body["role"], "send-only", "{body}");
}

#[tokio::test]
async fn the_list_carries_each_domains_row() {
	let world = world();
	let (status, body) = get(&world, "/api/v1/domains", token()).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(
		body["domains"],
		json!(["a.example", "b.example", "xn--bcher-kva.example"])
	);
	assert_eq!(body["disabled"], json!(["b.example"]));
	let roles: Vec<(&str, &str)> = body["details"]
		.as_array()
		.expect("details")
		.iter()
		.map(|row| {
			(
				row["domain"].as_str().expect("domain"),
				row["role"].as_str().expect("role"),
			)
		})
		.collect();
	assert_eq!(
		roles,
		[
			("a.example", "full"),
			("b.example", "disabled"),
			("xn--bcher-kva.example", "send-only"),
		]
	);
}

/// A key that is valid but holds only `send` is refused for the scope, and
/// the same request with a `read` key is served: the refusal is the scope's
/// and nothing else's.
#[tokio::test]
async fn a_key_without_the_read_scope_is_refused_and_a_reader_is_served() {
	let world = world();
	for path in ["/api/v1/domains/a.example", "/api/v1/domains"] {
		let (status, body) = get(&world, path, SENDER).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
		assert_eq!(body["error"]["code"], "forbidden", "{path}: {body}");
		assert!(
			body["error"]["message"]
				.as_str()
				.is_some_and(|message| message.contains("scope")),
			"{path}: refused for the scope: {body}"
		);
		let (status, body) = get(&world, path, READER).await;
		assert_eq!(status, StatusCode::OK, "{path}: {body}");
	}
}

#[tokio::test]
async fn a_confined_key_gets_the_same_404_for_a_foreign_and_an_unknown_domain() {
	let world = world();
	let (status, own) = get(&world, "/api/v1/domains/a.example", CONFINED).await;
	assert_eq!(status, StatusCode::OK, "its own domain: {own}");
	assert_eq!(own["domain"], "a.example");
	let (foreign_status, foreign) = get(&world, "/api/v1/domains/b.example", CONFINED).await;
	let (unknown_status, unknown) = get(&world, "/api/v1/domains/nope.example", CONFINED).await;
	assert_eq!(foreign_status, StatusCode::NOT_FOUND, "{foreign}");
	assert_eq!(unknown_status, StatusCode::NOT_FOUND, "{unknown}");
	assert_eq!(foreign, unknown, "the answers must not tell them apart");
	assert_eq!(foreign["error"]["code"], "not_found");
}

#[tokio::test]
async fn a_confined_key_lists_only_its_own_rows() {
	let world = world();
	let (status, body) = get(&world, "/api/v1/domains", CONFINED).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["domains"], json!(["a.example"]));
	let rows: Vec<&str> = body["details"]
		.as_array()
		.expect("details")
		.iter()
		.map(|row| row["domain"].as_str().expect("domain"))
		.collect();
	assert_eq!(rows, ["a.example"]);
}

/// A key confined to a domain the server does not host reaches none of the
/// hosted ones.
#[tokio::test]
async fn a_key_confined_to_a_domain_not_hosted_reaches_nothing() {
	let world = world();
	let (status, body) = get(&world, "/api/v1/domains", ELSEWHERE).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert_eq!(body["details"], json!([]), "{body}");
	let (status, _) = get(&world, "/api/v1/domains/a.example", ELSEWHERE).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}
