//! A quota too large for the account file is refused, so the file stays
//! readable and the domain its accounts use stays in use.

use super::fixture::*;
use super::writes::call;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn a_huge_quota_cannot_make_a_domain_in_use_look_free() {
	let world = world();
	world
		.state
		.store()
		.add(crate::directory_store::DynamicAccount {
			name: "carl".to_string(),
			addresses: vec!["carl@xn--bcher-kva.example".to_string()],
			password_hash: "$argon2id$stub".to_string(),
			..crate::directory_store::DynamicAccount::default()
		})
		.expect("account");
	for size in ["9000000T", "8388608T"] {
		let (status, body) = call(
			&world,
			"PUT",
			"/api/v1/accounts/carl/quota",
			WRITER,
			Some(json!({"quota": size})),
		)
		.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{size}: {body}");
	}
	let (status, body) = call(
		&world,
		"PUT",
		"/api/v1/accounts/carl/quota",
		WRITER,
		Some(json!({"quota": "8388607T"})),
	)
	.await;
	assert_eq!(status, StatusCode::OK, "{body}");
	let (status, body) = call(
		&world,
		"DELETE",
		"/api/v1/domains/xn--bcher-kva.example",
		WRITER,
		None,
	)
	.await;
	assert_eq!(status, StatusCode::CONFLICT, "{body}");
}
