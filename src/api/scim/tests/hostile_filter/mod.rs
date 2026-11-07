//! Encoded filters traverse HTTP query decoding, SCIM parsing and account lookup.
use super::base::{SCIM_KEY_SECRET, app, build_state};
use crate::api::tests::hostile_wire::{Peer, read, supervised};
use axum::http::StatusCode;

async fn filter(peer: &Peer, expression: &str) -> (StatusCode, serde_json::Value) {
	let mut url = reqwest::Url::parse(&format!("{}/scim/v2/Users", peer.base)).unwrap();
	url.query_pairs_mut().append_pair("filter", expression);
	read(
		peer.client
			.get(url)
			.bearer_auth(SCIM_KEY_SECRET.as_str())
			.send()
			.await
			.expect("SCIM filter response"),
	)
	.await
}

fn rejected(status: StatusCode, body: &serde_json::Value) {
	assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
	assert_eq!(body["status"], "400");
	assert_eq!(
		body["schemas"][0],
		"urn:ietf:params:scim:api:messages:2.0:Error"
	);
	assert!(body.get("Resources").is_none());
}

#[tokio::test]
async fn unsupported_filter_operator_is_rejected_on_wire() {
	if supervised(
		module_path!(),
		"unsupported_filter_operator_is_rejected_on_wire",
	) {
		return;
	}
	let (_dir, state) = build_state();
	let peer = Peer::start(app(state)).await;
	let (status, body) = filter(&peer, "userName co \"admin\"").await;
	rejected(status, &body);
	assert_eq!(body["detail"], "only `userName eq \"x\"` is supported");
	peer.healthy().await;
}

#[tokio::test]
async fn injected_filter_expression_is_rejected_on_wire() {
	if supervised(
		module_path!(),
		"injected_filter_expression_is_rejected_on_wire",
	) {
		return;
	}
	let (_dir, state) = build_state();
	state
		.store()
		.add(crate::directory_store::DynamicAccount {
			name: "victim".into(),
			addresses: vec!["victim@example.org".into()],
			..Default::default()
		})
		.unwrap();
	let peer = Peer::start(app(state)).await;
	// Positive control: auth and query decoding really reach the SCIM handler.
	let (status, body) = filter(&peer, "userName eq \"victim\"").await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["totalResults"], 1);
	for expression in [
		"userName eq \"absent\" or userName eq \"victim\"",
		"userName eq \"absent\" or \"1\" eq \"1\"",
		"userName eq \"victim\"; DROP TABLE accounts; --\"",
	] {
		let (status, body) = filter(&peer, expression).await;
		rejected(status, &body);
	}
	let (status, body) = filter(&peer, "userName eq \"victim\"").await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["totalResults"], 1);
	peer.healthy().await;
}
