//! What `PushSubscription/get` returns (RFC 8620 §7.2.1): `url` and `keys` are
//! private to the device that registered them and are never returned; with
//! `properties` null or omitted every other property is, and asking for one of
//! the two by name is `forbidden`. The response carries no `state`.

use super::jmap_tests_push::{ANN, call, push_state};
use serde_json::json;

/// Create a subscription that carries `keys` as well as `url`.
async fn create_with_keys(app: &axum::Router) -> String {
	let reply = call(
		app,
		ANN,
		"PushSubscription/set",
		json!({ "create": { "s": {
			"deviceClientId": "d",
			"url": "https://push.example/p",
			"keys": { "p256dh": "public-key", "auth": "auth-secret" },
		} } }),
	)
	.await;
	reply[1]["created"]["s"]["id"]
		.as_str()
		.expect("created")
		.to_string()
}

#[tokio::test]
async fn default_properties_leave_out_url_and_keys() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = push_state(dir.path());
	let id = create_with_keys(&app).await;
	let expected = json!({
		"id": id,
		"deviceClientId": "d",
		"verificationCode": null,
		"expires": null,
		"types": null,
	});
	for args in [json!({}), json!({ "ids": null, "properties": null })] {
		let reply = call(&app, ANN, "PushSubscription/get", args.clone()).await;
		assert_eq!(reply[0], "PushSubscription/get", "{args}");
		assert_eq!(reply[1]["list"], json!([expected]), "{args}");
		assert!(
			reply[1].get("state").is_none(),
			"{args}: PushSubscription/get returns no state"
		);
	}
}

#[tokio::test]
async fn asking_for_url_or_keys_is_forbidden() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = push_state(dir.path());
	create_with_keys(&app).await;
	for properties in [json!(["url"]), json!(["keys"]), json!(["id", "url"])] {
		let reply = call(
			&app,
			ANN,
			"PushSubscription/get",
			json!({ "properties": properties }),
		)
		.await;
		assert_eq!(
			reply,
			json!(["error", { "type": "forbidden" }, "c1"]),
			"properties {properties}"
		);
	}
}

#[tokio::test]
async fn named_properties_return_those_and_the_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = push_state(dir.path());
	let id = create_with_keys(&app).await;
	let reply = call(
		&app,
		ANN,
		"PushSubscription/get",
		json!({ "properties": ["deviceClientId"] }),
	)
	.await;
	assert_eq!(
		reply[1]["list"],
		json!([{ "id": id, "deviceClientId": "d" }])
	);
	let reply = call(
		&app,
		ANN,
		"PushSubscription/get",
		json!({ "properties": ["colour"] }),
	)
	.await;
	assert_eq!(
		reply,
		json!(["error", { "type": "invalidArguments" }, "c1"]),
		"an unknown property"
	);
}
