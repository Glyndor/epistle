//! The delivery `url` and `expires` of a PushSubscription (RFC 8620 §7.2) are
//! checked when a subscription is created or updated: the `url` must be an
//! absolute `https` URL without embedded credentials, and is immutable, and
//! `expires` must be a UTCDate.

use super::jmap_push::{ANN, call, create, push_state, visible};
use serde_json::{Value, json};

#[tokio::test]
async fn a_delivery_url_that_is_not_https_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = push_state(dir.path());
	for url in [
		"http://push.example/p",
		"ftp://push.example/p",
		"https://user:pw@push.example/p",
		"not a url",
	] {
		let reply = call(
			&app,
			ANN,
			"PushSubscription/set",
			json!({ "create": { "s": { "deviceClientId": "d", "url": url } } }),
		)
		.await;
		let error = &reply[1]["notCreated"]["s"];
		assert_eq!(error["type"], "invalidProperties", "{url}: {reply}");
		assert_eq!(error["properties"], json!(["url"]), "{url}: {reply}");
	}
	assert!(visible(&app, ANN, Value::Null).await.0.is_empty());

	// `url` is immutable (RFC 8620 §7.2), so an update cannot swap a checked
	// https URL for an unchecked one either.
	let id = create(&app, ANN, "https://push.example/p").await;
	let reply = call(
		&app,
		ANN,
		"PushSubscription/set",
		json!({ "update": { (id.clone()): { "url": "http://push.example/p" } } }),
	)
	.await;
	assert_eq!(
		reply[1]["notUpdated"][&id]["type"], "invalidProperties",
		"{reply}"
	);
	// `get` never returns `url` (RFC 8620 §7.2.1); the subscription is still
	// there, unchanged in what it does return.
	let got = call(&app, ANN, "PushSubscription/get", json!({ "ids": [id] })).await;
	assert_eq!(got[1]["list"][0]["deviceClientId"], "d", "{got}");
	assert!(got[1]["list"][0].get("url").is_none(), "{got}");
}

#[tokio::test]
async fn expires_must_be_a_utc_date() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = push_state(dir.path());
	for expires in [json!("tomorrow"), json!("2030-02-30T00:00:00Z"), json!(1)] {
		let reply = call(
			&app,
			ANN,
			"PushSubscription/set",
			json!({ "create": { "s": {
				"deviceClientId": "d", "url": "https://push.example/p", "expires": expires,
			} } }),
		)
		.await;
		let error = &reply[1]["notCreated"]["s"];
		assert_eq!(error["type"], "invalidProperties", "{expires}: {reply}");
		assert_eq!(
			error["properties"],
			json!(["expires"]),
			"{expires}: {reply}"
		);
	}
	let reply = call(
		&app,
		ANN,
		"PushSubscription/set",
		json!({ "create": { "s": {
			"deviceClientId": "d", "url": "https://push.example/p",
			"expires": "2030-01-01T00:00:00Z",
		} } }),
	)
	.await;
	let id = reply[1]["created"]["s"]["id"]
		.as_str()
		.expect("created")
		.to_string();
	let reply = call(
		&app,
		ANN,
		"PushSubscription/set",
		json!({ "update": { (id.clone()): { "expires": "soon" } } }),
	)
	.await;
	assert_eq!(
		reply[1]["notUpdated"][&id]["type"], "invalidProperties",
		"{reply}"
	);
	assert_eq!(
		reply[1]["notUpdated"][&id]["properties"],
		json!(["expires"]),
		"{reply}"
	);
}
