//! `VacationResponse/get` and `/set` tests (RFC 8621 §8): round-trip, validation
//! errors with exact JMAP error types, cross-account refusal, and that the
//! capability is present on every account the session advertises.
//!
//! The unit-level read/write tests live in `src/storage/vacation_store_tests.rs`;
//! here we only exercise the JMAP wire surface.

use axum::http::StatusCode;
use serde_json::json;

use super::router;
use super::tests::{TOKEN, request, request_with_body, test_state};

const CAPABILITY: &str = "urn:ietf:params:jmap:vacationresponse";

#[tokio::test]
async fn session_advertises_vacation_capability() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (_, session) = request(&app, "GET", "/jmap/session", Some(TOKEN.as_str())).await;
	assert!(
		session["capabilities"][CAPABILITY].is_object(),
		"vacation capability should be advertised"
	);
	let account = &session["accounts"]["alice"];
	assert!(
		account["accountCapabilities"][CAPABILITY].is_object(),
		"every account should advertise the vacation capability"
	);
}

#[tokio::test]
async fn vacation_get_returns_disabled_default_for_unknown_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let req = json!({
		"methodCalls": [["VacationResponse/get", {"accountId": "alice"}, "c1"]],
	});
	let (status, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	assert_eq!(status, StatusCode::OK);
	let response = &body["methodResponses"][0];
	assert_eq!(response[0], "VacationResponse/get");
	assert_eq!(response[1]["accountId"], "alice");
	let list = response[1]["list"].as_array().expect("list array");
	assert_eq!(list.len(), 1);
	let object = &list[0];
	assert_eq!(object["id"], "singleton");
	assert_eq!(object["isEnabled"], false);
	assert!(object["fromDate"].is_null());
	assert!(object["toDate"].is_null());
	assert!(object["textBody"].is_null());
	assert!(object["htmlBody"].is_null());
}

#[tokio::test]
async fn vacation_set_round_trips_through_get() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let set_req = json!({
		"methodCalls": [["VacationResponse/set", {
			"accountId": "alice",
			"update": { "singleton": {
				"isEnabled": true,
				"fromDate": "2030-01-01T00:00:00Z",
				"toDate": "2030-12-31T23:59:59Z",
				"subject": "Out of office",
				"textBody": "I am away.",
				"htmlBody": "<p>I am away.</p>",
			}}
		}, "s1"]],
	});
	let (status, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(set_req),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	let response = &body["methodResponses"][0];
	assert_eq!(response[0], "VacationResponse/set");
	assert!(
		response[1]["notUpdated"]
			.as_object()
			.map(|m| m.is_empty())
			.unwrap_or(true)
	);
	let updated = &response[1]["updated"];
	assert_eq!(updated["singleton"], serde_json::Value::Null);

	let get_req = json!({
		"methodCalls": [["VacationResponse/get", {"accountId": "alice"}, "g1"]],
	});
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(get_req),
	)
	.await;
	let object = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(object["id"], "singleton");
	assert_eq!(object["isEnabled"], true);
	assert_eq!(object["fromDate"], "2030-01-01T00:00:00Z");
	assert_eq!(object["toDate"], "2030-12-31T23:59:59Z");
	assert_eq!(object["subject"], "Out of office");
	assert_eq!(object["textBody"], "I am away.");
	assert_eq!(object["htmlBody"], "<p>I am away.</p>");
}

#[tokio::test]
async fn vacation_set_after_rejects_invalid_dates() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let set_req = json!({
		"methodCalls": [["VacationResponse/set", {
			"accountId": "alice",
			"update": { "singleton": {
				"isEnabled": true,
				"fromDate": "2030-12-31T00:00:00Z",
				"toDate": "2030-01-01T00:00:00Z",
				"textBody": "Out",
			}}
		}, "s1"]],
	});
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(set_req),
	)
	.await;
	let not_updated = &body["methodResponses"][0][1]["notUpdated"];
	let error = &not_updated["singleton"];
	assert_eq!(error["type"], "invalidProperties");
	let properties: Vec<&str> = error["properties"]
		.as_array()
		.expect("properties array")
		.iter()
		.filter_map(|v| v.as_str())
		.collect();
	assert!(properties.contains(&"fromDate"), "{properties:?}");
	assert!(properties.contains(&"toDate"), "{properties:?}");
	// The persisted setting must not have flipped: a failed `/set` is a
	// no-op, not a partial write.
	let get_req = json!({
		"methodCalls": [["VacationResponse/get", {"accountId": "alice"}, "g1"]],
	});
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(get_req),
	)
	.await;
	let object = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(object["isEnabled"], false);
	assert!(object["textBody"].is_null());
}

#[tokio::test]
async fn vacation_set_rejects_unparseable_date_value() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let set_req = json!({
		"methodCalls": [["VacationResponse/set", {
			"accountId": "alice",
			"update": { "singleton": {
				"isEnabled": true,
				"fromDate": "yesterday",
				"textBody": "Out",
			}}
		}, "s1"]],
	});
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(set_req),
	)
	.await;
	let error = &body["methodResponses"][0][1]["notUpdated"]["singleton"];
	assert_eq!(error["type"], "invalidProperties");
	let properties = error["properties"].as_array().expect("properties array");
	let names: Vec<&str> = properties.iter().filter_map(|v| v.as_str()).collect();
	assert!(names.contains(&"fromDate"), "{names:?}");
}

#[tokio::test]
async fn vacation_set_rejects_oversized_body() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let huge = "x".repeat(crate::storage::vacation_store::MAX_BODY_BYTES + 1);
	let set_req = json!({
		"methodCalls": [["VacationResponse/set", {
			"accountId": "alice",
			"update": { "singleton": {
				"isEnabled": true,
				"textBody": huge,
			}}
		}, "s1"]],
	});
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(set_req),
	)
	.await;
	let error = &body["methodResponses"][0][1]["notUpdated"]["singleton"];
	assert_eq!(error["type"], "invalidProperties");
	let properties = error["properties"].as_array().expect("properties array");
	let names: Vec<&str> = properties.iter().filter_map(|v| v.as_str()).collect();
	assert!(names.contains(&"textBody"), "{names:?}");
}

#[tokio::test]
async fn vacation_set_rejects_unknown_property() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let set_req = json!({
		"methodCalls": [["VacationResponse/set", {
			"accountId": "alice",
			"update": { "singleton": {
				"isEnabled": true,
				"randomExtra": "value",
			}}
		}, "s1"]],
	});
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(set_req),
	)
	.await;
	let error = &body["methodResponses"][0][1]["notUpdated"]["singleton"];
	assert_eq!(error["type"], "invalidProperties");
	let properties = error["properties"].as_array().expect("properties array");
	let names: Vec<&str> = properties.iter().filter_map(|v| v.as_str()).collect();
	assert!(names.contains(&"randomExtra"), "{names:?}");
}

#[tokio::test]
async fn vacation_set_rejects_wrong_singleton_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let set_req = json!({
		"methodCalls": [["VacationResponse/set", {
			"accountId": "alice",
			"update": { "wrong": { "isEnabled": true, "textBody": "Out" } }
		}, "s1"]],
	});
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(set_req),
	)
	.await;
	let not_updated = &body["methodResponses"][0][1]["notUpdated"];
	let error = &not_updated["wrong"];
	assert_eq!(error["type"], "notFound");
}

#[tokio::test]
async fn vacation_set_refuses_create_and_destroy() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let set_req = json!({
		"methodCalls": [["VacationResponse/set", {
			"accountId": "alice",
			"create": { "c": { "isEnabled": true, "textBody": "Out" } },
			"destroy": ["singleton"],
		}, "s1"]],
	});
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(set_req),
	)
	.await;
	let response = &body["methodResponses"][0][1];
	let not_created = response["notCreated"]
		.as_object()
		.expect("notCreated object");
	let not_destroyed = response["notDestroyed"]
		.as_object()
		.expect("notDestroyed object");
	assert_eq!(not_created["c"]["type"], "forbidden");
	assert_eq!(not_destroyed["singleton"]["type"], "forbidden");
	// Nothing was persisted: a follow-up /get still reports the disabled
	// default.
	let get_req = json!({
		"methodCalls": [["VacationResponse/get", {"accountId": "alice"}, "g1"]],
	});
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(get_req),
	)
	.await;
	let object = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(object["isEnabled"], false);
	assert!(object["textBody"].is_null());
}

#[tokio::test]
async fn vacation_get_for_other_account_is_account_not_found() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let req = json!({
		"methodCalls": [["VacationResponse/get", {"accountId": "nobody"}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let response = &body["methodResponses"][0];
	assert_eq!(response[0], "error");
	assert_eq!(response[1]["type"], "accountNotFound");
}

#[tokio::test]
async fn vacation_get_without_account_id_is_invalid_arguments() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let req = json!({
		"methodCalls": [["VacationResponse/get", {}, "c1"]],
	});
	let (_, body) =
		request_with_body(&app, "POST", "/jmap/api", Some(TOKEN.as_str()), Some(req)).await;
	let response = &body["methodResponses"][0];
	assert_eq!(response[0], "error");
	assert_eq!(response[1]["type"], "invalidArguments");
}

#[tokio::test]
async fn vacation_set_can_clear_text_body() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let enable = json!({
		"methodCalls": [["VacationResponse/set", {
			"accountId": "alice",
			"update": { "singleton": { "isEnabled": true, "textBody": "Out" } }
		}, "s1"]],
	});
	request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(enable),
	)
	.await;
	let disable = json!({
		"methodCalls": [["VacationResponse/set", {
			"accountId": "alice",
			"update": { "singleton": { "isEnabled": false, "textBody": null } }
		}, "s2"]],
	});
	request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(disable),
	)
	.await;
	let get_req = json!({
		"methodCalls": [["VacationResponse/get", {"accountId": "alice"}, "g1"]],
	});
	let (_, body) = request_with_body(
		&app,
		"POST",
		"/jmap/api",
		Some(TOKEN.as_str()),
		Some(get_req),
	)
	.await;
	let object = &body["methodResponses"][0][1]["list"][0];
	assert_eq!(object["isEnabled"], false);
	assert!(object["textBody"].is_null());
}
