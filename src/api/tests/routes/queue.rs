//! The queue the operator inspects and cancels from.

use super::base::{TOKEN, request, test_state};
use super::*;
use axum::http::StatusCode;
use std::time::Duration;

use crate::storage::FsSpool;

#[tokio::test]
async fn queue_pagination_walks_all_entries() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 5));

	let (status, page) = request(&app, "GET", "/api/v1/queue?limit=2", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(page["entries"].as_array().expect("entries").len(), 2);
	let cursor = page["next_cursor"].as_str().expect("cursor").to_string();

	let (_, page2) = request(
		&app,
		"GET",
		&format!("/api/v1/queue?limit=2&cursor={cursor}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(page2["entries"].as_array().expect("entries").len(), 2);
	// No overlap between pages.
	assert_ne!(page["entries"][0]["id"], page2["entries"][0]["id"]);

	let cursor2 = page2["next_cursor"].as_str().expect("cursor").to_string();
	let (_, page3) = request(
		&app,
		"GET",
		&format!("/api/v1/queue?limit=2&cursor={cursor2}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(page3["entries"].as_array().expect("entries").len(), 1);
	assert!(page3["next_cursor"].is_null());
}

#[tokio::test]
async fn queue_rejects_zero_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let (status, body) = request(&app, "GET", "/api/v1/queue?limit=0", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"]["code"], "invalid_input");
}

#[tokio::test]
async fn queue_entry_can_be_removed_once() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 1));
	let (_, page) = request(&app, "GET", "/api/v1/queue", Some(TOKEN.as_str())).await;
	let id = page["entries"][0]["id"].as_str().expect("id").to_string();

	let (status, body) = request(
		&app,
		"DELETE",
		&format!("/api/v1/queue/{id}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["removed"], id.as_str());

	let (status, body) = request(
		&app,
		"DELETE",
		&format!("/api/v1/queue/{id}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	assert_eq!(body["error"]["code"], "not_found");
}

#[tokio::test]
async fn queue_removal_records_cancellation_with_extra() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 1);
	let (_, page) = request(
		&router(state.clone()),
		"GET",
		"/api/v1/queue",
		Some(TOKEN.as_str()),
	)
	.await;
	let id: uuid::Uuid = page["entries"][0]["id"]
		.as_str()
		.expect("id")
		.parse()
		.expect("uuid");
	let extra = serde_json::json!({"order": "A-1042"});
	FsSpool::open(dir.path())
		.expect("spool")
		.update_envelope(id, |envelope| {
			envelope
				.extra
				.insert("order".to_string(), "A-1042".to_string());
		})
		.expect("add extra");
	let app = router(state.with_delivery_log_days(30));
	let (status, _) = request(
		&app,
		"DELETE",
		&format!("/api/v1/queue/{id}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);

	let records = crate::storage::DeliveryLog::open(dir.path(), 30)
		.list(Some(10), |record| record.spool_id == id)
		.expect("delivery log");
	assert_eq!(records.len(), 1);
	assert_eq!(
		records[0].outcome,
		crate::storage::DeliveryOutcome::Canceled
	);
	assert_eq!(
		records[0].extra,
		serde_json::from_value(extra).expect("extra map")
	);
}

#[tokio::test]
async fn queue_removal_notifies_webhook_with_extra() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = test_state(dir.path(), 1);
	let (_, page) = request(
		&router(state.clone()),
		"GET",
		"/api/v1/queue",
		Some(TOKEN.as_str()),
	)
	.await;
	let id: uuid::Uuid = page["entries"][0]["id"]
		.as_str()
		.expect("id")
		.parse()
		.expect("uuid");
	FsSpool::open(dir.path())
		.expect("spool")
		.update_envelope(id, |envelope| {
			envelope
				.extra
				.insert("order".to_string(), "A-1042".to_string());
		})
		.expect("add extra");
	let (url, captured) = crate::webhook::tests::receiver::webhook_receiver().await;
	let webhook = std::sync::Arc::new(
		crate::webhook::Webhook::new_allowing_private(&url, None).expect("webhook"),
	);
	let app = router(state.with_delivery_log_days(30).with_webhook(Some(webhook)));
	let (status, _) = request(
		&app,
		"DELETE",
		&format!("/api/v1/queue/{id}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	for _ in 0..200 {
		if !captured.lock().expect("lock").is_empty() {
			break;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	let bodies = captured.lock().expect("lock").clone();
	let event = bodies
		.iter()
		.map(|body| serde_json::from_str::<serde_json::Value>(body).expect("event"))
		.find(|event| event["event"] == "canceled")
		.expect("canceled event");
	assert_eq!(event["spool_id"], id.to_string());
	assert_eq!(event["extra"], serde_json::json!({"order": "A-1042"}));
}

#[tokio::test]
async fn removing_unknown_queue_entry_leaves_no_delivery_record() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0).with_delivery_log_days(30));
	let id = uuid::Uuid::now_v7();
	let (status, _) = request(
		&app,
		"DELETE",
		&format!("/api/v1/queue/{id}"),
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let records = crate::storage::DeliveryLog::open(dir.path(), 30)
		.list(Some(10), |_| true)
		.expect("delivery log");
	assert!(records.is_empty());
}
