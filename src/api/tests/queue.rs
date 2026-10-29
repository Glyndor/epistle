use super::base::{TOKEN, request, test_state};
use super::router;
use crate::storage::FsSpool;
use axum::http::StatusCode;
use std::time::Duration;

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
	let webhook = std::sync::Arc::new(crate::webhook::Webhook::new(&url, None).expect("webhook"));
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
