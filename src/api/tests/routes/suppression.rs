//! The suppression lists the operator keeps entries on.

use super::base::{TOKEN, request, request_with_body, test_state};
use super::*;
use crate::queue::SuppressionList;
use axum::http::StatusCode;
use serde_json::json;

async fn add(app: &Router, path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
	request_with_body(app, "POST", path, Some(TOKEN.as_str()), Some(body)).await
}

#[tokio::test]
async fn suppression_lists_global_and_per_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	let suppression = crate::queue::SuppressionList::open(dir.path()).expect("open");
	suppression.suppress("bob@example.net");
	suppression.suppress_for("alice@example.org", "carol@example.net");
	let app = router(test_state(dir.path(), 0));

	// Global list.
	let (status, body) = request(&app, "GET", "/api/v1/suppression", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["addresses"][0], "bob@example.net");

	// Per-account list.
	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/suppression?account=alice@example.org",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["addresses"][0], "carol@example.net");
}

#[tokio::test]
async fn suppression_delete_removes_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let suppression = crate::queue::SuppressionList::open(dir.path()).expect("open");
	suppression.suppress("bob@example.net");
	let app = router(test_state(dir.path(), 0));

	let (status, body) = request(
		&app,
		"DELETE",
		"/api/v1/suppression/bob@example.net",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["removed"], "bob@example.net");
	assert!(
		!crate::queue::SuppressionList::open(dir.path())
			.expect("open")
			.is_suppressed("bob@example.net")
	);
}

#[tokio::test]
async fn suppression_add_accepts_an_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	let (status, body) = add(
		&app,
		"/api/v1/suppression",
		json!({"address": "Complaint@Example.net", "reason": "manual complaint"}),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["suppressed"], "complaint@example.net");
	let list = SuppressionList::open(dir.path()).expect("open");
	assert_eq!(list.list(), ["complaint@example.net"]);
	let entry = list.entry("complaint@example.net").expect("entry");
	assert_eq!(entry.reason.as_deref(), Some("manual complaint"));
}

#[tokio::test]
async fn suppression_add_without_a_reason_records_the_api_default() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	let (status, _) = add(
		&app,
		"/api/v1/suppression",
		json!({"address": "bob@example.net"}),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	let entry = SuppressionList::open(dir.path())
		.expect("open")
		.entry("bob@example.net")
		.expect("entry");
	assert_eq!(
		entry.reason.as_deref(),
		Some(crate::suppression::API_DEFAULT_REASON)
	);
}

#[tokio::test]
async fn suppression_add_is_idempotent() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let first = json!({"address": "Complaint@Example.net", "reason": "first reason"});
	let (status, one) = add(&app, "/api/v1/suppression", first).await;
	assert_eq!(status, StatusCode::OK);
	let stored = SuppressionList::open(dir.path())
		.expect("open")
		.entry("complaint@example.net")
		.expect("entry");

	// A later second would show up as a different `since` if the marker were
	// replaced.
	tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
	let again = json!({"address": "complaint@example.net", "reason": "second reason"});
	let (status, two) = add(&app, "/api/v1/suppression", again).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(one["suppressed"], "complaint@example.net");
	assert_eq!(two["suppressed"], one["suppressed"]);

	let list = SuppressionList::open(dir.path()).expect("open");
	assert_eq!(list.list(), ["complaint@example.net"]);
	let kept = list.entry("complaint@example.net").expect("entry");
	assert_eq!(kept.reason.as_deref(), Some("first reason"));
	assert_eq!(kept.since, stored.since);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_suppression_adds_publish_one_complete_marker() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let request_for = |reason: &str| {
		let app = app.clone();
		let body = json!({"address": "race@example.net", "reason": reason});
		async move { add(&app, "/api/v1/suppression", body).await }
	};
	let (left, right) = tokio::join!(request_for("left reason"), request_for("right reason"));
	assert_eq!(left.0, StatusCode::OK);
	assert_eq!(right.0, StatusCode::OK);

	let list = SuppressionList::open(dir.path()).expect("open");
	assert_eq!(list.list(), ["race@example.net"]);
	let entry = list.entry("race@example.net").expect("one readable marker");
	assert!(entry.since.is_some(), "the marker carries its timestamp");
	assert!(
		matches!(
			entry.reason.as_deref(),
			Some("left reason") | Some("right reason")
		),
		"the reason belongs to one request: {:?}",
		entry.reason
	);
}

/// The same race without HTTP in between: many threads released together on
/// many fresh addresses, each address must end with one complete marker.
#[test]
fn racing_threads_never_leave_a_partial_marker() {
	let dir = tempfile::tempdir().expect("tempdir");
	let list = std::sync::Arc::new(SuppressionList::open(dir.path()).expect("open"));
	let gate = std::sync::Arc::new(std::sync::Barrier::new(4));
	let handles = (0..4)
		.map(|worker| {
			let (list, gate) = (list.clone(), gate.clone());
			std::thread::spawn(move || {
				for round in 0..40 {
					gate.wait();
					let address = format!("race{round}@example.net");
					let reason = format!("worker {worker}");
					crate::suppression::add(&list, &address, &[], Some(&reason), "unused")
						.unwrap_or_else(|_| panic!("add {address}"));
				}
			})
		})
		.collect::<Vec<_>>();
	for handle in handles {
		handle.join().expect("thread");
	}
	assert_eq!(list.list().len(), 40);
	for round in 0..40 {
		let entry = list
			.entry(&format!("race{round}@example.net"))
			.expect("complete marker");
		assert!(entry.since.is_some());
		assert!(
			entry
				.reason
				.as_deref()
				.is_some_and(|r| r.starts_with("worker "))
		);
	}
}

#[tokio::test]
async fn suppression_add_refuses_an_invalid_address() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	for path in [
		"/api/v1/suppression",
		"/api/v1/suppression?account=alice",
		"/api/v1/suppression?account=alice@example.org",
	] {
		let (status, body) = add(&app, path, json!({"address": "not an address"})).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
		assert_eq!(body["error"]["code"], "invalid_input", "{path}");
	}
	assert_nothing_listed(dir.path());
}

#[tokio::test]
async fn suppression_add_refuses_an_invalid_reason() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	let (status, body) = add(
		&app,
		"/api/v1/suppression",
		json!({"address": "bob@example.net", "reason": "line\nbreak"}),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
	assert_eq!(body["error"]["code"], "invalid_input");
	assert_nothing_listed(dir.path());
}

/// Neither the global list nor any of alice's lists has an entry.
fn assert_nothing_listed(dir: &std::path::Path) {
	let list = SuppressionList::open(dir).expect("open");
	assert!(list.list().is_empty());
	assert!(list.list_for("alice").is_empty());
	assert!(list.list_for("alice@example.org").is_empty());
}

#[tokio::test]
async fn an_account_address_selects_only_that_sending_list() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	let (status, body) = add(
		&app,
		"/api/v1/suppression?account=alice@example.org",
		json!({"address": "bob@example.net"}),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["suppressed"], "bob@example.net");
	let list = SuppressionList::open(dir.path()).expect("open");
	assert_eq!(list.list_for("alice@example.org"), ["bob@example.net"]);
	assert!(list.list_for("alice").is_empty(), "not the name list");
	assert!(list.list().is_empty(), "not the global list");
}

#[tokio::test]
async fn an_account_name_selects_its_name_and_address_lists() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));

	let (status, _) = add(
		&app,
		"/api/v1/suppression?account=alice",
		json!({"address": "bob@example.net"}),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	let list = SuppressionList::open(dir.path()).expect("open");
	assert_eq!(list.list_for("alice"), ["bob@example.net"]);
	assert_eq!(list.list_for("alice@example.org"), ["bob@example.net"]);
	assert!(list.list().is_empty());

	let (status, _) = add(
		&app,
		"/api/v1/suppression?account=nobody",
		json!({"address": "bob@example.net"}),
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_message_to_an_api_suppressed_address_is_dropped_and_logged_as_suppressed() {
	use crate::queue::tests::test_remote::FakeRemote;
	use crate::smtp::session::AcceptedMessage;
	use crate::storage::delivery_log::DeliveryLog;

	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(test_state(dir.path(), 0));
	let spool = crate::storage::FsSpool::open(dir.path()).expect("spool");
	let (status, _) = add(
		&app,
		"/api/v1/suppression",
		json!({"address": "bob@remote.example"}),
	)
	.await;
	assert_eq!(status, StatusCode::OK);

	spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@example.org".into(),
				recipients: vec!["bob@remote.example".into()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&std::collections::BTreeMap::new(),
		)
		.expect("queue");
	let remote = FakeRemote::default();
	let worker = crate::queue::Worker::new(
		crate::storage::FsSpool::open(dir.path()).expect("spool"),
		std::sync::Arc::new(remote.clone()),
		"mail.example.org",
	)
	.with_suppression(SuppressionList::open(dir.path()).expect("open"))
	.with_delivery_log(DeliveryLog::open(dir.path(), 30));
	worker.pass().await.expect("pass");

	assert!(remote.received().is_empty(), "no remote connection");
	assert!(spool.list().expect("list").is_empty(), "entry removed");
	let records = DeliveryLog::open(dir.path(), 30)
		.list(None, |_| true)
		.expect("records");
	assert_eq!(records.len(), 1);
	assert_eq!(records[0].recipient, "bob@remote.example");
	assert_eq!(
		records[0].outcome,
		crate::storage::DeliveryOutcome::Suppressed
	);
}

#[tokio::test]
async fn a_tenants_list_is_listed_and_cleared_on_its_own() {
	let dir = tempfile::tempdir().expect("tempdir");
	let list = crate::queue::SuppressionList::open(dir.path()).expect("open");
	let text = format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['a.example']\n[[tenant]]\nname = 'acme'\ndomains = ['a.example']\n",
		dir.path()
	);
	let config = crate::config::Config::parse_text(&text, std::path::Path::new("mail.toml"))
		.expect("config");
	let rules = crate::queue::SuppressionRules::from_config(&config);
	list.publish_tenants(&rules).expect("publish");
	list.record_bounce(&rules, "alice@a.example", "gone@example.net", "550", 1)
		.expect("record");
	let app = router(test_state(dir.path(), 0));

	let (status, body) = request(
		&app,
		"GET",
		"/api/v1/suppression?tenant=acme",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["addresses"][0], "gone@example.net");
	// The shared list is a different list.
	let (_, body) = request(&app, "GET", "/api/v1/suppression", Some(TOKEN.as_str())).await;
	assert_eq!(body["addresses"].as_array().map(Vec::len), Some(0));

	let (status, _) = request(
		&app,
		"GET",
		"/api/v1/suppression?tenant=acme&account=alice",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST);

	let (status, _) = request(
		&app,
		"DELETE",
		"/api/v1/suppression/gone@example.net?tenant=acme",
		Some(TOKEN.as_str()),
	)
	.await;
	assert_eq!(status, StatusCode::OK);
	assert!(list.list_for_tenant("acme").is_empty());
}
