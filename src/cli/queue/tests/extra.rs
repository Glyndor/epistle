//! `epistle queue remove` keeps what the sender attached to the message.

use super::base::webhook_receiver;
use super::*;
use crate::cli::queue::QueueCli;
use crate::smtp::session::AcceptedMessage;
use std::collections::BTreeMap;

const BODY: &str = "Subject: hi\r\n\r\nbody\r\n";

/// A message stored with a correlation map, as `POST /api/v1/send` does.
fn spool_with_extra() -> (tempfile::TempDir, Uuid) {
	let dir = tempfile::tempdir().expect("tempdir");
	let spool = FsSpool::open(dir.path()).expect("spool");
	let extra = BTreeMap::from([("order".to_string(), "A-1042".to_string())]);
	let id = spool
		.store(
			&AcceptedMessage {
				reverse_path: "alice@example.org".into(),
				recipients: vec!["bob@remote.example".into()],
				data: BODY.as_bytes().to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&extra,
		)
		.expect("store");
	(dir, id)
}

#[tokio::test]
async fn remove_keeps_the_extra_of_the_message_on_the_record_and_the_event() {
	let (url, captured) = webhook_receiver().await;
	let (dir, id) = spool_with_extra();
	let webhook = std::sync::Arc::new(crate::webhook::Webhook::new(&url, None).expect("webhook"));
	let mut out = Vec::new();
	let code = run(
		dir.path(),
		None,
		30,
		Some(QueueCli::Remove { id, yes: true }),
		false,
		1_700_000_000,
		Some(&webhook),
		&mut out,
	);
	assert_eq!(code, ExitCode::SUCCESS);
	let records = crate::storage::DeliveryLog::open(dir.path(), 30)
		.list(None, |_| true)
		.expect("log");
	assert_eq!(records.len(), 1);
	assert_eq!(
		records[0].extra.get("order").map(String::as_str),
		Some("A-1042")
	);
	for _ in 0..200 {
		if !captured.lock().expect("lock").is_empty() {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_millis(10)).await;
	}
	let bodies = captured.lock().expect("lock").clone();
	let body = bodies
		.iter()
		.find(|body| body.contains("\"event\":\"canceled\""))
		.expect("a canceled body");
	let event: serde_json::Value = serde_json::from_str(body).expect("json");
	assert_eq!(event["extra"]["order"], "A-1042");
}
