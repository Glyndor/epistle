//! A delivery that fails on this side (no STARTTLS where TLS is mandatory,
//! a TLSA lookup that fails) is retried with an enhanced status and one
//! fixed sentence, and the report to the sender carries both once the
//! message is given up.

use super::*;
use crate::storage::delivery_log::DeliveryLog;

/// Run `worker` past its give-up window and return the report it sent, and
/// the reason the delivery log kept for the retried attempt.
async fn give_up(dir: &std::path::Path, worker: Worker, bounces: &MemorySink) -> (String, String) {
	let created = created_at(&worker.spool);
	worker.set_now(created + 60);
	assert_eq!(worker.pass().await.expect("pass"), 0);
	assert_eq!(worker.spool.list().expect("list").len(), 1, "retried");
	assert!(bounces.messages().is_empty());
	worker.set_now(created + 3601);
	assert_eq!(worker.pass().await.expect("pass"), 0);
	let messages = bounces.messages();
	assert_eq!(messages.len(), 1, "one report");
	let body = String::from_utf8(messages[0].data.clone()).expect("ascii");
	let mut records = String::new();
	for file in std::fs::read_dir(dir.join("deliverylog"))
		.expect("log")
		.flatten()
	{
		records.push_str(&std::fs::read_to_string(file.path()).expect("day"));
	}
	let deferred = records
		.lines()
		.map(|line| serde_json::from_str::<crate::storage::DeliveryRecord>(line).expect("record"))
		.find(|record| record.outcome == crate::storage::DeliveryOutcome::Deferred)
		.expect("a deferral is logged");
	(body, deferred.reply.unwrap_or_default())
}

fn worker_for(
	dir: &std::path::Path,
	dns: Arc<dyn crate::spf::DnsLookup>,
) -> (Worker, Arc<MemorySink>, Arc<MemorySink>) {
	let remote = Arc::new(MemorySink::new());
	let bounces = Arc::new(MemorySink::new());
	let worker = Worker::new(
		spool_with_message(dir, "bob@remote.example"),
		Arc::new(LoopbackConnector {
			sink: remote.clone(),
			domain: "remote.example".to_string(),
		}),
		"mail.sender.example",
	)
	.with_dane(dns)
	.with_bounce_sink(bounces.clone() as Arc<dyn MessageSink>)
	.with_delivery_log(DeliveryLog::open(dir, 30))
	.with_max_age(3600);
	(worker, remote, bounces)
}

#[tokio::test]
async fn a_mandatory_tls_the_server_does_not_offer_is_x_7_10() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Any TLSA record makes STARTTLS mandatory; the loopback server offers none.
	let record = crate::dane::tlsa::TlsaRecord::from_parts(3, 1, 1, vec![0u8; 32]).expect("tlsa");
	let (worker, remote, bounces) = worker_for(dir.path(), Arc::new(DaneDns { record }));

	let (body, logged) = give_up(dir.path(), worker, &bounces).await;

	let sentence = "TLS is required but mx.remote.example does not offer STARTTLS";
	assert!(body.contains("Status: 5.7.10\r\n"), "{body}");
	assert!(
		body.contains(&format!("Diagnostic-Code: X-epistle; {sentence}\r\n")),
		"{body}"
	);
	assert_eq!(logged, format!("4.7.10 {sentence}"));
	assert!(remote.messages().is_empty(), "never sent in the clear");
}

#[tokio::test]
async fn a_tlsa_lookup_that_fails_is_x_7_5_and_never_a_downgrade() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (worker, remote, bounces) = worker_for(dir.path(), Arc::new(TlsaTempFailDns));

	let (body, logged) = give_up(dir.path(), worker, &bounces).await;

	let sentence = "the DANE TLSA records of mx.remote.example could not be looked up, so its \
	                TLS cannot be verified";
	assert!(body.contains("Status: 5.7.5\r\n"), "{body}");
	assert!(
		body.contains(&format!("Diagnostic-Code: X-epistle; {sentence}\r\n")),
		"{body}"
	);
	assert_eq!(logged, format!("4.7.5 {sentence}"));
	assert!(remote.messages().is_empty());
}
