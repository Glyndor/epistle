//! The serving side: what it does with a request, and what it answers.

use std::path::Path;

use super::super::{Operation, Outcome, Request, Server, requests_dir, results_dir};
use super::{FakeZone, domains, zones};

/// The hand-off directory of a test.
fn root(dir: &Path) -> std::path::PathBuf {
	dir.join("dns-handoff")
}

/// Write a request the way the asking side writes it.
fn request(dir: &Path, id: &str, request: Request) {
	std::fs::create_dir_all(requests_dir(&root(dir))).expect("requests dir");
	let bytes = serde_json::to_vec(&request).expect("encode");
	crate::storage::write_secret(&requests_dir(&root(dir)).join(id), &bytes).expect("write");
}

/// The answer to the request `id`.
fn answer(dir: &Path, id: &str) -> Outcome {
	let bytes = std::fs::read(results_dir(&root(dir)).join(id)).expect("the answer");
	serde_json::from_slice(&bytes).expect("decode")
}

/// A request the serving side accepts.
fn accepted(id: &str, name: &str, operation: Operation, created_at: u64) -> Request {
	Request {
		id: id.to_string(),
		operation,
		name: name.to_string(),
		kind: "TXT".to_string(),
		value: match operation {
			Operation::Publish => "v=DKIM1; k=ed25519; p=abc".to_string(),
			Operation::Withdraw => String::new(),
		},
		ttl: 300,
		created_at,
	}
}

#[tokio::test]
async fn a_publication_is_performed_and_answered() {
	let dir = tempfile::tempdir().expect("tempdir");
	let zone = FakeZone::new();
	let id = "0198a1b2-c3d4-7000-8000-000000000001";
	request(
		dir.path(),
		id,
		accepted(
			id,
			"ed1._domainkey.example.org",
			Operation::Publish,
			crate::dns::handoff::writer::now(),
		),
	);
	let server = Server::new(root(dir.path()), zone.clone(), zones(), domains());
	assert_eq!(server.serve_once().await, 1);
	assert_eq!(
		zone.values("ed1._domainkey.example.org"),
		vec!["v=DKIM1; k=ed25519; p=abc".to_string()]
	);
	let outcome = answer(dir.path(), id);
	assert!(outcome.ok, "the write happened: {outcome:?}");
	// The request is gone: it was answered.
	let left = std::fs::read_dir(requests_dir(&root(dir.path())))
		.expect("requests dir")
		.count();
	assert_eq!(left, 0, "the request was removed");
}

#[tokio::test]
async fn a_withdrawal_is_performed_and_answered() {
	let dir = tempfile::tempdir().expect("tempdir");
	let zone = FakeZone::new();
	zone.seed("ed1._domainkey.example.org", "v=DKIM1; k=ed25519; p=abc");
	let id = "0198a1b2-c3d4-7000-8000-000000000002";
	request(
		dir.path(),
		id,
		accepted(
			id,
			"ed1._domainkey.example.org",
			Operation::Withdraw,
			crate::dns::handoff::writer::now(),
		),
	);
	let server = Server::new(root(dir.path()), zone.clone(), zones(), domains());
	server.serve_once().await;
	assert!(
		zone.values("ed1._domainkey.example.org").is_empty(),
		"the record is gone"
	);
	assert!(answer(dir.path(), id).ok);
}

#[tokio::test]
async fn a_provider_failure_is_answered_with_the_reason() {
	let dir = tempfile::tempdir().expect("tempdir");
	let zone = FakeZone::new();
	zone.fail();
	let id = "0198a1b2-c3d4-7000-8000-000000000003";
	request(
		dir.path(),
		id,
		accepted(
			id,
			"ed1._domainkey.example.org",
			Operation::Publish,
			crate::dns::handoff::writer::now(),
		),
	);
	let server = Server::new(root(dir.path()), zone, zones(), domains());
	server.serve_once().await;
	let outcome = answer(dir.path(), id);
	assert!(!outcome.ok, "the write did not happen");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("provider request failed")),
		"the category is carried: {outcome:?}"
	);
}

#[tokio::test]
async fn an_expired_request_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let zone = FakeZone::new();
	let id = "0198a1b2-c3d4-7000-8000-000000000004";
	let old = crate::dns::handoff::writer::now()
		.saturating_sub(crate::dns::handoff::MAX_REQUEST_AGE.as_secs() + 10);
	request(
		dir.path(),
		id,
		accepted(id, "ed1._domainkey.example.org", Operation::Publish, old),
	);
	let server = Server::new(root(dir.path()), zone.clone(), zones(), domains());
	server.serve_once().await;
	let outcome = answer(dir.path(), id);
	assert!(!outcome.ok, "the request was too old");
	assert!(
		zone.records().is_empty(),
		"an expired request writes nothing: {:?}",
		zone.records()
	);
}

#[tokio::test]
async fn the_requests_are_served_in_the_order_they_were_made() {
	let dir = tempfile::tempdir().expect("tempdir");
	let zone = FakeZone::new();
	let now = crate::dns::handoff::writer::now();
	// The newer request is written first, so the directory lists them in
	// the wrong order.
	let newer = "0198a1b2-c3d4-7000-8000-000000000006";
	let older = "0198a1b2-c3d4-7000-8000-000000000005";
	request(
		dir.path(),
		newer,
		accepted(newer, "ed2._domainkey.example.org", Operation::Publish, now),
	);
	request(
		dir.path(),
		older,
		accepted(
			older,
			"ed1._domainkey.example.org",
			Operation::Publish,
			now - 10,
		),
	);
	let server = Server::new(root(dir.path()), zone.clone(), zones(), domains());
	server.serve_once().await;
	let names: Vec<String> = zone.records().into_iter().map(|(name, _)| name).collect();
	assert_eq!(
		names,
		vec![
			"ed1._domainkey.example.org".to_string(),
			"ed2._domainkey.example.org".to_string()
		],
		"the older request was served first"
	);
}

#[tokio::test]
async fn a_request_that_is_not_readable_is_answered_and_removed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let zone = FakeZone::new();
	let id = "0198a1b2-c3d4-7000-8000-000000000007";
	std::fs::create_dir_all(requests_dir(&root(dir.path()))).expect("requests dir");
	std::fs::write(requests_dir(&root(dir.path())).join(id), b"not json").expect("write");
	let server = Server::new(root(dir.path()), zone.clone(), zones(), domains());
	server.serve_once().await;
	let outcome = answer(dir.path(), id);
	assert!(!outcome.ok, "the request was refused");
	assert!(
		zone.records().is_empty(),
		"nothing was written: {:?}",
		zone.records()
	);
	let left = std::fs::read_dir(requests_dir(&root(dir.path())))
		.expect("requests dir")
		.count();
	assert_eq!(left, 0, "the request was removed");
}

#[tokio::test]
async fn a_file_that_is_not_a_request_is_left_alone() {
	let dir = tempfile::tempdir().expect("tempdir");
	let zone = FakeZone::new();
	std::fs::create_dir_all(requests_dir(&root(dir.path()))).expect("requests dir");
	// The temporary file of a request that is being written.
	let temporary = requests_dir(&root(dir.path())).join(".0198.tmp");
	std::fs::write(&temporary, b"half a request").expect("write");
	let server = Server::new(root(dir.path()), zone, zones(), domains());
	assert_eq!(server.serve_once().await, 0, "nothing was taken");
	assert!(
		temporary.exists(),
		"a file the asking side is writing is not removed"
	);
}
