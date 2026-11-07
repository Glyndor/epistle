//! The asking side: the request it writes, the answer it waits for and the
//! one it does not get.

use std::time::Duration;

use super::super::{Write, Writer, requests_dir, results_dir};
use super::{FakeZone, domains, zones};

/// The wait a test gives the answer.
const WAIT: Duration = Duration::from_millis(200);

/// The writer of a test, with a short wait.
fn writer(dir: &std::path::Path) -> Writer {
	Writer::new(dir).with_timeout(WAIT)
}

/// A certificates container that takes every request and answers it.
fn server(dir: &std::path::Path, zone: std::sync::Arc<FakeZone>) -> tokio::task::JoinHandle<()> {
	let server = super::super::Server::new(dir.join("dns-handoff"), zone, zones(), domains())
		.with_poll(Duration::from_millis(10));
	tokio::spawn(server.run())
}

#[tokio::test]
async fn the_request_is_written_owner_only_and_answered() {
	let dir = tempfile::tempdir().expect("tempdir");
	let zone = FakeZone::new();
	let serving = server(dir.path(), zone.clone());

	writer(dir.path())
		.perform(Write::dkim(
			"ed1._domainkey.example.org",
			"v=DKIM1; k=ed25519; p=abc",
		))
		.await
		.expect("the write");

	// The zone holds the record the request asked for.
	assert_eq!(
		zone.values("ed1._domainkey.example.org"),
		vec!["v=DKIM1; k=ed25519; p=abc".to_string()]
	);
	// The request is gone and the answer was read.
	let requests = std::fs::read_dir(requests_dir(&dir.path().join("dns-handoff")))
		.expect("requests dir")
		.count();
	assert_eq!(requests, 0, "the request was answered and removed");
	let results = std::fs::read_dir(results_dir(&dir.path().join("dns-handoff")))
		.expect("results dir")
		.count();
	assert_eq!(results, 0, "the answer was read and removed");
	serving.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn the_request_is_owner_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let writer = writer(dir.path());
	let waiting = tokio::spawn(async move {
		writer
			.perform(Write::dkim("ed1._domainkey.example.org", "v=DKIM1; p=abc"))
			.await
	});
	// The file is there while the write waits for its answer.
	let requests = requests_dir(&dir.path().join("dns-handoff"));
	let mut seen = false;
	for _ in 0..50 {
		if let Ok(entries) = std::fs::read_dir(&requests) {
			for entry in entries.flatten() {
				use std::os::unix::fs::PermissionsExt;
				let mode = entry.metadata().expect("stat").permissions().mode();
				assert_eq!(mode & 0o077, 0, "the request is owner-only");
				seen = true;
			}
		}
		if seen {
			break;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	assert!(seen, "the request was written");
	assert!(
		waiting.await.expect("the write").is_err(),
		"nobody answered"
	);
}

#[tokio::test]
async fn a_request_nobody_answers_fails_and_is_taken_back() {
	let dir = tempfile::tempdir().expect("tempdir");
	let error = writer(dir.path())
		.perform(Write::dkim("ed1._domainkey.example.org", "v=DKIM1; p=abc"))
		.await
		.expect_err("nobody answered");
	assert!(
		error.contains("did not answer"),
		"the reason names the missing answer: {error}"
	);
	// The request is taken back: the serving side must not write it later.
	let requests = std::fs::read_dir(requests_dir(&dir.path().join("dns-handoff")))
		.expect("requests dir")
		.count();
	assert_eq!(requests, 0, "the request was taken back");
}

#[tokio::test]
async fn an_answer_that_names_another_request_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().join("dns-handoff");
	std::fs::create_dir_all(results_dir(&root)).expect("results dir");
	// A certificates container that answers a request with an answer about
	// another one.
	let answering = tokio::spawn(async move {
		let requests = requests_dir(&root);
		let mut id = None;
		for _ in 0..100 {
			if let Ok(entries) = std::fs::read_dir(&requests) {
				for entry in entries.flatten() {
					id = Some(entry.file_name().to_string_lossy().into_owned());
				}
			}
			if id.is_some() {
				break;
			}
			tokio::time::sleep(Duration::from_millis(5)).await;
		}
		let id = id.expect("the request was written");
		let bytes = serde_json::to_vec(&super::super::Outcome::ok(
			"0198a1b2-c3d4-7000-8000-000000000009",
		))
		.expect("encode");
		std::fs::write(results_dir(&root).join(&id), bytes).expect("write");
	});
	let error = writer(dir.path())
		.perform(Write::dkim("ed1._domainkey.example.org", "v=DKIM1; p=abc"))
		.await
		.expect_err("the answer names another request");
	assert!(
		error.contains("names another request"),
		"the reason is carried: {error}"
	);
	answering.await.expect("the answering task");
}

#[tokio::test]
async fn a_refusal_is_reported_as_the_reason() {
	let dir = tempfile::tempdir().expect("tempdir");
	let zone = FakeZone::new();
	let serving = server(dir.path(), zone.clone());
	// A record of a domain this installation does not serve is refused by
	// the serving side, and the reason comes back.
	let error = writer(dir.path())
		.perform(Write::dkim("ed1._domainkey.evil.test", "v=DKIM1; p=abc"))
		.await
		.expect_err("the request is refused");
	assert!(
		error.contains("not a domain this installation serves"),
		"the reason is carried: {error}"
	);
	assert!(
		zone.records().is_empty(),
		"a refused request writes nothing: {:?}",
		zone.records()
	);
	serving.abort();
}

#[test]
fn the_sweep_removes_only_what_is_old() {
	let dir = tempfile::tempdir().expect("tempdir");
	let writer = Writer::new(dir.path());
	writer.prepare().expect("directories");
	let results = results_dir(&dir.path().join("dns-handoff"));
	let fresh = results.join("0198a1b2-c3d4-7000-8000-000000000030");
	let old = results.join("0198a1b2-c3d4-7000-8000-000000000031");
	std::fs::write(&fresh, b"{}").expect("fresh answer");
	let file = std::fs::File::create(&old).expect("old answer");
	file.set_modified(std::time::SystemTime::now() - Duration::from_secs(1000))
		.expect("backdate");
	writer.sweep();
	assert!(
		fresh.exists(),
		"an answer that is still being waited for stays"
	);
	assert!(!old.exists(), "an answer nobody read is removed");
}
