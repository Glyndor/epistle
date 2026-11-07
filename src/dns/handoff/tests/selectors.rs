//! The selectors the serving side accepts: the ones a rotation makes and
//! the ones the operator configured.
//!
//! The configured ones matter as much as the rotation's: the selector in
//! `[dkim]` signs until the first rotation replaces it, and the one in a
//! `[[dkim.domain]]` entry signs until that domain rotates. A rotation
//! publishes and retires them, so a hand-off that refused them would leave
//! the records of the selector in service published forever.

use std::path::Path;

use super::super::{Operation, Outcome, Request, Server};
use super::{FakeZone, accepted, answer, configured, domains, request, zones};

/// Serve the request in `dir` and answer with what the zone holds and what
/// the answer says.
async fn served(dir: &Path, id: &str) -> (Vec<(String, String)>, Outcome) {
	let zone = FakeZone::new();
	let server = Server::new(
		dir.join("dns-handoff"),
		zone.clone(),
		zones(),
		domains(),
		configured(),
	);
	server.serve_once().await;
	(zone.records(), answer(dir, id))
}

/// A request for the selector the operator configured in `[dkim]`.
fn configured_request(id: &str, selector: &str, operation: Operation) -> Request {
	let mut request = accepted(id);
	request.name = format!("{selector}._domainkey.example.org");
	request.operation = operation;
	request.value = match operation {
		Operation::Publish => "v=DKIM1; k=ed25519; p=abc".to_string(),
		Operation::Withdraw => String::new(),
	};
	request
}

#[tokio::test]
async fn a_configured_selector_is_published() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000030";
	let written = configured_request(id, "mail", Operation::Publish);
	request(dir.path(), id, &written);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(outcome.ok, "the request was served: {outcome:?}");
	assert_eq!(
		records,
		vec![(
			"mail._domainkey.example.org".to_string(),
			"v=DKIM1; k=ed25519; p=abc".to_string()
		)],
		"the record was published: {records:?}"
	);
}

#[tokio::test]
async fn a_configured_selector_is_retired() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000031";
	let zone = FakeZone::new();
	zone.seed("custom._domainkey.example.org", "v=DKIM1; k=ed25519; p=abc");
	let written = configured_request(id, "custom", Operation::Withdraw);
	request(dir.path(), id, &written);
	let server = Server::new(
		dir.path().join("dns-handoff"),
		zone.clone(),
		zones(),
		domains(),
		configured(),
	);
	server.serve_once().await;
	assert!(
		zone.values("custom._domainkey.example.org").is_empty(),
		"the record is gone: {:?}",
		zone.records()
	);
	assert!(answer(dir.path(), id).ok, "the request was served");
}

#[tokio::test]
async fn a_selector_nothing_uses_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000032";
	let written = configured_request(id, "random", Operation::Publish);
	request(dir.path(), id, &written);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("not a selector this installation uses")),
		"{outcome:?}"
	);
}
