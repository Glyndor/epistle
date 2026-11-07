//! The requests the serving side refuses: the other container is not
//! trusted.
//!
//! Every case here writes a request the rotation would never write, and
//! every one of them has to end with nothing in the zone and an answer that
//! says why.

use std::path::Path;

use super::super::{Operation, Outcome, Request, Server, requests_dir, results_dir};
use super::{FakeZone, domains, zones};

/// Write a request the way the asking side writes it.
fn request(dir: &Path, id: &str, request: &Request) {
	std::fs::create_dir_all(requests_dir(&dir.join("dns-handoff"))).expect("requests dir");
	let bytes = serde_json::to_vec(request).expect("encode");
	crate::storage::write_secret(&requests_dir(&dir.join("dns-handoff")).join(id), &bytes)
		.expect("write");
}

/// The answer to the request `id`.
fn answer(dir: &Path, id: &str) -> Outcome {
	let bytes = std::fs::read(results_dir(&dir.join("dns-handoff")).join(id)).expect("the answer");
	serde_json::from_slice(&bytes).expect("decode")
}

/// A request the serving side would accept, to change one thing at a time.
fn accepted(id: &str) -> Request {
	Request {
		id: id.to_string(),
		operation: Operation::Publish,
		name: "ed1._domainkey.example.org".to_string(),
		kind: "TXT".to_string(),
		value: "v=DKIM1; k=ed25519; p=abc".to_string(),
		ttl: 300,
		created_at: crate::dns::handoff::writer::now(),
	}
}

/// Serve the request in `dir` and answer with what the zone holds and what
/// the answer says.
async fn served(dir: &Path, id: &str) -> (Vec<(String, String)>, Outcome) {
	let zone = FakeZone::new();
	let server = Server::new(dir.join("dns-handoff"), zone.clone(), zones(), domains());
	server.serve_once().await;
	(zone.records(), answer(dir, id))
}

/// A request that is refused: nothing is written and the answer says why.
#[tokio::test]
async fn a_name_that_is_not_a_dkim_record_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000011";
	let mut hostile = accepted(id);
	hostile.name = "example.org".to_string();
	request(dir.path(), id, &hostile);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(!outcome.ok, "the request was refused");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("DKIM key record name")),
		"{outcome:?}"
	);
}

#[tokio::test]
async fn a_selector_no_rotation_makes_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000012";
	let mut hostile = accepted(id);
	hostile.name = "mail._domainkey.example.org".to_string();
	request(dir.path(), id, &hostile);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("not a selector a rotation makes")),
		"{outcome:?}"
	);
}

#[tokio::test]
async fn a_domain_this_installation_does_not_serve_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000013";
	let mut hostile = accepted(id);
	hostile.name = "ed1._domainkey.evil.test".to_string();
	request(dir.path(), id, &hostile);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("not a domain this installation serves")),
		"{outcome:?}"
	);
}

#[tokio::test]
async fn a_domain_outside_every_zone_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000014";
	let mut hostile = accepted(id);
	hostile.name = "ed1._domainkey.other.test".to_string();
	request(dir.path(), id, &hostile);
	// The domain is served, but no zone of this install holds it.
	let zone = FakeZone::new();
	let server = Server::new(
		dir.path().join("dns-handoff"),
		zone.clone(),
		zones(),
		vec!["other.test".to_string()],
	);
	server.serve_once().await;
	assert!(zone.records().is_empty(), "nothing was written");
	let outcome = answer(dir.path(), id);
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("none of the [dns] zones")),
		"{outcome:?}"
	);
}

#[tokio::test]
async fn a_record_that_is_not_a_txt_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000015";
	let mut hostile = accepted(id);
	hostile.kind = "A".to_string();
	request(dir.path(), id, &hostile);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("only a TXT record")),
		"{outcome:?}"
	);
}

#[tokio::test]
async fn a_value_that_is_not_a_dkim_record_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000016";
	let mut hostile = accepted(id);
	hostile.value = "v=spf1 -all".to_string();
	request(dir.path(), id, &hostile);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("not a DKIM key record")),
		"{outcome:?}"
	);
}

#[tokio::test]
async fn a_dkim_record_without_a_public_key_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000017";
	let mut hostile = accepted(id);
	hostile.value = "v=DKIM1; k=ed25519; p=".to_string();
	request(dir.path(), id, &hostile);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("carries no public key")),
		"{outcome:?}"
	);
}

#[tokio::test]
async fn a_time_to_live_of_zero_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000018";
	let mut hostile = accepted(id);
	hostile.ttl = 0;
	request(dir.path(), id, &hostile);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("not a time to live")),
		"{outcome:?}"
	);
}

#[tokio::test]
async fn a_time_to_live_above_the_bound_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000019";
	let mut hostile = accepted(id);
	hostile.ttl = crate::dns::handoff::MAX_TTL + 1;
	request(dir.path(), id, &hostile);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("not a time to live")),
		"{outcome:?}"
	);
}

#[tokio::test]
async fn a_withdrawal_that_carries_a_value_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000019";
	let mut hostile = accepted(id);
	hostile.operation = Operation::Withdraw;
	request(dir.path(), id, &hostile);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("whole record set")),
		"{outcome:?}"
	);
}

#[tokio::test]
async fn a_request_that_names_another_id_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-00000000001a";
	let mut hostile = accepted(id);
	hostile.id = "0198a1b2-c3d4-7000-8000-00000000001b".to_string();
	request(dir.path(), id, &hostile);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("another id")),
		"{outcome:?}"
	);
}

#[tokio::test]
async fn a_request_with_an_unknown_field_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-00000000001c";
	std::fs::create_dir_all(requests_dir(&dir.path().join("dns-handoff"))).expect("requests dir");
	let mut value = serde_json::to_value(accepted(id)).expect("encode");
	value.as_object_mut().expect("object").insert(
		"zone".to_string(),
		serde_json::Value::String("evil.test".to_string()),
	);
	std::fs::write(
		requests_dir(&dir.path().join("dns-handoff")).join(id),
		serde_json::to_vec(&value).expect("encode"),
	)
	.expect("write");
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(!outcome.ok, "the request was refused");
}

#[tokio::test]
async fn a_request_that_is_too_long_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-00000000001d";
	std::fs::create_dir_all(requests_dir(&dir.path().join("dns-handoff"))).expect("requests dir");
	let mut hostile = accepted(id);
	hostile.value = format!("v=DKIM1; p={}", "a".repeat(20_000));
	request(dir.path(), id, &hostile);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(!outcome.ok, "the request was refused");
}

#[cfg(unix)]
#[tokio::test]
async fn a_request_behind_a_link_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-00000000001e";
	let outside = dir.path().join("outside.json");
	let bytes = serde_json::to_vec(&accepted(id)).expect("encode");
	std::fs::write(&outside, bytes).expect("write");
	std::fs::create_dir_all(requests_dir(&dir.path().join("dns-handoff"))).expect("requests dir");
	std::os::unix::fs::symlink(
		&outside,
		requests_dir(&dir.path().join("dns-handoff")).join(id),
	)
	.expect("link");
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("not readable")),
		"{outcome:?}"
	);
}

#[tokio::test]
async fn a_request_that_claims_a_time_in_the_future_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-00000000001f";
	let mut hostile = accepted(id);
	hostile.created_at = crate::dns::handoff::writer::now() + 3600;
	request(dir.path(), id, &hostile);
	let (records, outcome) = served(dir.path(), id).await;
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outcome
			.error
			.as_deref()
			.is_some_and(|error| error.contains("time in the future")),
		"{outcome:?}"
	);
}
