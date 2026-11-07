//! The requests the serving side refuses: the other container is not
//! trusted.
//!
//! Every case here writes a request the rotation would never write, and
//! every one of them has to end with nothing in the zone and an answer that
//! says why.

use std::path::Path;

use super::super::{Operation, Outcome, Server};
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
async fn a_selector_nothing_uses_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = "0198a1b2-c3d4-7000-8000-000000000012";
	let mut hostile = accepted(id);
	hostile.name = "random._domainkey.example.org".to_string();
	request(dir.path(), id, &hostile);
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
		configured(),
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
	let id = "0198a1b2-c3d4-7000-8000-00000000001a";
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
