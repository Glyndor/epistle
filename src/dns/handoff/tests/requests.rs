//! The requests the serving side refuses because the file is not a request
//! it can use: another id, a field it does not know, a length over the
//! bound, a link where the request belongs, or a time in the future.
//!
//! Every case here writes a file the asking side would never write, and
//! every one of them has to end with nothing in the zone and an answer that
//! says why.

use super::super::{Server, requests_dir};
use super::{FakeZone, accepted, configured, domains, request, served, zones};

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

#[cfg(unix)]
#[tokio::test]
async fn a_requests_directory_that_is_a_link_is_not_followed() {
	let dir = tempfile::tempdir().expect("tempdir");
	let outside = tempfile::tempdir().expect("outside");
	let id = "0198a1b2-c3d4-7000-8000-000000000020";
	let root = dir.path().join("dns-handoff");
	std::fs::create_dir_all(&root).expect("root");
	std::os::unix::fs::symlink(outside.path(), requests_dir(&root)).expect("link");
	let bytes = serde_json::to_vec(&accepted(id)).expect("encode");
	std::fs::write(outside.path().join(id), bytes).expect("planted request");
	let zone = FakeZone::new();
	let server = Server::new(root, zone.clone(), zones(), domains(), configured());
	assert_eq!(server.serve_once().await, 0, "nothing was taken");
	let records = zone.records();
	assert!(records.is_empty(), "nothing was written: {records:?}");
	assert!(
		outside.path().join(id).exists(),
		"the request behind the link is left alone"
	);
}
