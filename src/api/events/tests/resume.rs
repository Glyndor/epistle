//! Resuming with `Last-Event-ID`.

use std::time::Duration;

use super::base::{ADMIN, QUIET, SOON, app, enqueue, fast, settle, state, stream, suppress};

const ALL: [&str; 6] = [
	"accounts",
	"deliveries",
	"domains",
	"queue",
	"status",
	"suppression",
];

fn sorted(mut names: Vec<String>) -> Vec<String> {
	names.sort();
	names
}

#[tokio::test]
async fn a_reconnect_replays_only_what_came_after_the_id() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	// A second stream keeps the sampler running while the first is away.
	let mut keeper = stream(&app, ADMIN, None).await;
	let mut first = stream(&app, ADMIN, None).await;
	settle().await;
	suppress(dir.path(), "a@elsewhere.example");
	let seen = first.event(SOON).await.expect("a suppression event");
	assert_eq!(seen.event.as_deref(), Some("suppression"));
	let id = seen.id.expect("every event has an id");
	drop(first);
	enqueue(&state, "alice@a.example", "someone@elsewhere.example");
	// The keeper saw both; wait until the queue change is in the ring.
	let told = keeper.names(QUIET * 2).await;
	assert!(told.iter().any(|name| name == "queue"), "{told:?}");
	let mut back = stream(&app, ADMIN, Some(&id)).await;
	let replayed = back.collect(QUIET).await;
	let names = sorted(replayed.iter().filter_map(|f| f.event.clone()).collect());
	assert_eq!(names, ["queue", "status"], "only what followed {id}");
	let seq = |id: &str| {
		id.split_once('.')
			.expect("boot.seq")
			.1
			.parse::<u64>()
			.expect("seq")
	};
	for frame in replayed {
		assert!(seq(frame.id.as_deref().expect("id")) > seq(&id));
	}
}

#[tokio::test]
async fn a_reconnect_with_nothing_missed_gets_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut keeper = stream(&app, ADMIN, None).await;
	let mut first = stream(&app, ADMIN, None).await;
	settle().await;
	suppress(dir.path(), "a@elsewhere.example");
	let id = first.event(SOON).await.expect("event").id.expect("id");
	assert!(!keeper.names(QUIET).await.is_empty());
	let mut back = stream(&app, ADMIN, Some(&id)).await;
	assert!(back.names(QUIET).await.is_empty());
}

#[tokio::test]
async fn an_id_from_before_nobody_listened_means_refetch_everything() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut first = stream(&app, ADMIN, None).await;
	settle().await;
	suppress(dir.path(), "a@elsewhere.example");
	let id = first.event(SOON).await.expect("event").id.expect("id");
	drop(first);
	let deadline = tokio::time::Instant::now() + SOON;
	while state.events().is_sampling() {
		assert!(
			tokio::time::Instant::now() < deadline,
			"sampler kept running"
		);
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	// Changes made now are seen by no one: the ring has a hole.
	enqueue(&state, "alice@a.example", "someone@elsewhere.example");
	let mut back = stream(&app, ADMIN, Some(&id)).await;
	assert_eq!(sorted(back.names(QUIET).await), ALL);
}

#[tokio::test]
async fn an_id_the_server_cannot_replay_means_refetch_everything() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut keeper = stream(&app, ADMIN, None).await;
	settle().await;
	suppress(dir.path(), "a@elsewhere.example");
	let id = keeper.event(SOON).await.expect("event").id.expect("id");
	let (boot, seq) = id.split_once('.').expect("boot.seq");
	let seq: u64 = seq.parse().expect("seq");
	for forged in [
		"garbage".to_string(),
		String::new(),
		"1.1".to_string(),
		format!("{boot}.{}", seq + 1000),
		format!("{boot}.x"),
		format!("x.{seq}"),
	] {
		let mut back = stream(&app, ADMIN, Some(&forged)).await;
		assert_eq!(sorted(back.names(QUIET).await), ALL, "id {forged:?}");
	}
}

#[tokio::test]
async fn a_fresh_stream_is_told_nothing_that_came_before_it() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut keeper = stream(&app, ADMIN, None).await;
	settle().await;
	suppress(dir.path(), "a@elsewhere.example");
	assert!(!keeper.names(QUIET).await.is_empty());
	let mut fresh = stream(&app, ADMIN, None).await;
	assert!(fresh.names(QUIET).await.is_empty());
}

#[tokio::test]
async fn event_ids_are_opaque_and_increase() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut reader = stream(&app, ADMIN, None).await;
	settle().await;
	suppress(dir.path(), "a@elsewhere.example");
	let first = reader.event(SOON).await.expect("event");
	enqueue(&state, "alice@a.example", "someone@elsewhere.example");
	let rest = reader.collect(QUIET * 2).await;
	let mut last = 0u64;
	for frame in std::iter::once(first).chain(rest) {
		let id = frame.id.expect("id");
		let (boot, seq) = id.split_once('.').expect("boot.seq");
		assert!(boot.chars().all(|c| c.is_ascii_digit()), "{id}");
		let seq: u64 = seq.parse().expect("seq");
		assert!(seq > last, "ids go up: {last} then {seq}");
		last = seq;
	}
}
