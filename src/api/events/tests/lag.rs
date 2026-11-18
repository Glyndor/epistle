//! A reader that falls behind is dropped, events are coalesced and an idle
//! stream stays alive.

use std::time::Duration;

use super::base::{ADMIN, Got, QUIET, SOON, app, fast, state, stream};
use crate::api::EventLimits;
use crate::api::events::topic::{Reach, Topic};

fn burst(state: &crate::api::ApiState, topic: Topic, times: usize) {
	state
		.events()
		.publish((0..times).map(|_| (topic, Reach::Everyone)).collect());
}

#[tokio::test]
async fn a_reader_that_falls_behind_the_ring_is_dropped() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(
		dir.path(),
		EventLimits {
			ring: 4,
			look: Duration::from_millis(300),
			..fast()
		},
	);
	let app = app(&state);
	let mut slow = stream(&app, ADMIN, None).await;
	// More than the ring holds before the reader looks: nothing is buffered
	// for it, the ring forgets, and the reader is cut.
	burst(&state, Topic::Queue, 10);
	assert!(
		slow.event(SOON).await.is_none(),
		"a lapped reader got events"
	);
	assert_eq!(state.events().open_streams(), 0, "its slot came back");
	assert!(state.events().held() <= 4, "the ring is bounded");
}

#[tokio::test]
async fn a_reader_inside_the_ring_is_not_dropped() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(
		dir.path(),
		EventLimits {
			ring: 4,
			look: Duration::from_millis(300),
			..fast()
		},
	);
	let app = app(&state);
	let mut reader = stream(&app, ADMIN, None).await;
	burst(&state, Topic::Queue, 4);
	let frame = reader.event(SOON).await.expect("an event");
	assert_eq!(frame.event.as_deref(), Some("queue"));
}

#[tokio::test]
async fn a_burst_is_one_event_per_topic() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(
		dir.path(),
		EventLimits {
			look: Duration::from_millis(300),
			..fast()
		},
	);
	let app = app(&state);
	let mut reader = stream(&app, ADMIN, None).await;
	burst(&state, Topic::Queue, 40);
	burst(&state, Topic::Status, 3);
	burst(&state, Topic::Queue, 2);
	let frames = reader.collect(QUIET * 2).await;
	let names: Vec<_> = frames.iter().filter_map(|f| f.event.as_deref()).collect();
	assert_eq!(names, ["status", "queue"], "{frames:?}");
	// Each carries the id of the last notification of its topic: the queue
	// was last at 45, the status at 43.
	let seq = |i: usize| frames[i].id.as_deref().unwrap().split_once('.').unwrap().1;
	assert_eq!((seq(0), seq(1)), ("43", "45"));
}

#[tokio::test]
async fn an_idle_stream_sends_a_heartbeat_comment() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state(dir.path(), fast());
	let app = app(&state);
	let mut reader = stream(&app, ADMIN, None).await;
	match reader.next(SOON).await {
		Got::Frame(frame) => {
			assert!(frame.comment, "{frame:?}");
			assert!(frame.event.is_none() && frame.data.is_none());
		}
		_ => panic!("no heartbeat on an idle stream"),
	}
	// More of them, and still no event.
	match reader.next(SOON).await {
		Got::Frame(frame) => assert!(frame.comment),
		_ => panic!("the heartbeat stopped"),
	}
}
