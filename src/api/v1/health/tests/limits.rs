//! How many runs may overlap, and that a run that ends gives its place back.

use std::sync::Arc;

use axum::http::{StatusCode, header};

use super::fixture::*;
use crate::api::HealthGate;

#[tokio::test]
async fn only_a_few_runs_overlap_and_a_third_is_told_to_come_back() {
	let world = world();
	let first = world.state.try_health_run().expect("a place");
	let second = world.state.try_health_run().expect("a place");
	assert!(world.state.try_health_run().is_none());
	for route in ["/api/v1/health", "/api/v1/health/config"] {
		let (status, headers, body) = get(&world.state, route, Some(HEALTHY)).await;
		assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{route}: {body}");
		assert!(
			headers.get(header::RETRY_AFTER).is_some(),
			"a 429 states the wait"
		);
	}
	drop(first);
	let (status, _, body) = get(&world.state, "/api/v1/health", Some(HEALTHY)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	drop(second);
}

/// A run, finished or dropped by a client that left, gives its place back.
#[tokio::test]
async fn the_places_come_back_after_runs_and_after_a_dropped_request() {
	let world = world();
	for _ in 0..6 {
		let (status, _, body) = get(&world.state, "/api/v1/health/antispam", Some(HEALTHY)).await;
		assert_eq!(status, StatusCode::OK, "{body}");
	}
	let state = world.state.clone();
	let request = tokio::spawn(async move { get(&state, "/api/v1/health", Some(HEALTHY)).await.0 });
	request.abort();
	let _ = request.await;
	let places = (world.state.try_health_run(), world.state.try_health_run());
	assert!(places.0.is_some() && places.1.is_some(), "a place was kept");
}

/// The answer follows the configuration the server runs with, not the file as
/// it is now: a file edited since, even into another valid configuration, is
/// not what the areas run on.
#[tokio::test]
async fn the_areas_run_on_the_live_configuration() {
	let world = world();
	let edited = format!(
		"{}[antispam]\nclamd_socket = \"/run/clamd.sock\"\n",
		std::fs::read_to_string(&world.path).expect("read")
	);
	std::fs::write(&world.path, edited).expect("overwrite");
	let (status, _, body) = get(&world.state, "/api/v1/health/antispam", Some(HEALTHY)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(
		!body.to_string().contains("content scanner wired in"),
		"the edited file was read: {body}"
	);
	let _ = &world.dir;
}

/// A client that leaves does not stop the run or free its place: the run is
/// a task of its own, and the place stays until the last thing it started
/// has returned. Clients that leave mid-run never make more than two runs
/// alive.
///
/// Two runs are held in the work they started, and the test acts only once
/// both have said they are in it: the third client is turned away, the first
/// two leave, and the places are still taken because the work is. Nothing is
/// waited for by time.
#[tokio::test]
async fn clients_that_leave_mid_run_neither_stop_it_nor_free_its_place() {
	let blocker = crate::cli::status::Blocker::closed();
	let world = build_with(true, |state| {
		state.with_health_blocker(Arc::clone(&blocker), None)
	});
	let mut requests = Vec::new();
	for _ in 0..2 {
		let state = world.state.clone();
		requests.push(tokio::spawn(async move {
			get(&state, "/api/v1/health/disk", Some(HEALTHY)).await.0
		}));
	}
	blocker.entered(2).await;
	// Both places are taken and both runs are in their work: a third client
	// is told to come back.
	let (status, _, body) = get(&world.state, "/api/v1/health/disk", Some(HEALTHY)).await;
	assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	for request in &requests {
		request.abort();
	}
	for request in requests {
		assert!(request.await.expect_err("dropped").is_cancelled());
	}
	assert!(
		world.state.try_health_run().is_none(),
		"the places were freed while the runs were still working"
	);
	assert_eq!(
		world.state.health_alive(),
		2,
		"the runs stopped with their clients"
	);
	assert!(world.state.health_peak() <= 2);
	blocker.open();
	blocker.left(2).await;
	world.state.health_places_free(2).await;
	assert_eq!(world.state.health_alive(), 0);
}

/// The limit is the server's: two listeners of one server share the places.
#[tokio::test]
async fn listeners_of_one_server_share_the_places() {
	let gate = HealthGate::new();
	let first = build_with(true, |state| state.with_health_gate(gate.clone()));
	let second = build_with(true, |state| state.with_health_gate(gate.clone()));
	let one = first.state.try_health_run().expect("a place");
	let two = second.state.try_health_run().expect("a place");
	for world in [&first, &second] {
		let (status, _, body) = get(&world.state, "/api/v1/health", Some(HEALTHY)).await;
		assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
	}
	drop((one, two));
	let (status, _, body) = get(&second.state, "/api/v1/health", Some(HEALTHY)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	// Servers that do not share a gate do not share places.
	let other = world();
	let _held = (other.state.try_health_run(), other.state.try_health_run());
	let (status, _, _) = get(&first.state, "/api/v1/health", Some(HEALTHY)).await;
	assert_eq!(status, StatusCode::OK);
}

/// An area cut off at its deadline leaves its blocking thread behind, and the
/// run keeps its place until that thread has returned: the request is answered
/// long before.
///
/// The clock of the test is paused and moved by hand, and the work is held
/// until the test opens it: once the work has said it is in, the test moves the
/// clock past the time the area gets, so the order is the one the test fixes
/// and no time is waited for. A paused clock does not move by itself while a
/// blocking thread runs, which is why the test moves it.
#[tokio::test(start_paused = true)]
async fn a_run_keeps_its_place_until_the_threads_of_a_cut_off_area_return() {
	let limit = std::time::Duration::from_millis(100);
	let blocker = crate::cli::status::Blocker::closed();
	let world = build_with(true, |state| {
		state.with_health_blocker(Arc::clone(&blocker), Some(limit))
	});
	let state = world.state.clone();
	let request =
		tokio::spawn(async move { get(&state, "/api/v1/health/disk", Some(HEALTHY)).await });
	blocker.entered(1).await;
	tokio::time::advance(limit * 2).await;
	let (status, _, body) = request.await.expect("answered");
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(body.to_string().contains("timed out"), "{body}");
	// The answer is out and the thread of the area is still in its work.
	let first = world.state.try_health_run();
	assert!(
		first.is_none() || world.state.try_health_run().is_none(),
		"the place was given back while a thread of the run was still working"
	);
	drop(first);
	blocker.open();
	blocker.left(1).await;
	world.state.health_places_free(2).await;
}
