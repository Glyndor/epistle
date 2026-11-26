//! How many runs may overlap, and that a run that ends gives its place back.

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
/// has returned. Three clients that leave mid-run never make more than two
/// runs alive.
#[tokio::test]
async fn clients_that_leave_mid_run_neither_stop_it_nor_free_its_place() {
	let lag = std::time::Duration::from_millis(600);
	let world = build_with(true, |state| state.with_health_lag(lag, None));
	let mut requests = Vec::new();
	for _ in 0..3 {
		let state = world.state.clone();
		requests.push(tokio::spawn(async move {
			get(&state, "/api/v1/health", Some(HEALTHY)).await.0
		}));
		tokio::time::sleep(std::time::Duration::from_millis(30)).await;
	}
	for request in &requests {
		request.abort();
	}
	for request in requests {
		let _ = request.await;
	}
	assert!(
		world.state.try_health_run().is_none(),
		"the places were freed while the runs were still working"
	);
	assert!(
		world.state.health_alive() >= 1,
		"the runs stopped with their clients"
	);
	assert!(
		world.state.health_peak() <= 2,
		"{}",
		world.state.health_peak()
	);
	assert!(world.state.health_peak() >= 1);
	for _ in 0..100 {
		if world.state.try_health_run().is_some() {
			return;
		}
		tokio::time::sleep(std::time::Duration::from_millis(50)).await;
	}
	panic!("the places never came back");
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
#[tokio::test]
async fn a_run_keeps_its_place_until_the_threads_of_a_cut_off_area_return() {
	let world = build_with(true, |state| {
		state.with_health_lag(
			std::time::Duration::from_millis(1500),
			Some(std::time::Duration::from_millis(100)),
		)
	});
	let started = std::time::Instant::now();
	let (status, _, body) = get(&world.state, "/api/v1/health/disk", Some(HEALTHY)).await;
	assert_eq!(status, StatusCode::OK, "{body}");
	assert!(
		started.elapsed() < std::time::Duration::from_millis(1200),
		"the answer waited for the thread"
	);
	assert!(body.to_string().contains("timed out"), "{body}");
	let first = world.state.try_health_run();
	assert!(
		first.is_none() || world.state.try_health_run().is_none(),
		"the place was given back while a thread of the run was still working"
	);
	drop(first);
	for _ in 0..100 {
		let (one, two) = (world.state.try_health_run(), world.state.try_health_run());
		if one.is_some() && two.is_some() {
			return;
		}
		drop((one, two));
		tokio::time::sleep(std::time::Duration::from_millis(50)).await;
	}
	panic!("the places never came back");
}
