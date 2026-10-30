//! The zone lookup of the Cloudflare provider: an empty result is an absent
//! zone only in a reply that is valid and says it succeeded.

use super::*;

use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use std::sync::{Arc, Mutex};

/// What the mock answers to a zone lookup: the status and the body.
#[derive(Clone)]
struct Answer {
	status: u16,
	body: &'static str,
}

/// A valid reply that holds no zone.
const EMPTY: Answer = Answer {
	status: 200,
	body: r#"{"result": [], "success": true}"#,
};

/// A valid reply that says it failed, with the empty result a failed
/// reply carries.
const FAILED: Answer = Answer {
	status: 200,
	body: r#"{"result": [], "success": false}"#,
};

/// A reply that is not a successful one, whose body still looks like the
/// answer of a zone that is not there.
const UNAVAILABLE: Answer = Answer {
	status: 503,
	body: r#"{"result": [], "success": true}"#,
};

/// A reply that is not a successful one and says it failed.
const UNAVAILABLE_AND_FAILED: Answer = Answer {
	status: 503,
	body: r#"{"result": [], "success": false}"#,
};

#[derive(Default)]
struct MockState {
	answer: Option<Answer>,
}

type Shared = Arc<Mutex<MockState>>;

async fn list_zones(State(state): State<Shared>) -> axum::response::Response {
	let answer = state.lock().unwrap().answer.clone().unwrap_or(EMPTY);
	let status =
		axum::http::StatusCode::from_u16(answer.status).unwrap_or(axum::http::StatusCode::OK);
	(
		status,
		[(axum::http::header::CONTENT_TYPE, "application/json")],
		answer.body,
	)
		.into_response()
}

/// A provider whose zone lookup answers `answer`.
async fn lookup_mock(answer: Answer) -> (CloudflareProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState {
		answer: Some(answer),
	}));
	let app = Router::new()
		.route("/zones", get(list_zones))
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = CloudflareProvider::new(ScopedSecret::new("example.org", "tok"))
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	(provider, state)
}

#[tokio::test]
async fn a_reply_that_is_not_successful_is_not_an_absent_zone() {
	// The status says the request failed, and the body it carries says
	// the zone is not there. The status decides: the body of a reply
	// that is not an answer is never read.
	let (provider, _state) = lookup_mock(UNAVAILABLE).await;
	assert_eq!(
		provider
			.has_zone("example.org")
			.await
			.expect_err("the provider could not answer"),
		ProviderError::Remote("HTTP 503 Service Unavailable".to_string())
	);
}

#[tokio::test]
async fn a_reply_that_says_it_failed_is_not_an_absent_zone() {
	// The reply says it failed, and carries the same empty result a
	// successful reply carries when the zone is not there.
	let (provider, _state) = lookup_mock(FAILED).await;
	assert_eq!(
		provider
			.has_zone("example.org")
			.await
			.expect_err("the provider could not answer"),
		ProviderError::Remote("Cloudflare answered that the zone lookup failed".to_string())
	);
}

#[tokio::test]
async fn a_reply_that_is_not_successful_and_says_it_failed_is_not_an_absent_zone() {
	// Both signals say the request failed, and the empty result says
	// nothing about the zone.
	let (provider, _state) = lookup_mock(UNAVAILABLE_AND_FAILED).await;
	assert_eq!(
		provider
			.has_zone("example.org")
			.await
			.expect_err("the provider could not answer"),
		ProviderError::Remote("HTTP 503 Service Unavailable".to_string())
	);
}

#[tokio::test]
async fn an_empty_result_in_a_valid_reply_is_an_absent_zone() {
	// The reply is valid and says it succeeded, and holds no zone: the
	// zone is not there, and the search goes on to the parent.
	let (provider, _state) = lookup_mock(EMPTY).await;
	assert!(
		!provider
			.has_zone("example.org")
			.await
			.expect("the zone lookup answers"),
		"the account holds no zone with that name"
	);
}
