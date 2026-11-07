//! A redirect is not followed: the destination must receive nothing.
//!
//! The client asks the CA for a resource. An answer that names another one
//! would carry the signed request — and the account key it proves — to a
//! host the CA chose, which is the same hole a hostile URL in the
//! directory opens. The transport does not follow redirects, and a 3xx is
//! an error that says so.

use super::*;
use axum::extract::State;
use axum::http::{HeaderName, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, head, post};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The server that must not be reached: it counts the requests it gets.
#[derive(Clone)]
struct Destination {
	hits: Arc<AtomicUsize>,
}

async fn destination(State(state): State<Destination>) -> impl IntoResponse {
	state.hits.fetch_add(1, Ordering::SeqCst);
	(StatusCode::OK, "the destination was reached")
}

/// The server that answers with a redirect to the destination.
#[derive(Clone)]
struct Redirector {
	location: String,
	hits: Arc<AtomicUsize>,
}

async fn redirect(State(state): State<Redirector>) -> impl IntoResponse {
	state.hits.fetch_add(1, Ordering::SeqCst);
	(
		StatusCode::FOUND,
		[(HeaderName::from_static("location"), state.location)],
		"",
	)
}

/// Start the destination and the server that redirects to it. Returns their
/// base URLs and the counter of the destination.
async fn servers() -> (String, String, Arc<AtomicUsize>) {
	let hits = Arc::new(AtomicUsize::new(0));
	let destination_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let destination_addr = destination_listener.local_addr().expect("addr");
	let destination_app = axum::Router::new()
		.route("/target", get(destination))
		.with_state(Destination { hits: hits.clone() });
	tokio::spawn(async move {
		axum::serve(destination_listener, destination_app)
			.await
			.expect("serve");
	});

	let redirect_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let redirect_addr = redirect_listener.local_addr().expect("addr");
	let redirect_app = axum::Router::new()
		.route("/dir", get(redirect))
		.route("/nonce", head(redirect))
		.route("/order", post(redirect))
		.with_state(Redirector {
			location: format!("http://{destination_addr}/target"),
			hits: Arc::new(AtomicUsize::new(0)),
		});
	tokio::spawn(async move {
		axum::serve(redirect_listener, redirect_app)
			.await
			.expect("serve");
	});

	(
		format!("http://{redirect_addr}"),
		format!("http://{destination_addr}"),
		hits,
	)
}

#[tokio::test]
async fn a_get_that_is_redirected_fails_and_the_destination_receives_nothing() {
	let (base, _destination, hits) = servers().await;
	let transport = HttpTransport::new().expect("transport");

	let error = transport
		.get(&format!("{base}/dir"))
		.await
		.expect_err("a redirect must fail");
	let message = error.to_string();
	assert!(
		message.contains("302"),
		"the status must be named: {message}"
	);
	assert!(
		message.contains("redirect"),
		"the reason must be named: {message}"
	);
	assert_eq!(
		hits.load(Ordering::SeqCst),
		0,
		"the destination must not receive the request"
	);
}

#[tokio::test]
async fn a_nonce_that_is_redirected_fails_and_the_destination_receives_nothing() {
	let (base, _destination, hits) = servers().await;
	let transport = HttpTransport::new().expect("transport");

	let error = transport
		.new_nonce(&format!("{base}/nonce"))
		.await
		.expect_err("a redirect must fail");
	let message = error.to_string();
	assert!(
		message.contains("302"),
		"the status must be named: {message}"
	);
	assert_eq!(
		hits.load(Ordering::SeqCst),
		0,
		"the destination must not receive the request"
	);
}

#[tokio::test]
async fn a_post_that_is_redirected_fails_and_the_destination_receives_nothing() {
	let (base, _destination, hits) = servers().await;
	let transport = HttpTransport::new().expect("transport");

	let error = transport
		.post(&format!("{base}/order"), "signed-jws")
		.await
		.expect_err("a redirect must fail");
	let message = error.to_string();
	assert!(
		message.contains("302"),
		"the status must be named: {message}"
	);
	assert!(
		message.contains("redirect"),
		"the reason must be named: {message}"
	);
	assert_eq!(
		hits.load(Ordering::SeqCst),
		0,
		"the destination must not receive the signed request"
	);
}
