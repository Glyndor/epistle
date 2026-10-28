//! The refusal path of the ACME flow: what a CA's answer looks like from the
//! outside, and what the client does with it.
//!
//! The fake CA answers over real HTTP through the production transport, so
//! the whole chain is exercised: the JWS is signed, the answer comes back
//! with the status a CA would use, and the client has to read it.

use super::*;
use crate::acme::transport::HttpTransport;
use axum::extract::State;
use axum::http::{HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, head, post};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The problem document a CA sends when it refuses a request (RFC 8555 §6.7),
/// indented the way Boulder indents it: two spaces, and the numeric `status`
/// on its own line.
fn problem(kind: &str, detail: &str) -> String {
	format!("{{\n  \"type\": \"{kind}\",\n  \"detail\": \"{detail}\",\n  \"status\": 400\n}}\n")
}

/// What the fake CA answers to a POST.
#[derive(Clone)]
enum Answer {
	/// The resource was created: 201 with a `Location` header.
	Created(String),
	/// The CA refused: a non-2xx status and a problem document.
	Refused(u16, String),
	/// A 2xx answer that names no resource.
	WithoutLocation,
}

/// The fake CA: what it answers to each POST, and how many order posts it got.
#[derive(Clone)]
struct Ca {
	base: String,
	account: Answer,
	order: Answer,
	order_posts: Arc<AtomicUsize>,
}

async fn directory(State(ca): State<Ca>) -> String {
	format!(
		"{{\"newNonce\": \"{}/new-nonce\", \"newAccount\": \"{}/new-account\", \
		 \"newOrder\": \"{}/new-order\"}}",
		ca.base, ca.base, ca.base
	)
}

async fn nonce() -> Response {
	(
		StatusCode::OK,
		[(HeaderName::from_static("replay-nonce"), "nonce-1")],
		"",
	)
		.into_response()
}

async fn account(State(ca): State<Ca>) -> Response {
	answer(&ca.account)
}

async fn order(State(ca): State<Ca>) -> Response {
	ca.order_posts.fetch_add(1, Ordering::SeqCst);
	answer(&ca.order)
}

/// The answer of the fake CA: the resource, or the refusal.
fn answer(answer: &Answer) -> Response {
	let nonce = (HeaderName::from_static("replay-nonce"), "nonce-2");
	match answer {
		Answer::Created(location) => (
			StatusCode::CREATED,
			[
				nonce,
				(HeaderName::from_static("location"), location.as_str()),
			],
			"{}",
		)
			.into_response(),
		Answer::Refused(status, body) => (
			StatusCode::from_u16(*status).expect("status"),
			[nonce],
			body.clone(),
		)
			.into_response(),
		Answer::WithoutLocation => (StatusCode::CREATED, [nonce], "{}").into_response(),
	}
}

/// Spawn the fake CA and return its base URL and its order-post counter.
async fn fake_ca(account_answer: Answer, order_answer: Answer) -> (String, Arc<AtomicUsize>) {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind");
	let addr = listener.local_addr().expect("addr");
	let base = format!("http://{addr}");
	let order_posts = Arc::new(AtomicUsize::new(0));
	let ca = Ca {
		base: base.clone(),
		account: account_answer,
		order: order_answer,
		order_posts: order_posts.clone(),
	};
	let app = axum::Router::new()
		.route("/directory", get(directory))
		.route("/new-nonce", head(nonce))
		.route("/new-account", post(account))
		.route("/new-order", post(order))
		.with_state(ca);
	tokio::spawn(async move {
		axum::serve(listener, app).await.expect("serve");
	});
	(base, order_posts)
}

/// A client over the real transport, pointed at the fake CA.
async fn client(base: &str) -> AcmeClient<HttpTransport> {
	let (key, _) = AccountKey::generate().expect("key");
	let transport = HttpTransport::new().expect("transport");
	AcmeClient::connect(transport, key, &format!("{base}/directory"))
		.await
		.expect("connect")
}

#[tokio::test]
async fn a_refused_order_names_the_reason_instead_of_failing_to_parse() {
	// This is the answer that reached the issue: a CA that refuses the
	// order answers with a problem document, and the document was parsed as
	// the order that was asked for.
	let (base, _) = fake_ca(
		Answer::Created("https://acme.example/acct/1".into()),
		Answer::Refused(
			400,
			problem(
				"urn:ietf:params:acme:error:unauthorized",
				"No TXT record found at _acme-challenge.mail.example.org",
			),
		),
	)
	.await;
	let client = client(&base).await;
	client
		.register(&["admin@example.org".to_string()])
		.await
		.expect("register");

	let error = client
		.new_order(&["mail.example.org".to_string()])
		.await
		.expect_err("a refused order must fail");
	let message = error.to_string();
	assert!(
		message.contains("urn:ietf:params:acme:error:unauthorized"),
		"the reason must be named: {message}"
	);
	assert!(
		message.contains("No TXT record found"),
		"the detail must be named: {message}"
	);
	assert!(
		!message.contains("expected value"),
		"the JSON parse error must not stand in for the reason: {message}"
	);
}

#[tokio::test]
async fn a_refused_account_names_the_reason_and_stops_the_flow() {
	let (base, order_posts) = fake_ca(
		Answer::Refused(
			400,
			problem(
				"urn:ietf:params:acme:error:invalidContact",
				"Contact mailto:postmaster@example.org is not a valid contact",
			),
		),
		Answer::Created("https://acme.example/order/7".into()),
	)
	.await;
	let client = client(&base).await;

	let error = client
		.register(&["postmaster@example.org".to_string()])
		.await
		.expect_err("a refused account must fail");
	let message = error.to_string();
	assert!(
		message.contains("urn:ietf:params:acme:error:invalidContact"),
		"the reason must be named: {message}"
	);
	assert!(
		message.contains("is not a valid contact"),
		"the detail must be named: {message}"
	);
	assert!(
		!client.is_registered(),
		"no account was created, so none is held"
	);
	assert_eq!(
		order_posts.load(Ordering::SeqCst),
		0,
		"the flow must not go on to the order after the account was refused"
	);
}

#[tokio::test]
async fn an_account_that_was_not_created_fails_the_registration() {
	// A 2xx answer with no `Location` names no account: the CA accepted the
	// request and created nothing, and every later request would go out with
	// no `kid`.
	let (base, order_posts) = fake_ca(
		Answer::WithoutLocation,
		Answer::Created("https://acme.example/order/7".into()),
	)
	.await;
	let client = client(&base).await;

	let error = client
		.register(&["admin@example.org".to_string()])
		.await
		.expect_err("an account that was not created must fail");
	let message = error.to_string();
	assert!(
		message.contains("no account was created"),
		"the failure must say the account was not created: {message}"
	);
	assert!(
		!client.is_registered(),
		"no account was created, so none is held"
	);
	assert_eq!(
		order_posts.load(Ordering::SeqCst),
		0,
		"the flow must not go on to the order"
	);
}

#[tokio::test]
async fn an_answer_that_is_not_a_problem_document_is_reported_with_its_bytes() {
	// Something in front of the CA answered: an HTML error page, not a
	// document. The status and the bytes are all there is.
	let (base, _) = fake_ca(
		Answer::Created("https://acme.example/acct/1".into()),
		Answer::Refused(
			502,
			"<html><head><title>502 Bad Gateway</title></head></html>".into(),
		),
	)
	.await;
	let client = client(&base).await;
	client
		.register(&["admin@example.org".to_string()])
		.await
		.expect("register");

	let error = client
		.new_order(&["mail.example.org".to_string()])
		.await
		.expect_err("a refused order must fail");
	let message = error.to_string();
	assert!(
		message.contains("502"),
		"the status must be named: {message}"
	);
	assert!(
		message.contains("502 Bad Gateway"),
		"the bytes must be kept: {message}"
	);
}
