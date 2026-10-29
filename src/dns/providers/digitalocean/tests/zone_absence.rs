//! The zone lookup of the DigitalOcean provider: only the first access
//! decides whether the domain is there, and a failure after a valid page
//! is a failure of the provider, not an absent domain.

use super::*;

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::get;
use std::sync::{Arc, Mutex};

/// The absolute URL of the second page, as the answer of the first page
/// carries it.
#[derive(Default)]
struct MockState {
	next_url: Option<String>,
}

type Shared = Arc<Mutex<MockState>>;

/// The first page of the records of a domain, with a link to a second one.
async fn list_records(
	State(state): State<Shared>,
	Path(zone): Path<String>,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
	let s = state.lock().unwrap();
	if zone != "example.org" {
		return Err(axum::http::StatusCode::NOT_FOUND);
	}
	Ok(axum::Json(serde_json::json!({
		"domain_records": [],
		"links": { "pages": { "next": s.next_url.clone() } }
	})))
}

/// The second page, which the provider cannot read.
async fn second_page() -> axum::http::StatusCode {
	axum::http::StatusCode::NOT_FOUND
}

/// A provider whose listing has a second page the mock refuses to answer.
async fn mock() -> (DigitaloceanProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState::default()));
	let app = Router::new()
		.route("/v2/domains/{zone}/records", get(list_records))
		.route("/page2", get(second_page))
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	state.lock().unwrap().next_url = Some(format!("http://{addr}/page2"));
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = DigitaloceanProvider::new(ScopedSecret::new("example.org", "tok"))
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	(provider, state)
}

#[tokio::test]
async fn a_page_after_a_valid_one_is_not_a_domain_that_is_not_there() {
	// The first page answered, so the domain is there. The second page
	// answers 404, and that is a failure of the provider.
	let (provider, _state) = mock().await;
	let error = provider
		.list("example.org")
		.await
		.expect_err("the second page cannot be read");
	assert!(
		!matches!(error, ProviderError::ZoneNotFound(_)),
		"a page after a valid one is not an absent domain: {error}"
	);
}

#[tokio::test]
async fn the_zone_lookup_stops_when_a_later_page_cannot_be_read() {
	// The lookup may not answer that the zone is absent: the search would
	// go on to the parent and the record would land in a zone the
	// operator did not ask for.
	let (provider, _state) = mock().await;
	assert_eq!(
		provider
			.has_zone("example.org")
			.await
			.expect_err("the provider could not answer"),
		ProviderError::Remote("HTTP 404 Not Found".to_string())
	);
}
