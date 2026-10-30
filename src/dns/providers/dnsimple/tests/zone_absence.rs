//! The zone lookup of the DNSimple provider: only the first access decides
//! whether the zone is there, and a failure after a valid page is a failure
//! of the provider, not an absent zone.

use super::*;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The pages the mock answers, and what it answers to the ones after the
/// first.
#[derive(Default)]
struct MockState {
	reads: usize,
}

type Shared = Arc<Mutex<MockState>>;

/// The first page of the records of a zone, which says there is a second
/// one.
async fn list_records(
	State(state): State<Shared>,
	Path(zone): Path<String>,
	Query(query): Query<HashMap<String, String>>,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
	let mut s = state.lock().unwrap();
	s.reads += 1;
	if zone != "example.org" {
		return Err(axum::http::StatusCode::NOT_FOUND);
	}
	let page: u32 = query
		.get("page")
		.and_then(|page| page.parse().ok())
		.unwrap_or(1);
	if page > 1 {
		// The second page cannot be read.
		return Err(axum::http::StatusCode::NOT_FOUND);
	}
	Ok(axum::Json(serde_json::json!({
		"data": [{
			"id": 1, "name": "_dmarc", "type": "TXT",
			"content": "v=DMARC1; p=none", "ttl": 3600
		}],
		"pagination": { "total_pages": 2, "total_entries": 1 }
	})))
}

/// A provider whose listing has a second page the mock refuses to answer.
async fn mock() -> (DnsimpleProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState::default()));
	let app = Router::new()
		.route("/acct/zones/{zone}/records", get(list_records))
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = DnsimpleProvider::new(ScopedSecret::new("example.org", "tok"), "acct")
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	(provider, state)
}

#[tokio::test]
async fn a_page_after_a_valid_one_is_not_a_zone_that_is_not_there() {
	// The first page answered, so the zone is there. The second page
	// answers 404, and that is a failure of the provider.
	let (provider, _state) = mock().await;
	let error = provider
		.list("example.org")
		.await
		.expect_err("the second page cannot be read");
	assert!(
		!matches!(error, ProviderError::ZoneNotFound(_)),
		"a page after a valid one is not an absent zone: {error}"
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
