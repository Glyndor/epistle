//! The zone name travels in the `search` query parameter: characters that
//! mean something in a query string must not add parameters.

use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Query, State};
use axum::http::Uri;
use axum::routing::get;

type Seen = Arc<Mutex<Vec<(Option<String>, HashMap<String, String>)>>>;

async fn zones(
	State(seen): State<Seen>,
	uri: Uri,
	Query(params): Query<HashMap<String, String>>,
) -> axum::Json<serde_json::Value> {
	seen.lock()
		.unwrap()
		.push((uri.query().map(str::to_string), params));
	axum::Json(serde_json::json!({ "Items": [] }))
}

#[tokio::test]
async fn zone_search_escapes_query_characters() {
	let seen: Seen = Arc::default();
	let app = Router::new()
		.route("/dnszone", get(zones))
		.with_state(seen.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let zone = "ex&search=evil.org#f";
	let provider = BunnyProvider::new(ScopedSecret::new(zone, "key"))
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	let err = provider
		.list(zone)
		.await
		.expect_err("the mock has no such zone");
	assert_eq!(
		err,
		ProviderError::Remote(format!("zone not found: {zone}"))
	);
	let seen = seen.lock().unwrap();
	assert_eq!(seen.len(), 1, "exactly one zone search was sent");
	assert_eq!(
		seen[0].0.as_deref(),
		Some("search=ex%26search%3Devil.org%23f"),
		"the raw query carries the zone as one escaped value"
	);
	assert_eq!(seen[0].1.len(), 1, "no extra query parameter was injected");
	assert_eq!(seen[0].1.get("search").map(String::as_str), Some(zone));
}
