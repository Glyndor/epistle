//! The zone is data in the request path: characters that mean something in a
//! URL must not change which resource the token is sent to.

use super::*;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::Uri;
use axum::routing::get;

type Seen = Arc<Mutex<Vec<(String, String, Option<String>)>>>;

async fn record(
	State(seen): State<Seen>,
	Path(zone): Path<String>,
	uri: Uri,
) -> axum::Json<serde_json::Value> {
	seen.lock().unwrap().push((
		zone,
		uri.path().to_string(),
		uri.query().map(str::to_string),
	));
	axum::Json(serde_json::json!([]))
}

#[tokio::test]
async fn zone_with_slash_and_query_characters_stays_one_path_segment() {
	let seen: Seen = Arc::default();
	let app = Router::new()
		.route("/domains/{zone}/rrsets/", get(record))
		.with_state(seen.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let zone = "evil/../x?admin=1#f";
	let provider = DesecProvider::new(ScopedSecret::new(zone, "tok"))
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	provider
		.list(zone)
		.await
		.expect("list reaches the mock on the escaped path");
	let seen = seen.lock().unwrap();
	assert_eq!(seen.len(), 1, "exactly one request reached the zone route");
	assert_eq!(seen[0].0, zone, "the zone arrives intact as one segment");
	assert_eq!(
		seen[0].1, "/domains/evil%2F..%2Fx%3Fadmin=1%23f/rrsets/",
		"the raw request path keeps the zone escaped"
	);
	assert_eq!(seen[0].2, None, "no query string was smuggled in");
}
