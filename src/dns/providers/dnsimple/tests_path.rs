//! The account id and the zone are data in the request path: characters that
//! mean something in a URL must not change which resource the token reaches.

use super::*;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::Uri;
use axum::routing::get;

type Seen = Arc<Mutex<Vec<(String, String, String, Option<String>)>>>;

async fn records(
	State(seen): State<Seen>,
	Path((account, zone)): Path<(String, String)>,
	uri: Uri,
) -> axum::Json<serde_json::Value> {
	seen.lock().unwrap().push((
		account,
		zone,
		uri.path().to_string(),
		uri.query().map(str::to_string),
	));
	axum::Json(serde_json::json!({
		"data": [],
		"pagination": { "total_pages": 1 }
	}))
}

#[tokio::test]
async fn account_and_zone_with_slash_and_query_characters_stay_single_segments() {
	let seen: Seen = Arc::default();
	let app = Router::new()
		.route("/v2/{account}/zones/{zone}/records", get(records))
		.with_state(seen.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let account = "12/../34?x=1";
	let zone = "a b/c#f";
	let provider = DnsimpleProvider::new(ScopedSecret::new(zone, "tok"), account)
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}/v2")).unwrap());
	provider
		.list(zone)
		.await
		.expect("list reaches the mock on the escaped path");
	let seen = seen.lock().unwrap();
	assert_eq!(
		seen.len(),
		1,
		"exactly one request reached the records route"
	);
	assert_eq!(seen[0].0, account, "the account id arrives as one segment");
	assert_eq!(seen[0].1, zone, "the zone arrives as one segment");
	assert_eq!(
		seen[0].2, "/v2/12%2F..%2F34%3Fx=1/zones/a%20b%2Fc%23f/records",
		"the raw request path keeps both identifiers escaped"
	);
	assert_eq!(
		seen[0].3.as_deref(),
		Some("per_page=100&page=1"),
		"the only query is the pagination the provider adds"
	);
}
