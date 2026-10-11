//! Test helper: an in-process HTTP server that records the method and the
//! raw request target (path and query, still percent-encoded) of every request
//! and answers with canned JSON bodies in order. Provider tests use it to pin
//! what actually goes on the wire for identifiers that contain characters with
//! a meaning in a URL.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};

use crate::net::HttpsUrl;

/// The request lines seen so far, as `"METHOD /path?query"`.
pub(super) type Seen = Arc<Mutex<Vec<String>>>;

struct Script {
	seen: Seen,
	bodies: Vec<String>,
}

async fn record(
	State(script): State<Arc<Script>>,
	method: Method,
	uri: Uri,
) -> (StatusCode, String) {
	let mut seen = script.seen.lock().unwrap();
	let index = seen.len();
	seen.push(format!(
		"{method} {}",
		uri.path_and_query().map_or("", |pq| pq.as_str())
	));
	let body = script
		.bodies
		.get(index)
		.or(script.bodies.last())
		.cloned()
		.unwrap_or_else(|| "{}".to_string());
	(StatusCode::OK, body)
}

/// Start the server. `bodies[i]` answers the i-th request; the last one answers
/// every request after it. Returns the server's loopback base (no path) and the
/// shared record of requests.
pub(super) async fn probe(bodies: &[&str]) -> (HttpsUrl, Seen) {
	let seen = Seen::default();
	let script = Arc::new(Script {
		seen: seen.clone(),
		bodies: bodies.iter().map(|b| (*b).to_string()).collect(),
	});
	let app = Router::new().fallback(record).with_state(script);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let base = HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap();
	(base, seen)
}

/// `base` with `path` (starting with `/`) appended, for providers whose API
/// root carries a prefix such as `/v2`.
pub(super) fn under(base: &HttpsUrl, path: &str) -> HttpsUrl {
	HttpsUrl::loopback_http(&format!("{}{}", base.as_str().trim_end_matches('/'), path)).unwrap()
}
