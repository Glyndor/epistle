//! Two changes made at the same time to one record set must both survive.
//!
//! GoDaddy replaces the whole set at a (type, name) on a PUT, so a change is
//! read, edited and written back. Two ACME orders that publish a challenge
//! at `_acme-challenge` together (an apex and its wildcard) read the same
//! set, and the later write erases the other's value. The fake server holds
//! each read until a second one has arrived, so unsynchronized changes see
//! the same snapshot; changes that wait for each other do not, and the
//! server gives up waiting after a moment.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::Method;
use axum::response::IntoResponse;
use axum::routing::get;
use tokio::sync::Notify;

use super::*;

const NAME: &str = "_acme-challenge.example.org";

struct Zone {
	set: Mutex<serde_json::Value>,
	reads: AtomicUsize,
	together: Notify,
}

async fn handle(
	State(zone): State<Arc<Zone>>,
	method: Method,
	body: String,
) -> axum::response::Response {
	match method {
		Method::GET => {
			let snapshot = zone.set.lock().unwrap().clone();
			if zone.reads.fetch_add(1, Ordering::SeqCst) + 1 >= 2 {
				zone.together.notify_waiters();
			} else {
				let _ = tokio::time::timeout(Duration::from_millis(600), zone.together.notified())
					.await;
			}
			axum::Json(snapshot).into_response()
		}
		Method::PUT => {
			*zone.set.lock().unwrap() = serde_json::from_str(&body).expect("PUT body is JSON");
			axum::http::StatusCode::OK.into_response()
		}
		Method::DELETE => {
			*zone.set.lock().unwrap() = serde_json::json!([]);
			axum::http::StatusCode::NO_CONTENT.into_response()
		}
		_ => axum::http::StatusCode::METHOD_NOT_ALLOWED.into_response(),
	}
}

fn element(value: &str) -> serde_json::Value {
	serde_json::json!({ "data": value, "ttl": 600 })
}

async fn zone_with(initial: serde_json::Value) -> (GodaddyProvider, Arc<Zone>) {
	let zone = Arc::new(Zone {
		set: Mutex::new(initial),
		reads: AtomicUsize::new(0),
		together: Notify::new(),
	});
	let app = Router::new()
		.route(
			"/domains/example.org/records/{kind}/{name}",
			get(handle).put(handle).delete(handle),
		)
		.with_state(zone.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}", listener.local_addr().unwrap());
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = GodaddyProvider::new("ak".into(), "sk".into(), "example.org".into())
		.with_base(crate::net::HttpsUrl::loopback_http(&base).unwrap());
	(provider, zone)
}

fn values(zone: &Zone) -> BTreeSet<String> {
	zone.set
		.lock()
		.unwrap()
		.as_array()
		.expect("the set is an array")
		.iter()
		.map(|e| {
			e["data"]
				.as_str()
				.expect("data")
				.trim_matches('"')
				.to_string()
		})
		.collect()
}

fn challenge(value: &str) -> DnsRecord {
	DnsRecord::new(NAME, RecordKind::Txt, value, 600)
}

#[tokio::test]
async fn two_challenges_published_together_both_stay() {
	let (provider, zone) = zone_with(serde_json::json!([])).await;
	let (a, b) = tokio::join!(
		provider.upsert("example.org", challenge("token-apex")),
		provider.upsert("example.org", challenge("token-wildcard")),
	);
	a.expect("first publish");
	b.expect("second publish");
	let expected: BTreeSet<String> = ["token-apex", "token-wildcard"]
		.into_iter()
		.map(String::from)
		.collect();
	assert_eq!(values(&zone), expected);
}

#[tokio::test]
async fn a_challenge_withdrawn_while_another_is_published_leaves_only_the_new_one() {
	let (provider, zone) = zone_with(serde_json::json!([element("old-token")])).await;
	let (published, withdrawn) = tokio::join!(
		provider.upsert("example.org", challenge("new-token")),
		provider.delete("example.org", challenge("old-token")),
	);
	published.expect("publish");
	withdrawn.expect("withdraw");
	let expected: BTreeSet<String> = ["new-token"].into_iter().map(String::from).collect();
	assert_eq!(values(&zone), expected);
}
