//! Two changes made at the same time to one rrset must both survive.
//!
//! deSEC's PUT replaces the whole rrset, so a change reads the live rrset,
//! edits it and writes it back. Two ACME orders that publish a challenge at
//! `_acme-challenge` together read the same rrset, and the later write erases
//! the other's value. The fake server holds each read until a second one has
//! arrived, so unsynchronized changes see the same snapshot; changes that wait
//! for each other do not, and the server gives up waiting after a moment.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::Method;
use axum::routing::get;
use tokio::sync::Notify;

use super::*;

const NAME: &str = "_acme-challenge.example.org";

struct Zone {
	records: Mutex<Vec<String>>,
	reads: AtomicUsize,
	together: Notify,
}

async fn handle(
	State(zone): State<Arc<Zone>>,
	method: Method,
	body: String,
) -> axum::Json<serde_json::Value> {
	if method == Method::PUT {
		let put: serde_json::Value = serde_json::from_str(&body).expect("PUT body is JSON");
		*zone.records.lock().unwrap() = put[0]["records"]
			.as_array()
			.expect("records")
			.iter()
			.map(|r| r.as_str().expect("record").to_string())
			.collect();
		return axum::Json(serde_json::json!([]));
	}
	let snapshot = zone.records.lock().unwrap().clone();
	if zone.reads.fetch_add(1, Ordering::SeqCst) + 1 >= 2 {
		zone.together.notify_waiters();
	} else {
		let _ = tokio::time::timeout(Duration::from_millis(600), zone.together.notified()).await;
	}
	axum::Json(serde_json::json!([{
		"subname": "_acme-challenge",
		"type": "TXT",
		"ttl": 3600,
		"records": snapshot,
	}]))
}

async fn zone_with(initial: &[&str]) -> (DesecProvider, Arc<Zone>) {
	let zone = Arc::new(Zone {
		records: Mutex::new(initial.iter().map(|v| format!("\"{v}\"")).collect()),
		reads: AtomicUsize::new(0),
		together: Notify::new(),
	});
	let app = Router::new()
		.route("/domains/{zone}/rrsets/", get(handle).put(handle))
		.with_state(zone.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}", listener.local_addr().unwrap());
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = DesecProvider::new(ScopedSecret::new("example.org", "tok-concurrent"))
		.with_base(crate::net::HttpsUrl::loopback_http(&base).unwrap());
	(provider, zone)
}

fn values(zone: &Zone) -> BTreeSet<String> {
	zone.records
		.lock()
		.unwrap()
		.iter()
		.map(|r| r.trim_matches('"').to_string())
		.collect()
}

fn challenge(value: &str) -> DnsRecord {
	DnsRecord::new(NAME, RecordKind::Txt, value, 3600)
}

fn set(items: &[&str]) -> BTreeSet<String> {
	items.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn two_challenges_published_together_both_stay() {
	let (provider, zone) = zone_with(&[]).await;
	let (a, b) = tokio::join!(
		provider.upsert("example.org", challenge("token-apex")),
		provider.upsert("example.org", challenge("token-wildcard")),
	);
	a.expect("first publish");
	b.expect("second publish");
	assert_eq!(values(&zone), set(&["token-apex", "token-wildcard"]));
}

#[tokio::test]
async fn a_challenge_withdrawn_while_another_is_published_leaves_only_the_new_one() {
	let (provider, zone) = zone_with(&["old-token"]).await;
	let (published, withdrawn) = tokio::join!(
		provider.upsert("example.org", challenge("new-token")),
		provider.delete("example.org", challenge("old-token")),
	);
	published.expect("publish");
	withdrawn.expect("withdraw");
	assert_eq!(values(&zone), set(&["new-token"]));
}
