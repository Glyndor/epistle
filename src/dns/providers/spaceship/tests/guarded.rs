//! The guarded write of the Spaceship provider, against a mock that keeps
//! its records as a list, adds what a save carries and removes what a
//! removal names, value included, as the API does.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::routing::get;

use super::*;
use crate::dns::publish::provider::{Change, Guard, Precondition, Receipt};

const ZONE: &str = "example.org";
const NAME: &str = "mail.example.org";

#[derive(Default)]
struct Zone {
	records: Vec<serde_json::Value>,
	/// What was written, in order: `PUT <address>` or `DELETE <address>`.
	writes: Vec<String>,
	/// The `force` flag of every save.
	forces: Vec<bool>,
}

type Held = Arc<Mutex<Zone>>;

fn a_record(name: &str, address: &str) -> serde_json::Value {
	serde_json::json!({"name": name, "type": "A", "address": address, "ttl": 300})
}

/// The zone of a case: the records at `mail`, a record at another name and
/// a TXT at the same one. A change must leave the other two alone.
fn zone_records(addresses: &[&str]) -> Vec<serde_json::Value> {
	let mut records = vec![
		a_record("other", "198.51.100.1"),
		serde_json::json!({"name": "mail", "type": "TXT", "value": "v=spf1 -all", "ttl": 300}),
		serde_json::json!({"name": "@", "type": "NS", "nameserver": "ns1.example.net", "ttl": 300}),
	];
	records.extend(addresses.iter().map(|a| a_record("mail", a)));
	records
}

async fn list(State(zone): State<Held>) -> axum::Json<serde_json::Value> {
	let items = zone.lock().unwrap().records.clone();
	axum::Json(serde_json::json!({"items": items, "total": items.len()}))
}

async fn save(State(zone): State<Held>, body: String) -> axum::http::StatusCode {
	let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
	let mut zone = zone.lock().unwrap();
	zone.forces.push(parsed["force"].as_bool().unwrap());
	for item in parsed["items"].as_array().unwrap() {
		zone.writes
			.push(format!("PUT {}", item["address"].as_str().unwrap_or("?")));
		zone.records.push(item.clone());
	}
	axum::http::StatusCode::NO_CONTENT
}

async fn remove(State(zone): State<Held>, body: String) -> axum::http::StatusCode {
	let items: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
	let mut zone = zone.lock().unwrap();
	for item in items {
		zone.writes.push(format!(
			"DELETE {}",
			item["address"].as_str().unwrap_or("?")
		));
		// A removal names the record by every field it carries.
		zone.records.retain(|stored| {
			!item
				.as_object()
				.unwrap()
				.iter()
				.all(|(key, value)| stored.get(key) == Some(value))
		});
	}
	axum::http::StatusCode::NO_CONTENT
}

async fn start(addresses: &[&str]) -> (SpaceshipProvider, Held) {
	let held: Held = Arc::new(Mutex::new(Zone {
		records: zone_records(addresses),
		..Default::default()
	}));
	let app = Router::new()
		.route("/dns/records/{zone}", get(list).put(save).delete(remove))
		.with_state(held.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = SpaceshipProvider::new("AK".into(), "SK".into(), ZONE.into())
		.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}")).unwrap());
	(provider, held)
}

fn a(value: &str) -> DnsRecord {
	DnsRecord::new(NAME, RecordKind::A, value, 300)
}

fn addresses(held: &Held) -> Vec<String> {
	let mut live: Vec<String> = held
		.lock()
		.unwrap()
		.records
		.iter()
		.filter(|r| r["name"] == "mail" && r["type"] == "A")
		.map(|r| r["address"].as_str().unwrap().to_string())
		.collect();
	live.sort();
	live
}

/// A change planned against what the provider lists now.
async fn change(
	provider: &SpaceshipProvider,
	plan: impl FnOnce(&[DnsRecord]) -> Vec<DnsRecord>,
) -> Change {
	let snapshot = provider.publish_snapshot(ZONE).await.unwrap();
	let before: Vec<_> = snapshot
		.records
		.into_iter()
		.filter(|o| o.record.name == NAME && o.record.kind == RecordKind::A)
		.collect();
	let listed: Vec<DnsRecord> = before.iter().map(|o| o.record.clone()).collect();
	Change {
		name: NAME.into(),
		kind: RecordKind::A,
		before,
		after: plan(&listed),
		precondition: Precondition::Identity,
		operation_id: "epistle-publish-test".into(),
	}
}

fn writes(held: &Held) -> Vec<String> {
	held.lock().unwrap().writes.clone()
}

#[tokio::test]
async fn the_snapshot_says_it_checks_and_names_what_a_removal_matches() {
	let (provider, _held) = start(&["203.0.113.10"]).await;
	let snapshot = provider.publish_snapshot(ZONE).await.unwrap();
	assert_eq!(snapshot.guard, Guard::Checked);
	let own = snapshot
		.records
		.iter()
		.find(|o| o.record == a("203.0.113.10"))
		.expect("listed");
	let removal: serde_json::Value =
		serde_json::from_str(own.identity.as_deref().expect("an identity")).unwrap();
	assert_eq!(removal["address"], "203.0.113.10");
	assert_eq!(removal["name"], "mail");
	// A type epistle cannot write has nothing to remove it by.
	assert!(
		snapshot
			.records
			.iter()
			.any(|o| o.record.kind == RecordKind::Ns && o.identity.is_none())
	);
}

#[tokio::test]
async fn a_record_added_after_the_listing_stops_the_write() {
	let (provider, held) = start(&["203.0.113.10"]).await;
	let change = change(&provider, |_| vec![a("203.0.113.11")]).await;
	held.lock().unwrap().records = zone_records(&["203.0.113.10", "203.0.113.99"]);
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert!(writes(&held).is_empty());
}

#[tokio::test]
async fn a_record_replaced_after_the_listing_stops_the_write() {
	let (provider, held) = start(&["203.0.113.10"]).await;
	let change = change(&provider, |_| vec![a("203.0.113.11")]).await;
	held.lock().unwrap().records = zone_records(&["203.0.113.50"]);
	assert_eq!(
		provider.apply_guarded(ZONE, change).await,
		Receipt::PreconditionFailed
	);
	assert!(writes(&held).is_empty());
}

#[tokio::test]
async fn a_replacement_adds_the_new_record_and_then_removes_the_old_one_by_value() {
	let (provider, held) = start(&["203.0.113.20", "203.0.113.10"]).await;
	let change = change(&provider, |listed| {
		listed
			.iter()
			.map(|r| {
				if r.value.ends_with(".10") {
					a("203.0.113.11")
				} else {
					r.clone()
				}
			})
			.collect()
	})
	.await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	assert_eq!(writes(&held), ["PUT 203.0.113.11", "DELETE 203.0.113.10"]);
	assert_eq!(addresses(&held), ["203.0.113.11", "203.0.113.20"]);
	// A save never forces: a conflict is refused, not resolved by dropping
	// a record.
	assert_eq!(held.lock().unwrap().forces, [false]);
}

#[tokio::test]
async fn a_removal_names_only_its_own_value() {
	let (provider, held) = start(&["203.0.113.20", "203.0.113.10"]).await;
	let change = change(&provider, |listed| {
		listed
			.iter()
			.filter(|r| r.value.ends_with(".20"))
			.cloned()
			.collect()
	})
	.await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	assert_eq!(writes(&held), ["DELETE 203.0.113.10"]);
	assert_eq!(addresses(&held), ["203.0.113.20"]);
	// The record at another name, the TXT at the same one and the NS stay.
	assert_eq!(held.lock().unwrap().records.len(), 4);
}

#[tokio::test]
async fn a_new_record_is_added_and_nothing_else_is_written() {
	let (provider, held) = start(&["203.0.113.20"]).await;
	let change = change(&provider, |listed| {
		let mut after = listed.to_vec();
		after.push(a("203.0.113.11"));
		after
	})
	.await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	assert_eq!(writes(&held), ["PUT 203.0.113.11"]);
}

#[tokio::test]
async fn a_change_that_alters_nothing_writes_nothing() {
	let (provider, held) = start(&["203.0.113.10"]).await;
	let change = change(&provider, |listed| listed.to_vec()).await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Applied { .. }), "{receipt:?}");
	assert!(writes(&held).is_empty());
}

#[tokio::test]
async fn a_change_outside_its_name_is_refused_before_any_write() {
	let (provider, held) = start(&["203.0.113.10"]).await;
	let other = DnsRecord::new("other.example.org", RecordKind::A, "203.0.113.11", 300);
	let change = change(&provider, |_| vec![other]).await;
	let receipt = provider.apply_guarded(ZONE, change).await;
	assert!(matches!(receipt, Receipt::Rejected(_)), "{receipt:?}");
	assert!(writes(&held).is_empty());
}
