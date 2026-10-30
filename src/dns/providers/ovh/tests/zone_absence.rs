//! The zone lookup of the OVH provider: the endpoints carry a version
//! prefix (`/1.0`), a zone the account does not hold is a zone that is
//! not there, and a record that is not there is not a zone that is not
//! there.

use super::base::txt;
use super::*;

use axum::Router;
use axum::extract::{Path, State};
use axum::routing::get;
use std::sync::{Arc, Mutex};

/// The ids the list of a zone answers with.
#[derive(Default)]
struct MockState {
	ids: Vec<u64>,
}

type Shared = Arc<Mutex<MockState>>;

/// The records of a zone OVH holds. A zone it does not hold answers 404,
/// the way OVH answers one.
async fn list_records(
	State(state): State<Shared>,
	Path(zone): Path<String>,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
	let s = state.lock().unwrap();
	if zone != "example.org" {
		return Err(axum::http::StatusCode::NOT_FOUND);
	}
	Ok(axum::Json(serde_json::json!(s.ids)))
}

/// One record of the zone, read by id.
async fn read_record(
	State(_state): State<Shared>,
	Path((_zone, id)): Path<(String, u64)>,
) -> axum::Json<serde_json::Value> {
	axum::Json(serde_json::json!({
		"id": id,
		"zone": "example.org",
		"fieldType": "TXT",
		"subDomain": "_dmarc",
		"target": "v=DMARC1; p=none",
		"ttl": 3600,
	}))
}

/// A write to a record that is not there answers 404: the record was
/// removed between the read and the write.
async fn write_record(
	State(_state): State<Shared>,
	Path((_zone, _id)): Path<(String, u64)>,
) -> axum::http::StatusCode {
	axum::http::StatusCode::NOT_FOUND
}

/// A provider pointed at the versioned endpoint of the mock.
async fn mock(ids: Vec<u64>) -> (OvhProvider, Shared) {
	let state: Shared = Arc::new(Mutex::new(MockState { ids }));
	let app = Router::new()
		.route(
			"/1.0/domain/zone/{zone}/record",
			get(list_records).post(list_records),
		)
		.route(
			"/1.0/domain/zone/{zone}/record/{id}",
			get(read_record).put(write_record).delete(write_record),
		)
		.with_state(state.clone());
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	let provider = OvhProvider::new(
		"AKID".into(),
		"secret".into(),
		ScopedSecret::new("example.org", "CK"),
	)
	.with_base(crate::net::HttpsUrl::loopback_http(&format!("http://{addr}/1.0")).unwrap());
	(provider, state)
}

#[tokio::test]
async fn a_zone_ovh_does_not_hold_is_a_zone_that_is_not_there() {
	// The endpoints carry a version prefix, so the path of a request is
	// `/1.0/domain/zone/{zone}/record`. A 404 there says the zone is not
	// there, and the search goes on to the parent.
	let (provider, _state) = mock(Vec::new()).await;
	assert_eq!(
		crate::dns::zone::resolve(&provider, "mail.example.org")
			.await
			.expect("the search finds the parent zone"),
		"example.org"
	);
}

#[tokio::test]
async fn the_zone_the_error_names_is_the_zone_the_operation_asked_for() {
	let (provider, _state) = mock(Vec::new()).await;
	assert_eq!(
		provider
			.list("mail.example.org")
			.await
			.expect_err("the zone is not there"),
		ProviderError::ZoneNotFound("mail.example.org".to_string())
	);
}

#[tokio::test]
async fn a_record_that_is_not_there_is_not_a_zone_that_is_not_there() {
	// The record was removed between the list and the write. The write
	// answers 404, and that is about the record, not about the zone.
	let (provider, _state) = mock(vec![7]).await;
	let error = provider
		.upsert("example.org", txt("_dmarc.example.org", "v=DMARC1; p=none"))
		.await
		.expect_err("the record is gone");
	assert!(
		!matches!(error, ProviderError::ZoneNotFound(_)),
		"a record that is gone is not a zone that is not there: {error}"
	);
}

#[test]
fn the_zone_of_a_url_is_read_relative_to_the_base() {
	let base = crate::net::HttpsUrl::parse("https://eu.api.ovh.com/1.0").unwrap();
	let url = base
		.with_segments(["domain", "zone", "mail.example.org", "record"])
		.unwrap();
	assert_eq!(
		zone_of(&base, &url).as_deref(),
		Some("mail.example.org"),
		"the zone of a versioned URL is the zone the request asks for"
	);
}

#[test]
fn the_zone_of_a_url_is_the_zone_the_operation_asked_for() {
	// The zone travels through the URL percent-encoded; the error names
	// the zone the operation asked for.
	let base = crate::net::HttpsUrl::parse("https://eu.api.ovh.com/1.0").unwrap();
	let url = base
		.with_segments(["domain", "zone", "mail example.org", "record"])
		.unwrap();
	assert_eq!(zone_of(&base, &url).as_deref(), Some("mail example.org"));
}
