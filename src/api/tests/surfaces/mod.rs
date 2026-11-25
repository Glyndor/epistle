//! Each surface of the router is mounted where it is asked for and nowhere
//! else, and a listener that serves one of them answers `404` for the rest.

use axum::Router;
use axum::http::StatusCode;
use serde_json::Value;

use super::base::{TOKEN, request, test_state};
use crate::api::{Surface, Surfaces, router, router_for};
use tower::ServiceExt;

const EVERY: [Surface; 4] = [
	Surface::Manage,
	Surface::Jmap,
	Surface::Oauth,
	Surface::Scim,
];

fn app(dir: &std::path::Path, surfaces: &[Surface]) -> Router {
	router_for(test_state(dir, 0), &Surfaces::only(surfaces))
}

/// The status of a request with the bearer token, whatever the body of the
/// answer is.
async fn status_of(app: &Router, method: &str, path: &str) -> StatusCode {
	let request = axum::http::Request::builder()
		.method(method)
		.uri(path)
		.header(
			axum::http::header::AUTHORIZATION,
			format!("Bearer {}", TOKEN.as_str()),
		)
		.body(axum::body::Body::empty())
		.expect("request");
	app.clone()
		.oneshot(request)
		.await
		.expect("response")
		.status()
}

/// A path of the OpenAPI document with its `{parameters}` filled in.
fn concrete(path: &str) -> String {
	let mut out = String::new();
	let mut inside = false;
	for character in path.chars() {
		match character {
			'{' => {
				inside = true;
				out.push('x');
			}
			'}' => inside = false,
			other if !inside => out.push(other),
			_ => {}
		}
	}
	out
}

/// The paths of the document that other listeners serve: the client setup
/// documents, the ACME responder and the metrics. They belong to no surface of
/// the API listener.
const OTHER_LISTENERS: [&str; 7] = [
	"/mail/config-v1.1.xml",
	"/.well-known/autoconfig/mail/config-v1.1.xml",
	"/autodiscover/autodiscover.xml",
	"/autodiscover/autodiscover.json",
	"/mobileconfig",
	"/.well-known/acme-challenge/{token}",
	"/metrics",
];

/// Every `(path, METHOD)` of the document that the API listener serves.
fn documented() -> Vec<(String, String)> {
	let doc: Value = crate::api::openapi::parsed().expect("openapi.yaml reads");
	let mut found = Vec::new();
	for (path, item) in doc["paths"].as_object().expect("paths") {
		if OTHER_LISTENERS.contains(&path.as_str()) {
			continue;
		}
		for method in item.as_object().expect("path item").keys() {
			if ["get", "post", "put", "patch", "delete"].contains(&method.as_str()) {
				found.push((concrete(path), method.to_ascii_uppercase()));
			}
		}
	}
	found
}

#[test]
fn every_path_has_a_surface() {
	let doc: Value = crate::api::openapi::parsed().expect("openapi.yaml reads");
	for path in doc["paths"].as_object().expect("paths").keys() {
		let other = OTHER_LISTENERS.contains(&path.as_str());
		assert_eq!(
			Surface::of_path(&concrete(path)).is_none(),
			other,
			"{path}: a path the API listener serves belongs to a surface, and one that another \
			 listener serves belongs to none"
		);
	}
	assert_eq!(Surface::of_path("/nope"), None);
	assert_eq!(
		Surface::of_path("/api/v1x"),
		None,
		"a prefix is a whole segment"
	);
	assert_eq!(Surface::of_path("/jmapx/session"), None);
}

#[tokio::test]
async fn every_route_belongs_to_one_surface() {
	let dir = tempfile::tempdir().expect("tempdir");
	let whole = router(test_state(dir.path(), 0));
	let singles: Vec<(Surface, Router)> = EVERY
		.iter()
		.map(|surface| (*surface, app(dir.path(), &[*surface])))
		.collect();
	let mut checked = 0;
	for (path, method) in documented() {
		let owner = Surface::of_path(&path).expect("a surface");
		// `/healthz` is on every listener, which its own test pins.
		if owner == Surface::Oauth || path == "/healthz" {
			continue;
		}
		let expected = status_of(&whole, &method, &path).await;
		for (surface, app) in &singles {
			let status = status_of(app, &method, &path).await;
			if *surface == owner {
				assert_eq!(status, expected, "{method} {path} on its own surface");
			} else {
				assert_eq!(
					status,
					StatusCode::NOT_FOUND,
					"{method} {path} on {surface:?}"
				);
			}
		}
		checked += 1;
	}
	assert!(checked > 60, "only {checked} routes were compared");
}

#[tokio::test]
async fn jmap_listener_takes_jmap_off_api() {
	let dir = tempfile::tempdir().expect("tempdir");
	let without_jmap = app(
		dir.path(),
		&[Surface::Manage, Surface::Oauth, Surface::Scim],
	);
	// With a credential the answer is that no route is there; without one the
	// bearer check answers first, as it does for any path nobody serves.
	let (status, _) = request(&without_jmap, "GET", "/jmap/session", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::NOT_FOUND);
	let (status, _) = request(&without_jmap, "GET", "/jmap/session", None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	let jmap_only = app(dir.path(), &[Surface::Jmap]);
	let (status, _) = request(&jmap_only, "GET", "/jmap/session", None).await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
	let (status, _) = request(&jmap_only, "GET", "/jmap/session", Some(TOKEN.as_str())).await;
	assert_eq!(status, StatusCode::OK);
	let (status, _) = request(&jmap_only, "GET", "/api/v1/status", Some(TOKEN.as_str())).await;
	assert_eq!(
		status,
		StatusCode::NOT_FOUND,
		"management is not on the jmap listener"
	);
}

#[tokio::test]
async fn healthz_is_on_every_listener() {
	let dir = tempfile::tempdir().expect("tempdir");
	for surface in EVERY {
		let (status, body) = request(&app(dir.path(), &[surface]), "GET", "/healthz", None).await;
		assert_eq!(
			(status, body["status"].as_str()),
			(StatusCode::OK, Some("ok")),
			"{surface:?}"
		);
	}
}

#[tokio::test]
async fn the_whole_router_is_every_surface() {
	let dir = tempfile::tempdir().expect("tempdir");
	let whole = router(test_state(dir.path(), 0));
	let every = router_for(test_state(dir.path(), 0), &Surfaces::all());
	for (path, method) in documented() {
		let a = status_of(&whole, &method, &path).await;
		let b = status_of(&every, &method, &path).await;
		assert_eq!(a, b, "{method} {path}");
	}
}
