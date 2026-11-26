//! Who may use the health routes: the `health` scope, and only that, and
//! never a key confined to domains or bound to an account.

use axum::http::StatusCode;

use super::fixture::*;

const ROUTES: [&str; 3] = [
	"/api/v1/health",
	"/api/v1/health/config",
	"/api/v1/health/antispam",
];

#[tokio::test]
async fn a_request_without_a_credential_is_refused() {
	let world = world();
	for route in ROUTES {
		let (status, _, _) = get(&world.state, route, None).await;
		assert_eq!(status, StatusCode::UNAUTHORIZED, "{route}");
	}
}

/// `read` and every other scope together do not open the routes.
#[tokio::test]
async fn a_key_without_the_health_scope_is_refused() {
	let world = world();
	for route in ROUTES {
		let (status, _, body) = get(&world.state, route, Some(OTHERS)).await;
		assert_eq!(status, StatusCode::FORBIDDEN, "{route}: {body}");
	}
}

/// The answer is the server's: a confined key or a bound one is refused
/// before the area is even looked up, so a name tells it nothing.
#[tokio::test]
async fn a_confined_or_bound_key_is_refused_whatever_the_area() {
	let world = world();
	for secret in [CONFINED, BOUND] {
		for route in [
			"/api/v1/health",
			"/api/v1/health/config",
			"/api/v1/health/no-such-area",
		] {
			let (status, _, body) = get(&world.state, route, Some(secret)).await;
			assert_eq!(status, StatusCode::FORBIDDEN, "{route}: {body}");
		}
	}
}

#[tokio::test]
async fn the_health_key_and_the_configured_token_get_the_report() {
	let world = world();
	for secret in [HEALTHY, token()] {
		let (status, _, body) = get(&world.state, "/api/v1/health", Some(secret)).await;
		assert_eq!(status, StatusCode::OK, "{body}");
		let areas: Vec<&str> = body
			.as_object()
			.expect("object")
			.keys()
			.map(String::as_str)
			.collect();
		assert_eq!(areas, ["antispam", "config"]);
		for report in body.as_object().unwrap().values() {
			assert!(report["status"].is_string() && report["detail"].is_string());
		}
		let (status, _, one) = get(&world.state, "/api/v1/health/antispam", Some(secret)).await;
		assert_eq!(status, StatusCode::OK, "{one}");
		assert_eq!(one.as_object().unwrap().len(), 1);
		assert_eq!(one["antispam"], body["antispam"]);
	}
}

#[tokio::test]
async fn a_name_that_is_not_an_area_is_not_found() {
	let world = world();
	let long = "a".repeat(5000);
	for name in [
		"nope",
		"Config",
		"CONFIG",
		"all",
		"",
		"config%00",
		"..%2F..%2Fetc%2Fpasswd",
		"config%2Fantispam",
		"config,antispam",
		"storage-keys",
		long.as_str(),
	] {
		let (status, _, body) = get(
			&world.state,
			&format!("/api/v1/health/{name}"),
			Some(HEALTHY),
		)
		.await;
		assert!(
			status == StatusCode::NOT_FOUND,
			"{:?}: {status} {body}",
			&name[..name.len().min(30)]
		);
	}
}

/// Without the live configuration the routes have nothing to run against,
/// and say so without guessing.
#[tokio::test]
async fn a_server_without_a_live_configuration_fails_closed() {
	let world = build(false);
	let (status, _, body) = get(&world.state, "/api/v1/health", Some(HEALTHY)).await;
	assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
}
