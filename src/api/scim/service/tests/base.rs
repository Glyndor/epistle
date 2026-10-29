use super::service_provider_config;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn service_provider_config_advertises_no_bulk_no_sort() {
	let app = axum::Router::new().route(
		"/ServiceProviderConfig",
		axum::routing::get(service_provider_config),
	);
	let response = app
		.oneshot(
			Request::builder()
				.uri("/ServiceProviderConfig")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.expect("response");
	assert_eq!(response.status(), StatusCode::OK);
	assert_eq!(
		response.headers().get("content-type").expect("ct"),
		"application/scim+json"
	);
	let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
		.await
		.unwrap();
	let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
	assert_eq!(json["bulk"]["supported"], false);
	assert_eq!(json["sort"]["supported"], false);
	assert_eq!(json["filter"]["supported"], true);
	assert_eq!(json["patch"]["supported"], true);
}
