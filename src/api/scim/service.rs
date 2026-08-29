//! SCIM 2.0 discovery endpoints.
//!
//! RFC 7644 §4: `ServiceProviderConfig`, `Schemas`, `ResourceTypes`. Every
//! IdP we integrate against calls at least one of these on first connect to
//! discover what we actually support. We answer truthfully: bulk is off,
//! sort is off, etag is off, filter is on (limited to `userName eq "x"`),
//! patch is on (limited to `replace` of `active` and `password`).
//!
//! These three endpoints are static JSON: they do not depend on the
//! directory state, and a single render at startup is enough.

use axum::Json;
use axum::http::header;
use axum::response::IntoResponse;

use super::error::CONTENT_TYPE;

/// Wrap `value` so the response carries the SCIM `Content-Type`. SCIM
/// requires `application/scim+json` on every successful response, not just
/// the error path — see RFC 7644 §8.1.
fn scim(value: serde_json::Value) -> impl IntoResponse {
	([(header::CONTENT_TYPE, CONTENT_TYPE)], Json(value))
}

/// Schema URN advertised by the ServiceProviderConfig response.
const SERVICE_PROVIDER_CONFIG_SCHEMA: &str =
	"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

/// `GET /ServiceProviderConfig` — RFC 7644 §4.2.
///
/// We claim only what we implement. Lying here ("`bulk": true`) is the
/// classic SCIM interop trap: an IdP that believes the lie will issue a
/// request our server then has to fail at runtime, with a worse error than
/// the one we could have given up front.
pub async fn service_provider_config() -> impl IntoResponse {
	let body = serde_json::json!({
		"schemas": [SERVICE_PROVIDER_CONFIG_SCHEMA],
		"patch": {
			"supported": true,
			// RFC 7644 §3.5.2 names `add`, `remove`, `replace`. We only
			// honour `replace` of `active` and `password`; see users::patch_user.
			"operations": ["replace", "add"]
		},
		"bulk": {
			"supported": false,
			"maxOperations": 0,
			"maxPayloadSize": 0
		},
		"filter": {
			"supported": true,
			"maxResults": 200
		},
		"sort": {
			"supported": false
		},
		"etag": {
			"supported": false
		},
		"changePassword": {
			"supported": false
		},
		"authenticationSchemes": [
			{
				"name": "OAuth Bearer Token",
				"description":
					"A management API key with the `scim` scope, presented as a Bearer token.",
				"specUri": "https://tools.ietf.org/html/rfc6750",
				"type": "oauthbearertoken"
			}
		]
	});
	scim(body)
}

/// `GET /Schemas` — RFC 7644 §4.3. We advertise the User schema only;
/// Groups and EnterpriseUser are deliberately absent (Groups is 501,
/// Enterprise is out of scope).
pub async fn schemas() -> impl IntoResponse {
	let user_schema = serde_json::json!({
		"id": "urn:ietf:params:scim:schemas:core:2.0:User",
		"name": "User",
		"description": "User account as provisioned via SCIM.",
		"attributes": [
			{
				"name": "userName",
				"type": "string",
				"required": true,
				"mutability": "readWrite",
				"returned": "default",
				"uniqueness": "server"
			},
			{
				"name": "active",
				"type": "boolean",
				"required": false,
				"mutability": "readWrite",
				"returned": "default"
			},
			{
				"name": "password",
				"type": "string",
				"required": false,
				"mutability": "writeOnly",
				"returned": "never"
			},
			{
				"name": "emails",
				"type": "complex",
				"required": false,
				"mutability": "readWrite",
				"returned": "default",
				"multiValued": true
			}
		]
	});
	scim(serde_json::json!({
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
		"totalResults": 1,
		"Resources": [user_schema],
		"startIndex": 1,
		"itemsPerPage": 1
	}))
}

/// `GET /ResourceTypes` — RFC 7644 §4.4. We declare the User resource only.
pub async fn resource_types() -> impl IntoResponse {
	let user_resource = serde_json::json!({
		"id": "User",
		"name": "User",
		"endpoint": "/scim/v2/Users",
		"description": "Account that authenticates to the mail server.",
		"schema": "urn:ietf:params:scim:schemas:core:2.0:User",
		"schemaExtensions": []
	});
	scim(serde_json::json!({
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
		"totalResults": 1,
		"Resources": [user_resource],
		"startIndex": 1,
		"itemsPerPage": 1
	}))
}

#[cfg(test)]
mod tests {
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
}
