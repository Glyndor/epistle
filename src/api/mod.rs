//! Management HTTP API (`/api/v1`).
//!
//! Read-only views plus queue management, consumed by the CLI and by
//! mail-panel. Every endpoint requires the bearer token; the listener
//! binds to localhost unless explicitly configured otherwise.

pub mod api_keys;
mod error;
mod jmap;
mod state;
pub mod v1;

pub use api_keys::{ApiKey, ApiKeyStore};
pub use state::ApiState;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{get, post};
use tower_http::cors::CorsLayer;

/// Build the API router with authentication applied to every route.
pub fn router(state: ApiState) -> Router {
	// Authenticated surface: every route requires the bearer token.
	let authenticated = Router::new()
		.nest("/api/v1", v1::router())
		// JMAP (RFC 8620): Session discovery and the request-envelope endpoint.
		// `.well-known/jmap` is the standard autodiscovery path (§2.2).
		.route("/.well-known/jmap", get(jmap::session))
		.route("/jmap/session", get(jmap::session))
		.route("/jmap/api", post(jmap::api))
		.route(
			"/jmap/download/{account_id}/{blob_id}/{name}",
			get(jmap::download),
		)
		// Allow the upload route a body limit matching maxSizeUpload (plus a
		// small margin so the handler returns the spec's limit error rather
		// than a bare transport 413); other routes keep the default cap.
		.route(
			"/jmap/upload/{account_id}",
			post(jmap::upload).layer(DefaultBodyLimit::max(jmap::MAX_UPLOAD_SIZE + 1_048_576)),
		)
		// Deny all CORS: no origins, methods, or headers are allowed.
		.layer(CorsLayer::new())
		.layer(middleware::from_fn_with_state(
			state.clone(),
			state::require_bearer_token,
		));
	// Unauthenticated liveness probe (reveals nothing) for load balancers and
	// orchestrators; merged outside the auth layer.
	Router::new()
		.route(
			"/healthz",
			get(|| async { axum::Json(serde_json::json!({ "status": "ok" })) }),
		)
		.merge(authenticated)
		.with_state(state)
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "jmap_tests.rs"]
mod jmap_tests;

#[cfg(test)]
#[path = "jmap_tests_b.rs"]
mod jmap_tests_b;
