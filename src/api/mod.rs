//! Management HTTP API (`/api/v1`).
//!
//! Read-only views plus queue management, consumed by the CLI and by
//! mail-panel. Every endpoint requires the bearer token; the listener
//! binds to localhost unless explicitly configured otherwise.

mod error;
mod jmap;
mod state;
pub mod v1;

pub use state::ApiState;

use axum::Router;
use axum::middleware;
use axum::routing::{get, post};
use tower_http::cors::CorsLayer;

/// Build the API router with authentication applied to every route.
pub fn router(state: ApiState) -> Router {
	Router::new()
		.nest("/api/v1", v1::router())
		// JMAP (RFC 8620): Session discovery and the request-envelope endpoint.
		// `.well-known/jmap` is the standard autodiscovery path (§2.2).
		.route("/.well-known/jmap", get(jmap::session))
		.route("/jmap/session", get(jmap::session))
		.route("/jmap/api", post(jmap::api))
		// Deny all CORS: no origins, methods, or headers are allowed.
		.layer(CorsLayer::new())
		.layer(middleware::from_fn_with_state(
			state.clone(),
			state::require_bearer_token,
		))
		.with_state(state)
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "jmap_tests.rs"]
mod jmap_tests;
