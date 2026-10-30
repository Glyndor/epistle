//! Management HTTP API (`/api/v1`).
//!
//! Read-only views plus queue management, consumed by the CLI and by
//! mail-panel. Every endpoint requires the bearer token; the listener
//! binds to localhost unless explicitly configured otherwise.

mod account_bound;
mod account_view;
pub mod api_keys;
mod audit;
mod authorization;
mod error;
pub(crate) mod jmap;
mod mail_from;
pub mod oauth;
pub(crate) mod openapi;
mod quota;
pub mod scim;
mod state;
pub mod tenant_limits;
pub mod v1;

pub use api_keys::{ApiKey, ApiKeySet, ApiKeySetSnapshot, ApiKeyStore};
pub use audit::{AuditEvent, log_auth_attempt, log_privilege_change, log_send_limited};
pub use authorization::{Credential, Principal};
pub use jmap::reclaim_blobs;
pub use state::{ApiState, ClientIp};
pub use tenant_limits::TenantLimits;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{get, post};
use tower_http::cors::CorsLayer;

/// Build the API router with authentication applied to every route.
pub fn router(state: ApiState) -> Router {
	// The configured per-instance message-size cap, applied consistently
	// to SMTP, the JMAP upload body limit, the JMAP `Email/set` build,
	// and the REST `POST /api/v1/send` builder.
	let max_message_size = state.max_message_size();
	// Authenticated surface: every route requires the bearer token.
	let authenticated = Router::new()
		.nest("/api/v1", v1::router(max_message_size))
		// SCIM 2.0 provisioning (RFC 7644). The dedicated `Scope::Scim`
		// gates every route, set in `acceptable_scopes_for` for any path
		// starting with `/scim/v2`. A `read`/`write`-only key cannot
		// enumerate or mutate users here.
		.nest("/scim/v2", scim::router())
		// JMAP (RFC 8620): Session discovery and the request-envelope endpoint.
		// `.well-known/jmap` is the standard autodiscovery path (§2.2).
		.route("/.well-known/jmap", get(jmap::session))
		.route("/jmap/session", get(jmap::session))
		// The body limit is the `maxSizeRequest` the Session advertises, not
		// axum's 2 MiB default.
		.route(
			"/jmap/api",
			post(jmap::api).layer(DefaultBodyLimit::max(jmap::MAX_SIZE_REQUEST)),
		)
		// JMAP over WebSocket (RFC 8887): the upgrade endpoint, under the same
		// bearer auth as the rest of the authenticated router.
		.route("/jmap/ws", get(jmap::websocket::ws_upgrade))
		// JMAP push over an event source (RFC 8620 §7.3).
		.route("/jmap/eventsource", get(jmap::event_source::event_source))
		.route(
			"/jmap/download/{account_id}/{blob_id}/{name}",
			get(jmap::download),
		)
		// The upload route's body limit is `maxSizeUpload`: the
		// operator-configured `[server] max_message_size`, the same value
		// the SMTP path applies at end-of-DATA. The handler answers a
		// larger body with the spec's limit error. Other routes keep the
		// default cap.
		.route(
			"/jmap/upload/{account_id}",
			post(jmap::upload).layer(DefaultBodyLimit::max(max_message_size)),
		)
		// Runs after the bearer check below (layers wrap outward), so the
		// matched credentials are already in the request.
		.layer(middleware::from_fn_with_state(
			state.clone(),
			account_bound::confine,
		))
		// Deny all CORS: no origins, methods, or headers are allowed.
		.layer(CorsLayer::new())
		.layer(middleware::from_fn_with_state(
			state.clone(),
			state::require_bearer_token,
		));
	// Unauthenticated liveness probe (reveals nothing) for load balancers and
	// orchestrators; merged outside the auth layer.
	let mut public = Router::new()
		.route(
			"/healthz",
			get(|| async { axum::Json(serde_json::json!({ "status": "ok" })) }),
		)
		.merge(authenticated);
	// OAuth 2.0 authorization-server grant endpoints (RFC 8628 device flow + RFC
	// 7636 PKCE). Mounted only when a signing key is configured; the endpoints
	// self-authenticate (codes / account credentials), so they sit OUTSIDE the
	// API bearer middleware. With no signing key, the routes are absent entirely
	// (fail closed — no path can issue an unsigned token).
	if state.authz().is_some() {
		public = public
			.merge(oauth::public_router())
			.merge(oauth::authenticated_router());
	}
	public.with_state(state)
}

#[cfg(test)]
mod tests;
