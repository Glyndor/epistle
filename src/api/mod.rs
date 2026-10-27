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
#[path = "mod_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "single_label_tests.rs"]
mod single_label_tests;

#[cfg(test)]
#[path = "mod_tests_b.rs"]
mod tests_b;

#[cfg(test)]
#[path = "scram_off_tests.rs"]
mod scram_off_tests;

#[cfg(test)]
#[path = "account_bound_tests.rs"]
mod account_bound_tests;

#[cfg(test)]
#[path = "mod_tests_newrecipients.rs"]
mod tests_newrecipients;

#[cfg(test)]
#[path = "mod_tests_quota.rs"]
mod tests_quota;

#[cfg(test)]
#[path = "auth_tests.rs"]
mod auth_tests;

#[cfg(test)]
#[path = "masked_tests.rs"]
mod masked_tests;

#[cfg(test)]
#[path = "jmap_tests.rs"]
mod jmap_tests;

#[cfg(test)]
mod jmap_tests_author;

#[cfg(test)]
#[path = "send_as_tests.rs"]
mod send_as_tests;

#[cfg(test)]
mod jmap_tests_b;

#[cfg(test)]
mod jmap_tests_mailbox_tree;

#[cfg(test)]
mod jmap_tests_encoded_words;

#[cfg(test)]
mod jmap_tests_c;

#[cfg(test)]
mod jmap_tests_d;

#[cfg(test)]
mod jmap_tests_e2;

#[cfg(test)]
mod jmap_tests_e;

#[cfg(test)]
mod jmap_tests_f;

#[cfg(test)]
mod jmap_tests_g;

#[cfg(test)]
mod jmap_tests_framing;

#[cfg(test)]
#[path = "recipients_tests.rs"]
mod recipients_tests;

#[cfg(test)]
mod jmap_tests_principal;

#[cfg(test)]
mod jmap_tests_principal_b;

#[cfg(test)]
mod jmap_tests_principal_c;

#[cfg(test)]
mod jmap_tests_push;

#[cfg(test)]
mod jmap_tests_push_validation;

#[cfg(test)]
mod jmap_tests_ws_revoke;

#[cfg(test)]
mod send_tests_principal;

#[cfg(test)]
mod send_tests_outbound;

#[cfg(test)]
mod send_tests_save_sent;

#[cfg(test)]
mod send_tests_class;
#[cfg(test)]
mod send_tests_class_key;

#[cfg(test)]
mod send_tests_class_paths;

#[cfg(test)]
mod send_tests_identification;

#[cfg(test)]
mod send_tests_rich;

#[cfg(test)]
mod send_tests_rich_headers;

#[cfg(test)]
mod send_tests_injection;

#[cfg(test)]
mod jmap_tests_email_create;

#[cfg(test)]
mod send_tests_bcc;

#[cfg(test)]
mod send_tests_toolarge;
#[cfg(test)]
mod send_tests_virus;

#[cfg(test)]
mod send_tests_attachments;

#[cfg(test)]
mod send_tests_ratelimit;

#[cfg(test)]
mod send_tests_trace;

#[cfg(test)]
mod jmap_tests_attachment_limit;

#[cfg(test)]
mod jmap_tests_message_size;

#[cfg(test)]
mod jmap_tests_partition;

#[cfg(test)]
mod jmap_tests_changes_helpers;

#[cfg(test)]
mod jmap_tests_changes;

#[cfg(test)]
mod jmap_tests_changes_b;

#[cfg(test)]
mod jmap_tests_query_changes;

#[cfg(test)]
mod jmap_tests_changes_c;

#[cfg(test)]
mod jmap_tests_limits;

#[cfg(test)]
mod jmap_tests_limits_objects;

#[cfg(test)]
mod jmap_tests_limits_concurrency;

#[cfg(test)]
#[path = "auth_once_tests.rs"]
mod auth_once_tests;

#[cfg(test)]
mod jmap_tests_limits_backref;

#[cfg(test)]
#[path = "tenancy_tests.rs"]
mod tenancy_tests;

#[cfg(test)]
mod tenancy_tests_routes;

#[cfg(test)]
#[path = "route_rules_tests.rs"]
mod route_rules_tests;

#[cfg(test)]
#[path = "auth_guessing_tests.rs"]
mod auth_guessing_tests;

#[cfg(test)]
#[path = "auth_limiter_clients_tests.rs"]
mod auth_limiter_clients_tests;

#[cfg(test)]
mod tenant_limits_tests_e2e;

#[cfg(test)]
#[path = "cidr_dual_stack_tests.rs"]
mod cidr_dual_stack_tests;

#[cfg(test)]
#[path = "api_key_reload_tests.rs"]
mod api_key_reload_tests;

#[cfg(test)]
#[path = "secret_diagnostics_tests.rs"]
mod secret_diagnostics_tests;

#[cfg(test)]
mod jmap_tests_disabled;

#[cfg(test)]
mod jmap_tests_read_scope;

#[cfg(test)]
mod jmap_tests_push_get;

#[cfg(test)]
mod jmap_tests_eventsource;

#[cfg(test)]
mod jmap_tests_vacation;

#[cfg(test)]
mod jmap_tests_vacation_b;

#[cfg(test)]
mod jmap_tests_sieve_capability;

#[cfg(test)]
mod jmap_tests_sieve_support;

#[cfg(test)]
mod jmap_tests_sieve_get;

#[cfg(test)]
mod jmap_tests_sieve_query;

#[cfg(test)]
mod jmap_tests_sieve_validate;

#[cfg(test)]
mod jmap_tests_sieve_set;

#[cfg(test)]
mod jmap_tests_sieve_activate;

#[cfg(test)]
mod jmap_tests_sieve_authz;

#[cfg(test)]
mod jmap_tests_sieve_vacation;

#[cfg(test)]
mod jmap_tests_sieve_atomic;

#[cfg(test)]
mod jmap_tests_sieve_scope;

#[cfg(test)]
mod jmap_tests_sieve_cost;

#[cfg(test)]
mod jmap_tests_sieve_padding;

#[cfg(test)]
#[path = "mod_tests_addresses.rs"]
mod tests_addresses;

#[cfg(test)]
#[path = "mod_tests_display_name.rs"]
mod tests_display_name;

#[cfg(test)]
#[path = "mod_tests_queue.rs"]
mod tests_queue;

#[cfg(test)]
#[path = "confinement_tests.rs"]
mod confinement_tests;

#[cfg(test)]
mod confinement_tests_jmap;

#[cfg(test)]
mod confinement_tests_reach;
