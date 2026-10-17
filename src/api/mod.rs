//! Management HTTP API (`/api/v1`).
//!
//! Read-only views plus queue management, consumed by the CLI and by
//! mail-panel. Every endpoint requires the bearer token; the listener
//! binds to localhost unless explicitly configured otherwise.

mod account_bound;
mod account_view;
pub mod api_keys;
mod audit;
pub mod domain_scope;
mod error;
pub(crate) mod jmap;
mod mail_from;
pub mod oauth;
mod principal;
mod quota;
pub mod scim;
mod state;
pub mod tenant_limits;
pub mod v1;

pub use api_keys::{ApiKey, ApiKeySet, ApiKeySetSnapshot, ApiKeyStore};
pub use audit::{AuditEvent, log_auth_attempt, log_privilege_change, log_send_limited};
pub use jmap::reclaim_blobs;
pub use principal::{Credential, Principal};
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
#[path = "api_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "api_tests_b.rs"]
mod tests_b;

#[cfg(test)]
#[path = "scram_off_tests.rs"]
mod scram_off_tests;

#[cfg(test)]
#[path = "account_bound_tests.rs"]
mod account_bound_tests;

#[cfg(test)]
#[path = "api_tests_newrecipients.rs"]
mod tests_newrecipients;

#[cfg(test)]
#[path = "api_tests_quota.rs"]
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
#[path = "jmap_tests_author.rs"]
mod jmap_tests_author;

#[cfg(test)]
#[path = "jmap_tests_b.rs"]
mod jmap_tests_b;

#[cfg(test)]
#[path = "jmap_tests_mailbox_tree.rs"]
mod jmap_tests_mailbox_tree;

#[cfg(test)]
#[path = "jmap_tests_encoded_words.rs"]
mod jmap_tests_encoded_words;

#[cfg(test)]
#[path = "jmap_tests_c.rs"]
mod jmap_tests_c;

#[cfg(test)]
#[path = "jmap_tests_d.rs"]
mod jmap_tests_d;

#[cfg(test)]
#[path = "jmap_tests_e2.rs"]
mod jmap_tests_e2;

#[cfg(test)]
#[path = "jmap_tests_e.rs"]
mod jmap_tests_e;

#[cfg(test)]
#[path = "jmap_tests_f.rs"]
mod jmap_tests_f;

#[cfg(test)]
#[path = "jmap_tests_g.rs"]
mod jmap_tests_g;

#[cfg(test)]
#[path = "jmap_tests_principal.rs"]
mod jmap_tests_principal;

#[cfg(test)]
#[path = "jmap_tests_principal_b.rs"]
mod jmap_tests_principal_b;

#[cfg(test)]
#[path = "jmap_tests_principal_c.rs"]
mod jmap_tests_principal_c;

#[cfg(test)]
#[path = "jmap_tests_push.rs"]
mod jmap_tests_push;

#[cfg(test)]
#[path = "jmap_tests_push_validation.rs"]
mod jmap_tests_push_validation;

#[cfg(test)]
#[path = "jmap_tests_ws_revoke.rs"]
mod jmap_tests_ws_revoke;

#[cfg(test)]
#[path = "send_tests_principal.rs"]
mod send_tests_principal;

#[cfg(test)]
#[path = "send_tests_outbound.rs"]
mod send_tests_outbound;

#[cfg(test)]
#[path = "send_tests_save_sent.rs"]
mod send_tests_save_sent;

#[cfg(test)]
#[path = "send_tests_class.rs"]
mod send_tests_class;
#[cfg(test)]
#[path = "send_tests_class_key.rs"]
mod send_tests_class_key;

#[cfg(test)]
#[path = "send_tests_class_paths.rs"]
mod send_tests_class_paths;

#[cfg(test)]
#[path = "send_tests_rich.rs"]
mod send_tests_rich;

#[cfg(test)]
#[path = "send_tests_rich_headers.rs"]
mod send_tests_rich_headers;

#[cfg(test)]
#[path = "send_tests_injection.rs"]
mod send_tests_injection;

#[cfg(test)]
#[path = "jmap_tests_email_create.rs"]
mod jmap_tests_email_create;

#[cfg(test)]
#[path = "send_tests_bcc.rs"]
mod send_tests_bcc;

#[cfg(test)]
#[path = "send_tests_toolarge.rs"]
mod send_tests_toolarge;
#[cfg(test)]
#[path = "send_tests_virus.rs"]
mod send_tests_virus;

#[cfg(test)]
#[path = "send_tests_attachments.rs"]
mod send_tests_attachments;

#[cfg(test)]
#[path = "send_tests_ratelimit.rs"]
mod send_tests_ratelimit;

#[cfg(test)]
#[path = "send_tests_trace.rs"]
mod send_tests_trace;

#[cfg(test)]
#[path = "jmap_tests_attachment_limit.rs"]
mod jmap_tests_attachment_limit;

#[cfg(test)]
#[path = "jmap_tests_message_size.rs"]
mod jmap_tests_message_size;

#[cfg(test)]
#[path = "jmap_tests_partition.rs"]
mod jmap_tests_partition;

#[cfg(test)]
#[path = "jmap_tests_changes_helpers.rs"]
mod jmap_tests_changes_helpers;

#[cfg(test)]
#[path = "jmap_tests_changes.rs"]
mod jmap_tests_changes;

#[cfg(test)]
#[path = "jmap_tests_changes_b.rs"]
mod jmap_tests_changes_b;

#[cfg(test)]
#[path = "jmap_tests_query_changes.rs"]
mod jmap_tests_query_changes;

#[cfg(test)]
#[path = "jmap_tests_changes_c.rs"]
mod jmap_tests_changes_c;

#[cfg(test)]
#[path = "jmap_tests_limits.rs"]
mod jmap_tests_limits;

#[cfg(test)]
#[path = "jmap_tests_limits_objects.rs"]
mod jmap_tests_limits_objects;

#[cfg(test)]
#[path = "jmap_tests_limits_concurrency.rs"]
mod jmap_tests_limits_concurrency;

#[cfg(test)]
#[path = "auth_once_tests.rs"]
mod auth_once_tests;

#[cfg(test)]
#[path = "jmap_tests_limits_backref.rs"]
mod jmap_tests_limits_backref;

#[cfg(test)]
#[path = "tenancy_tests.rs"]
mod tenancy_tests;

#[cfg(test)]
#[path = "tenant_limits_tests_e2e.rs"]
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
#[path = "jmap_tests_disabled.rs"]
mod jmap_tests_disabled;

#[cfg(test)]
#[path = "jmap_tests_read_scope.rs"]
mod jmap_tests_read_scope;

#[cfg(test)]
#[path = "jmap_tests_push_get.rs"]
mod jmap_tests_push_get;

#[cfg(test)]
#[path = "jmap_tests_eventsource.rs"]
mod jmap_tests_eventsource;

#[cfg(test)]
#[path = "jmap_tests_vacation.rs"]
mod jmap_tests_vacation;

#[cfg(test)]
#[path = "jmap_tests_vacation_b.rs"]
mod jmap_tests_vacation_b;

#[cfg(test)]
#[path = "api_tests_addresses.rs"]
mod tests_addresses;

#[cfg(test)]
#[path = "api_tests_display_name.rs"]
mod tests_display_name;
