//! SCIM 2.0 provisioning endpoints under `/scim/v2`.
//!
//! RFC 7643 (core schema) + RFC 7644 (protocol). The surface here is the
//! minimum that the identity providers we integrate against actually use:
//! `ServiceProviderConfig` / `Schemas` / `ResourceTypes` for discovery, and
//! `Users` for full lifecycle management. `Groups` is intentionally
//! unimplemented (the module returns `501` on every call) — the directory
//! has no notion of group membership yet, so provisioning groups would be
//! a no-op pretending to be a feature.
//!
//! Authentication shares the management API's bearer tokens; the route
//! uses the dedicated `Scope::Scim` so a leaked token that happens to
//! have `read` or `write` cannot enumerate or mutate accounts.
//!
//! Every response carries `Content-Type: application/scim+json`. Errors
//! follow RFC 7644 §3.7: the `urn:ietf:params:scim:api:messages:2.0:Error`
//! schema URN, a numeric `status`, and a `detail` string.

mod error;
mod groups;
mod service;
mod types;
mod users;

use axum::Router;
use axum::routing::get;

use crate::api::state::ApiState;

/// Build the SCIM 2.0 route tree. Mounted by [`crate::api::router`] under
/// `/scim/v2` inside the authenticated surface.
pub fn router() -> Router<ApiState> {
	Router::new()
		// Discovery.
		.route(
			"/ServiceProviderConfig",
			get(service::service_provider_config),
		)
		.route("/Schemas", get(service::schemas))
		.route("/ResourceTypes", get(service::resource_types))
		// Users.
		.route("/Users", get(users::list_users).post(users::create_user))
		.route(
			"/Users/{id}",
			get(users::get_user)
				.put(users::put_user)
				.patch(users::patch_user)
				.delete(users::delete_user),
		)
		// Groups (501).
		.route(
			"/Groups",
			get(groups::list_groups).post(groups::create_group),
		)
		.route(
			"/Groups/{id}",
			get(groups::get_group)
				.put(groups::put_group)
				.patch(groups::patch_group)
				.delete(groups::delete_group),
		)
}

#[cfg(test)]
#[path = "scim_tests.rs"]
mod tests;
