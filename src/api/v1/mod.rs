//! `/api/v1` routes. Each route module mirrors its path.

mod accounts;
mod archive;
mod auth;
mod deliveries;
mod display_name;
mod domains;
mod mailboxes;
mod masked;
mod queue;
mod scope;
mod send;
#[cfg(test)]
pub(crate) use send::sink_refusal;
mod send_from;
mod send_message;
mod send_request;
mod status;
mod suppression;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

use super::state::ApiState;

/// The v1 route tree.
pub fn router(max_message_size: usize) -> Router<ApiState> {
	Router::new()
		.route("/status", get(status::get))
		.route("/openapi.json", get(crate::api::openapi::get))
		.route("/auth/verify", post(auth::verify))
		.route("/domains", get(domains::list))
		.route("/accounts", get(accounts::list).post(accounts::create))
		.route("/accounts/{name}", axum::routing::delete(accounts::remove))
		.route(
			"/accounts/{name}/password",
			axum::routing::put(accounts::set_password),
		)
		.route(
			"/accounts/{name}/display_name",
			axum::routing::put(display_name::set),
		)
		.route(
			"/accounts/{name}/totp",
			axum::routing::post(accounts::enroll_totp).delete(accounts::disable_totp),
		)
		.route("/accounts/{name}/mailboxes", get(mailboxes::list))
		.route(
			"/accounts/{name}/masked",
			get(masked::list).post(masked::create),
		)
		.route(
			"/accounts/{name}/masked/{address}",
			axum::routing::patch(masked::update).delete(masked::remove),
		)
		.route("/accounts/{name}/archive", get(archive::list))
		.route(
			"/accounts/{name}/archive/{id}/restore",
			axum::routing::post(archive::restore),
		)
		.route("/queue", get(queue::list))
		.route("/queue/{id}", axum::routing::delete(queue::remove))
		.route("/suppression", get(suppression::list))
		.route(
			"/suppression/{address}",
			axum::routing::delete(suppression::remove),
		)
		.route("/deliveries", get(deliveries::list))
		// Explicit body ceiling consistent with the SMTP message-size limit,
		// rather than relying on the framework default. The cap is the
		// operator-configured `[server] max_message_size`, so the REST
		// `POST /api/v1/send` builder never goes above what the SMTP
		// `SIZE` and end-of-DATA checks accept.
		.route(
			"/send",
			post(send::send).layer(DefaultBodyLimit::max(max_message_size)),
		)
}
