//! `/api/v1` routes. Each route module mirrors its path.

mod accounts;
mod domains;
mod mailboxes;
mod queue;
mod send;
mod status;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

use super::state::ApiState;

/// The v1 route tree.
pub fn router() -> Router<ApiState> {
	Router::new()
		.route("/status", get(status::get))
		.route("/domains", get(domains::list))
		.route("/accounts", get(accounts::list).post(accounts::create))
		.route("/accounts/{name}", axum::routing::delete(accounts::remove))
		.route(
			"/accounts/{name}/password",
			axum::routing::put(accounts::set_password),
		)
		.route(
			"/accounts/{name}/totp",
			axum::routing::post(accounts::enroll_totp).delete(accounts::disable_totp),
		)
		.route("/accounts/{name}/mailboxes", get(mailboxes::list))
		.route("/queue", get(queue::list))
		.route("/queue/{id}", axum::routing::delete(queue::remove))
		// Explicit body ceiling consistent with the SMTP message-size limit,
		// rather than relying on the framework default.
		.route(
			"/send",
			post(send::send).layer(DefaultBodyLimit::max(
				crate::smtp::session::MAX_MESSAGE_SIZE,
			)),
		)
}
