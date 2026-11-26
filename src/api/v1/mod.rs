//! `/api/v1` routes. Each route module mirrors its path.

mod accounts;
mod aliases;
mod archive;
mod auth;
mod bans;
mod deliveries;
mod display_name;
mod dns;
#[cfg(test)]
pub(crate) use dns::parity as dns_parity;
mod domains;
mod health;
mod mailboxes;
mod masked;
mod queue;
mod queue_access;
mod queue_detail;
mod scope;
mod send;
mod send_cancel;
#[cfg(test)]
pub(crate) use send::sink_refusal;
pub(crate) mod send_dry_limits;
mod send_from;
mod send_message;
mod send_recipient;
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
		.route("/dns/records", get(dns::records))
		.route("/dns/verify", get(dns::verify))
		.route("/health", get(health::all))
		.route("/health/{area}", get(health::one))
		.route(
			"/bans",
			get(bans::list)
				.post(bans::ban)
				.layer(DefaultBodyLimit::max(bans::MAX_BODY)),
		)
		.route(
			"/bans/allow",
			get(bans::allow_list)
				.post(bans::allow_add)
				.layer(DefaultBodyLimit::max(bans::MAX_BODY)),
		)
		.route(
			"/bans/allow/{cidr}",
			axum::routing::delete(bans::allow_remove),
		)
		.route("/bans/{subject}", axum::routing::delete(bans::unban))
		.route("/domains", get(domains::list).post(domains::add::add))
		.route(
			"/domains/{domain}",
			get(domains::domain::get)
				.put(domains::set::set)
				.delete(domains::change::remove),
		)
		.route("/domains/{domain}/enable", post(domains::switch::enable))
		.route("/domains/{domain}/disable", post(domains::switch::disable))
		.route("/domains/{domain}/aliases", post(domains::aliases::add))
		.route(
			"/domains/{domain}/aliases/{alias}",
			axum::routing::delete(domains::aliases::remove),
		)
		.route(
			"/aliases",
			get(aliases::list)
				.post(aliases::create)
				.layer(DefaultBodyLimit::max(16 * 1024)),
		)
		.route("/aliases/{alias}", axum::routing::delete(aliases::remove))
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
		.route("/events", get(crate::api::events::get))
		.route("/queue", get(queue::list))
		.route("/queue/destinations", get(queue_detail::destinations))
		.route("/queue/{id}", get(queue_detail::show).delete(queue::remove))
		.route("/queue/{id}/retry", post(queue_detail::retry))
		.route("/queue/{id}/hold", post(queue_detail::hold))
		.route("/queue/{id}/release", post(queue_detail::release))
		.route(
			"/suppression",
			get(suppression::list)
				.post(suppression::add)
				.layer(DefaultBodyLimit::max(4096)),
		)
		.route(
			"/suppression/{address}",
			axum::routing::delete(suppression::remove),
		)
		.route("/deliveries", get(deliveries::list))
		// Explicit body ceiling consistent with the SMTP message-size limit,
		// rather than relying on the framework default. The cap is the
		// operator-configured `max_message_size`, so the REST
		// `POST /api/v1/send` builder never goes above what the SMTP
		// `SIZE` and end-of-DATA checks accept.
		.route(
			"/send",
			post(send::send).layer(DefaultBodyLimit::max(max_message_size)),
		)
		.route("/send/{id}", axum::routing::delete(send_cancel::cancel))
}
