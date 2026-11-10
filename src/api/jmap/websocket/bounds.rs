//! What one JMAP WebSocket may cost the server: how many a caller may hold
//! open at once, and how long one may sit without a frame.
//!
//! A socket that has been upgraded keeps its place in the listener's
//! connection count for as long as it lives, and nothing else ends it while
//! the client stays silent, so both bounds are enforced here.

use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, close_code};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::super::Principal;
use super::super::caller_slots::{CallerSlot, Work};
use crate::api::state::ApiState;

/// Sockets one caller may hold open at once, the same cap as the event-source
/// streams ([`super::super::event_source::MAX_STREAMS_PER_CALLER`]). A client
/// needs one socket; the rest is room for a reconnect that overlaps the old
/// connection while it is still being torn down.
pub(crate) const MAX_SOCKETS_PER_CALLER: usize = 4;

/// How long a socket may go without any frame, ping and pong included, before
/// the server closes it with 1001 (going away). The server sends no pings of
/// its own, so a client that wants an idle socket kept sends one inside this
/// window. It matches the longest event-source ping interval.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// A slot for one more socket of the caller behind `principal`, or the `429`
/// that refuses the upgrade, naming the limit it applied (RFC 8620 §3.6.1).
// The refusal is a whole response and is only built on the unhappy path.
#[allow(clippy::result_large_err)]
pub(super) fn take_slot(state: &ApiState, principal: &Principal) -> Result<CallerSlot, Response> {
	let Some(owner) = super::super::push_subscription::owner_of(state, principal) else {
		return Err(super::super::jmap_error(
			StatusCode::FORBIDDEN,
			"forbidden",
			"no caller identity",
		));
	};
	CallerSlot::take_for(state, &owner, Work::WebSocket, MAX_SOCKETS_PER_CALLER).ok_or_else(|| {
		let problem = super::super::limits::problem(
			"maxConcurrentWebSockets",
			StatusCode::TOO_MANY_REQUESTS,
			"too many open WebSockets for this credential",
		);
		(StatusCode::TOO_MANY_REQUESTS, axum::Json(problem)).into_response()
	})
}

/// The next message of `socket`, or `None` when the connection ended or sat
/// idle for [`IDLE_TIMEOUT`]; an idle socket is sent a close frame first. The
/// timer restarts at every message, and runs on the runtime clock.
pub(super) async fn recv_or_idle(socket: &mut WebSocket) -> Option<Message> {
	match tokio::time::timeout(IDLE_TIMEOUT, socket.recv()).await {
		Ok(Some(Ok(message))) => Some(message),
		Ok(_) => None,
		Err(_) => {
			let close = CloseFrame {
				code: close_code::AWAY,
				reason: "idle".into(),
			};
			socket.send(Message::Close(Some(close))).await.ok();
			None
		}
	}
}
