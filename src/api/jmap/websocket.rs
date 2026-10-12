//! JMAP over WebSocket (RFC 8887).
//!
//! `GET /jmap/ws` upgrades to a WebSocket carried under the same bearer auth as
//! the rest of the API. Each text frame is a JMAP WebSocket message object
//! tagged by `@type` (RFC 8887 §4):
//!
//! - `Request` — the same envelope as `POST /jmap/api` (`using`, `methodCalls`)
//!   plus an optional `id`. It is dispatched through the shared
//!   [`super::dispatch_request`], and answered with a `Response` echoing
//!   `requestId` when an `id` was given.
//! - `WebSocketPushEnable` / `WebSocketPushDisable` — opt the connection in or
//!   out of in-band push (RFC 8887 §5).
//! - anything else, or an unparseable frame — answered with a `RequestError`
//!   problem-details object (RFC 8887 §4.2); the connection is never dropped.
//!
//! When push is enabled, a `Request` whose dispatch changed an account's state
//! is followed by a `StateChange` frame describing the new state. The push is
//! **connection-scoped**: it is sent on the same socket to the client that made
//! the change. Full cross-connection / out-of-band delivery — POSTing to the
//! `url` of a `PushSubscription` — is OUT OF SCOPE here; the PushSubscription
//! objects (`push_subscription.rs`) round-trip through get/set but
//! nothing is delivered to them.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, State};
use axum::response::IntoResponse;
use serde_json::{Value, json};

use super::Principal;
use super::Request;
use crate::api::state::{ApiState, MatchedAuth};

/// `GET /jmap/ws` (RFC 8887 §3): upgrade to a WebSocket. Auth is already enforced
/// by the bearer-token middleware on the authenticated router; the captured
/// `MatchedAuth` is propagated into the per-connection loop so each frame is
/// dispatched against the same credential that opened it.
pub async fn ws_upgrade(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
	upgrade.on_upgrade(move |socket| serve(socket, state, auth))
}

/// Per-connection loop: read text frames, answer each, and emit any in-band push
/// frames. Binary frames are rejected with a `RequestError`; close/ping/pong are
/// left to the transport.
async fn serve(mut socket: WebSocket, state: ApiState, auth: MatchedAuth) {
	// Resolve the principal once when the connection opens; the WebSocket
	// carries the same credential across every frame on the socket, so
	// resolving it per frame would only repeat work.
	let principal = Principal::for_token(&state, &auth);
	let mut push = PushState::default();
	while let Some(Ok(message)) = socket.recv().await {
		let text = match message {
			Message::Text(text) => text.to_string(),
			Message::Binary(_) => {
				let error = request_error("notJSON", "binary frames are not accepted").to_string();
				if socket.send(Message::Text(error.into())).await.is_err() {
					return;
				}
				continue;
			}
			Message::Close(_) => return,
			Message::Ping(_) | Message::Pong(_) => continue,
		};
		for reply in handle_ws_message(&state, &principal, &text, &mut push) {
			if socket.send(Message::Text(reply.into())).await.is_err() {
				return;
			}
		}
	}
}

/// Whether the connection has opted into in-band push, and for which data types
/// (RFC 8887 §5.1: `WebSocketPushEnable.dataTypes`; `None` means all types).
#[derive(Default)]
pub struct PushState {
	enabled: bool,
	data_types: Option<Vec<String>>,
}

/// The JMAP data types whose state a successful `/set` may change, reported in a
/// `StateChange` (RFC 8620 §5.3). We do not track a per-type change log, so a
/// change to any of them is signalled together from one account-state token.
const STATEFUL_TYPES: [&str; 2] = ["Email", "Mailbox"];

/// Handle one decoded WebSocket frame, returning the frames to send back (zero,
/// one, or — for a state-changing `Request` with push enabled — a `Response`
/// followed by a `StateChange`). Pure with respect to the socket so it can be
/// unit-tested with JSON strings.
pub fn handle_ws_message(
	state: &ApiState,
	principal: &Principal,
	text: &str,
	push: &mut PushState,
) -> Vec<String> {
	let Ok(value) = serde_json::from_str::<Value>(text) else {
		return vec![request_error("notJSON", "frame is not valid JSON").to_string()];
	};
	match value.get("@type").and_then(Value::as_str) {
		Some("Request") => handle_request(state, principal, &value, push),
		Some("WebSocketPushEnable") => {
			push.enabled = true;
			push.data_types = value
				.get("dataTypes")
				.and_then(Value::as_array)
				.map(|types| {
					types
						.iter()
						.filter_map(|t| t.as_str().map(str::to_string))
						.collect()
				});
			Vec::new()
		}
		Some("WebSocketPushDisable") => {
			push.enabled = false;
			push.data_types = None;
			Vec::new()
		}
		Some(other) => {
			vec![request_error("unknownType", &format!("unsupported @type: {other}")).to_string()]
		}
		None => vec![request_error("notRequest", "missing @type").to_string()],
	}
}

/// Dispatch a WebSocket `Request` frame and build its `Response`, plus a
/// `StateChange` when push is enabled and a `/set` changed an account's state.
fn handle_request(
	state: &ApiState,
	principal: &Principal,
	value: &Value,
	push: &PushState,
) -> Vec<String> {
	// The envelope is the HTTP request shape plus an optional client `id`.
	let request: Request = match serde_json::from_value(value.clone()) {
		Ok(request) => request,
		Err(_) => {
			return vec![request_error("notRequest", "invalid Request envelope").to_string()];
		}
	};
	let request_id = value.get("id").and_then(Value::as_str).map(str::to_string);

	// Sample account state before and after dispatch so a successful /set that
	// actually changed stored mail can be reported (RFC 8887 §5.2). The list
	// is filtered through the principal so a domain-scoped connection does
	// not learn the existence of foreign tenants' state tokens.
	let accounts: Vec<String> = principal
		.admissible_accounts(&state.accounts())
		.into_iter()
		.map(|a| a.name.clone())
		.collect();
	let before: Vec<String> = accounts.iter().map(|a| state.account_state(a)).collect();
	let response = match super::dispatch_request(state, principal, request) {
		Ok(response) => response,
		Err(mut problem) => {
			problem["@type"] = json!("RequestError");
			return vec![problem.to_string()];
		}
	};

	let mut response_frame = serde_json::Map::new();
	response_frame.insert("@type".to_string(), json!("Response"));
	response_frame.insert(
		"methodResponses".to_string(),
		json!(response.method_responses),
	);
	if let Some(id) = request_id {
		response_frame.insert("requestId".to_string(), json!(id));
	}
	let mut frames = vec![Value::Object(response_frame).to_string()];

	if push.enabled
		&& let Some(state_change) = build_state_change(state, &accounts, &before, push)
	{
		frames.push(state_change.to_string());
	}
	frames
}

/// Build a `StateChange` for the accounts whose state token moved, restricted to
/// the push subscription's data types (RFC 8887 §5.2 / RFC 8620 §5.3). Returns
/// `None` when nothing changed.
fn build_state_change(
	state: &ApiState,
	accounts: &[String],
	before: &[String],
	push: &PushState,
) -> Option<Value> {
	let types: Vec<&str> = STATEFUL_TYPES
		.into_iter()
		.filter(|t| {
			push.data_types
				.as_ref()
				.is_none_or(|wanted| wanted.iter().any(|w| w == t))
		})
		.collect();
	if types.is_empty() {
		return None;
	}
	let mut changed = serde_json::Map::new();
	for (account, prior) in accounts.iter().zip(before) {
		let now = state.account_state(account);
		if &now != prior {
			let states: serde_json::Map<String, Value> = types
				.iter()
				.map(|t| ((*t).to_string(), json!(now)))
				.collect();
			changed.insert(account.clone(), Value::Object(states));
		}
	}
	if changed.is_empty() {
		return None;
	}
	Some(json!({ "@type": "StateChange", "changed": changed }))
}

/// A RFC 8887 §4.2 `RequestError`: a problem-details object carried in a frame
/// rather than closing the connection.
fn request_error(kind: &str, detail: &str) -> Value {
	json!({
		"@type": "RequestError",
		"type": format!("urn:ietf:params:jmap:error:{kind}"),
		"status": 400,
		"detail": detail,
	})
}

#[cfg(test)]
#[path = "websocket_tests.rs"]
mod tests;
