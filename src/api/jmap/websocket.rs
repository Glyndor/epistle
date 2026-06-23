//! JMAP over WebSocket (RFC 8887) and the PushSubscription objects (RFC 8620
//! §7.2).
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
//! objects round-trip through get/set but nothing is delivered to them.

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use serde_json::{Value, json};

use super::Request;
use crate::api::state::ApiState;

/// `GET /jmap/ws` (RFC 8887 §3): upgrade to a WebSocket. Auth is already enforced
/// by the bearer-token middleware on the authenticated router.
pub async fn ws_upgrade(
	State(state): State<ApiState>,
	upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
	upgrade.on_upgrade(move |socket| serve(socket, state))
}

/// Per-connection loop: read text frames, answer each, and emit any in-band push
/// frames. Binary frames are rejected with a `RequestError`; close/ping/pong are
/// left to the transport.
async fn serve(mut socket: WebSocket, state: ApiState) {
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
		for reply in handle_ws_message(&state, &text, &mut push) {
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
pub fn handle_ws_message(state: &ApiState, text: &str, push: &mut PushState) -> Vec<String> {
	let Ok(value) = serde_json::from_str::<Value>(text) else {
		return vec![request_error("notJSON", "frame is not valid JSON").to_string()];
	};
	match value.get("@type").and_then(Value::as_str) {
		Some("Request") => handle_request(state, &value, push),
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
fn handle_request(state: &ApiState, value: &Value, push: &PushState) -> Vec<String> {
	// The envelope is the HTTP request shape plus an optional client `id`.
	let request: Request = match serde_json::from_value(value.clone()) {
		Ok(request) => request,
		Err(_) => {
			return vec![request_error("notRequest", "invalid Request envelope").to_string()];
		}
	};
	let request_id = value.get("id").and_then(Value::as_str).map(str::to_string);

	// Sample account state before and after dispatch so a successful /set that
	// actually changed stored mail can be reported (RFC 8887 §5.2).
	let accounts: Vec<String> = state.accounts().into_iter().map(|a| a.name).collect();
	let before: Vec<String> = accounts.iter().map(|a| state.account_state(a)).collect();
	let response = super::dispatch_request(state, request);

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

/// `PushSubscription/get` (RFC 8620 §7.2): session-scoped, so it takes no
/// `accountId`. Returns the stored subscriptions, optionally filtered by `ids`.
pub fn push_subscription_get(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let wanted: Option<Vec<String>> = args.get("ids").and_then(Value::as_array).map(|ids| {
		ids.iter()
			.filter_map(|id| id.as_str().map(str::to_string))
			.collect()
	});
	let all = state.push_subscriptions();
	let list: Vec<Value> = all
		.into_iter()
		.filter(|sub| {
			wanted.as_ref().is_none_or(|ids| {
				sub.get("id")
					.and_then(Value::as_str)
					.is_some_and(|id| ids.iter().any(|w| w == id))
			})
		})
		.collect();
	json!(["PushSubscription/get", { "state": "0", "list": list, "notFound": [] }, call_id])
}

/// `PushSubscription/set` (RFC 8620 §7.2): create, update and destroy
/// session-scoped subscriptions. Subscriptions are validated and echoed but no
/// out-of-band delivery is performed (out of scope), so server-set fields are
/// minimal: an id and the client's `verificationCode` echo are not sent.
pub fn push_subscription_set(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let mut created = serde_json::Map::new();
	let mut not_created = serde_json::Map::new();
	let mut updated = serde_json::Map::new();
	let mut not_updated = serde_json::Map::new();
	let mut destroyed = Vec::new();
	let mut not_destroyed = serde_json::Map::new();

	state.with_push_subscriptions(|store| {
		if let Some(creates) = args.get("create").and_then(Value::as_object) {
			for (key, props) in creates {
				// A subscription must carry a delivery `url` (RFC 8620 §7.2).
				if props
					.get("url")
					.and_then(Value::as_str)
					.is_none_or(str::is_empty)
				{
					not_created.insert(
						key.clone(),
						json!({ "type": "invalidProperties", "properties": ["url"] }),
					);
					continue;
				}
				let id = uuid::Uuid::now_v7().to_string();
				let mut object = props.clone();
				if let Some(map) = object.as_object_mut() {
					map.insert("id".to_string(), json!(id));
					// We never verify or push, so report no pending keys.
					map.entry("verificationCode").or_insert(Value::Null);
				}
				store.push(object);
				created.insert(key.clone(), json!({ "id": id }));
			}
		}
		if let Some(updates) = args.get("update").and_then(Value::as_object) {
			for (id, patch) in updates {
				match store
					.iter_mut()
					.find(|sub| sub.get("id").and_then(Value::as_str) == Some(id.as_str()))
				{
					Some(sub) => {
						if let (Some(target), Some(patch)) =
							(sub.as_object_mut(), patch.as_object())
						{
							for (k, v) in patch {
								target.insert(k.clone(), v.clone());
							}
						}
						updated.insert(id.clone(), Value::Null);
					}
					None => {
						not_updated.insert(id.clone(), json!({ "type": "notFound" }));
					}
				}
			}
		}
		if let Some(ids) = args.get("destroy").and_then(Value::as_array) {
			for id in ids.iter().filter_map(Value::as_str) {
				let before = store.len();
				store.retain(|sub| sub.get("id").and_then(Value::as_str) != Some(id));
				if store.len() < before {
					destroyed.push(json!(id));
				} else {
					not_destroyed.insert(id.to_string(), json!({ "type": "notFound" }));
				}
			}
		}
	});

	json!([
		"PushSubscription/set",
		{
			"oldState": null, "newState": "0",
			"created": created, "notCreated": not_created,
			"updated": updated, "notUpdated": not_updated,
			"destroyed": destroyed, "notDestroyed": not_destroyed,
		},
		call_id
	])
}

#[cfg(test)]
#[path = "websocket_tests.rs"]
mod tests;
