//! JMAP (RFC 8620) Core: the Session resource and the request/response method
//! framework.
//!
//! A client fetches the Session object to discover capabilities and the API
//! URL, then POSTs a request envelope whose method calls are dispatched here.
//! Calls are answered in order, with result back-references (`#`-prefixed
//! arguments) resolved against earlier responses (RFC 8620 §3.7). `Core/echo`
//! plus the Mail methods (Mailbox/Email/Thread/Identity/Quota/EmailSubmission)
//! are wired in the dispatch below.

use axum::Json;
use axum::extract::{Extension, FromRequest, Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::Principal;
use super::state::{ApiState, MatchedAuth};
use crate::api::api_keys::Scope;
use caller_slots::{CallerSlot, Work};
use sieve_capability::SIEVE_CAPABILITY;

/// Default media type when none is supplied or recorded (RFC 8620 §6.1).
const DEFAULT_BLOB_TYPE: &str = "application/octet-stream";

mod address_tokenizer;
pub(crate) mod blob_path;
mod blobs;
pub(crate) mod caller_slots;
mod dispatcher;
mod download;
mod email;
mod email_build;
pub mod event_source;
pub use download::download;
mod email_submission;
mod upload_api;
use scope::{jmap_scope_error, required_scope};
pub use upload_api::upload;
mod uploads;
pub use uploads::Uploads;
pub(crate) mod limits;
pub use limits::{
	MAX_CALLS_IN_REQUEST, MAX_CONCURRENT_REQUESTS, MAX_CONCURRENT_UPLOAD, MAX_OBJECTS_IN_GET,
	MAX_OBJECTS_IN_SET, MAX_SIZE_REQUEST,
};
mod mailbox_set;
mod methods;
mod objects;
pub(crate) use objects::email_body_for_fuzzing;
pub(crate) mod push_subscription;
mod scope;
mod send_gate;
mod sieve;
mod sieve_blob;
use sieve::{
	sieve_capability, sieve_content, sieve_script, sieve_script_query, sieve_script_set,
	sieve_script_validate,
};
mod vacation_response;
pub mod websocket;

mod fold;
mod query_changes;
pub(crate) mod state;

pub(crate) use dispatcher::MAX_REQUEST_LIMITS;
use dispatcher::{ResolveError, Resolver};

pub use blobs::{account_usage_bytes, backfill_blob_ownership, reclaim_blobs};

#[cfg(test)]
pub(crate) use blobs::read_blob_owner;

/// JMAP core capability URN.
const CORE_CAPABILITY: &str = "urn:ietf:params:jmap:core";
/// JMAP mail capability URN (RFC 8621).
const MAIL_CAPABILITY: &str = "urn:ietf:params:jmap:mail";
/// JMAP submission capability URN (RFC 8621 §7) — carries identities.
const SUBMISSION_CAPABILITY: &str = "urn:ietf:params:jmap:submission";
/// JMAP quota capability URN (RFC 9425).
const QUOTA_CAPABILITY: &str = "urn:ietf:params:jmap:quota";
/// JMAP over WebSocket capability URN (RFC 8887).
const WEBSOCKET_CAPABILITY: &str = "urn:ietf:params:jmap:websocket";
/// JMAP vacation-response capability URN (RFC 8621 §8.3): an account
/// advertises it when the account can read and set its vacation setting.
const VACATION_CAPABILITY: &str = "urn:ietf:params:jmap:vacationresponse";

/// `GET /jmap/session`: the Session resource (RFC 8620 §2).
pub async fn session(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
) -> Json<Value> {
	let principal = Principal::for_token(&state, &auth);
	let views = state.accounts();
	let accounts: serde_json::Map<String, Value> = principal
		.admissible_accounts(&views)
		.into_iter()
		.map(|account| {
			(
				account.name.clone(),
				json!({
					"name": account.name,
					"isPersonal": true,
					"isReadOnly": false,
					"accountCapabilities": {
						CORE_CAPABILITY: {}, MAIL_CAPABILITY: {},
						SUBMISSION_CAPABILITY: {}, QUOTA_CAPABILITY: {},
						VACATION_CAPABILITY: {},
						SIEVE_CAPABILITY: sieve_capability::account_value(),
					},
				}),
			)
		})
		.collect();
	let primary: serde_json::Map<String, Value> = accounts
		.keys()
		.next()
		.into_iter()
		.flat_map(|id| {
			[CORE_CAPABILITY, SIEVE_CAPABILITY]
				.map(|capability| (capability.to_string(), Value::String(id.clone())))
		})
		.collect();

	// The Session resource advertises the configured cap, not a hard-coded
	// constant, so what the client is told and what the handlers enforce
	// cannot drift. `maxSizeUpload` is the same number the upload route's
	// body limit applies (configured `max_message_size`), and the
	// per-attachment bound is the same base minus the headroom that the
	// rest of the message needs for headers and the body itself.
	let max_message_size = state.max_message_size();
	let max_size_attachments_per_email =
		max_message_size.saturating_sub(limits::ATTACHMENT_HEADROOM) / 78 * 76 / 4 * 3;
	Json(json!({
		"capabilities": {
			CORE_CAPABILITY: {
				"maxSizeUpload": max_message_size as u64,
				"maxConcurrentUpload": MAX_CONCURRENT_UPLOAD as u32,
				"maxSizeRequest": MAX_SIZE_REQUEST as u64,
				"maxConcurrentRequests": MAX_CONCURRENT_REQUESTS as u32,
				"maxCallsInRequest": MAX_CALLS_IN_REQUEST as u32,
				"maxObjectsInGet": MAX_OBJECTS_IN_GET as u32,
				"maxObjectsInSet": MAX_OBJECTS_IN_SET as u32,
				"collationAlgorithms": [],
			},
			MAIL_CAPABILITY: {
				"maxMailboxesPerEmail": null,
				"maxMailboxDepth": null,
				"maxSizeMailboxName": 128u32,
				"maxSizeAttachmentsPerEmail": max_size_attachments_per_email as u64,
				"emailQuerySortOptions": [],
				"mayCreateTopLevelMailbox": true,
			},
			SUBMISSION_CAPABILITY: {
				"maxDelayedSend": 0u32,
				"submissionExtensions": {},
			},
			QUOTA_CAPABILITY: {},
			// JMAP over WebSocket (RFC 8887 §2): a relative `/jmap/ws` URL, like
			// the other URLs above. `supportsPush` advertises in-band StateChange
			// pushes over the same socket (RFC 8887 §5).
			WEBSOCKET_CAPABILITY: {
				"url": "/jmap/ws",
				"supportsPush": true,
			},
			VACATION_CAPABILITY: {},
			SIEVE_CAPABILITY: sieve_capability::session_value(),
		},
		"accounts": accounts,
		"primaryAccounts": primary,
		"username": "",
		"apiUrl": "/jmap/api",
		"downloadUrl": "/jmap/download/{accountId}/{blobId}/{name}",
		"uploadUrl": "/jmap/upload/{accountId}",
		// RFC 8620 §7.3: a URI Template carrying the three variables.
		"eventSourceUrl": "/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
		"state": "0",
	}))
}

/// One method call `[name, arguments, callId]` (RFC 8620 §3.2).
#[derive(Deserialize)]
pub struct MethodCall(String, Value, String);

/// A JMAP request envelope (RFC 8620 §3.3). The `using` capability list is
/// accepted and ignored until capability negotiation is implemented.
#[derive(Deserialize)]
pub struct Request {
	#[serde(rename = "methodCalls")]
	pub method_calls: Vec<MethodCall>,
}

/// A JMAP response envelope.
#[derive(Serialize)]
pub struct Response {
	#[serde(rename = "methodResponses")]
	pub method_responses: Vec<Value>,
}

/// `POST /jmap/api`: dispatch each method call, returning the responses.
pub async fn api(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	request: axum::extract::Request,
) -> axum::response::Response {
	let principal = Principal::for_token(&state, &auth);
	// The slot is held from before the body is read until the response is
	// built, so a request counts against `maxConcurrentRequests` for as long
	// as the server is busy with it.
	let Some(_slot) = CallerSlot::take(
		&state,
		&principal,
		Work::Request,
		limits::MAX_CONCURRENT_REQUESTS,
	) else {
		let problem =
			limits::too_many_concurrent("maxConcurrentRequests", limits::MAX_CONCURRENT_REQUESTS);
		return (StatusCode::TOO_MANY_REQUESTS, Json(problem)).into_response();
	};
	// A body over the route's cap (`maxSizeRequest`) is answered with the
	// RFC 8620 `limit` problem naming it, not axum's plain-text 413.
	let request = match Json::<Request>::from_request(request, &()).await {
		Ok(Json(request)) => request,
		Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
			let problem = limits::request_too_large();
			return (StatusCode::PAYLOAD_TOO_LARGE, Json(problem)).into_response();
		}
		Err(rejection) => return rejection.into_response(),
	};
	// Uploaded blobs an `Email/set` create names are read here, where the
	// blob backend can be awaited; dispatch itself is synchronous.
	let uploads = Uploads::prefetch(&state, &principal, &request).await;
	match dispatch_request(&state, &principal, request, &uploads) {
		Ok(response) => Json(response).into_response(),
		Err(problem) => (StatusCode::BAD_REQUEST, Json(problem)).into_response(),
	}
}

/// Dispatch a request envelope's method calls and collect the responses
/// (RFC 8620 §3.3–§3.7). Shared by the HTTP `POST /jmap/api` handler and the
/// WebSocket transport (RFC 8887), so the two never diverge. Pure aside from the
/// data-dir/state mutations the individual methods perform.
///
/// A request over `maxCallsInRequest` is refused here, before anything is
/// allocated or run, with the RFC 8620 `limit` problem each transport
/// returns in its own framing.
pub fn dispatch_request(
	state: &ApiState,
	principal: &Principal,
	request: Request,
	uploads: &Uploads,
) -> Result<Response, Value> {
	let calls = request.method_calls.len();
	if calls > limits::MAX_CALLS_IN_REQUEST {
		return Err(limits::too_many_calls());
	}
	// `PushSubscription/*` and `Core/echo` are session-scoped: they do not
	// carry an `accountId`. `Core/echo` touches nothing; the push
	// subscriptions are filtered by the caller that created them. The rest
	// of the methods need an account check: the scope each call needs is
	// checked below with `state.require_scope_for_principal`, and the
	// per-method handler does the principal check on the `accountId` it
	// pulls out of the arguments.
	let mut method_responses = Vec::with_capacity(calls);
	let mut resolver = Resolver::new(MAX_REQUEST_LIMITS);
	for MethodCall(name, args, call_id) in request.method_calls {
		// Resolve result back-references (`#`-prefixed args) against earlier
		// responses. Without a bound, a request where each call's argument
		// is a `#ResultOf` reference to the previous result would double
		// the materialised data every step and reach hundreds of MB on a
		// 25-call chain. A call with a reference resolving to more
		// objects than maxObjectsInGet/maxObjectsInSet, or whose
		// references push the request's resolved bytes past
		// maxSizeRequest, is refused with `requestTooLarge`; an
		// unresolvable reference fails with `invalidResultReference`.
		let args = match resolver.resolve(&args, &method_responses) {
			Ok(args) => args,
			Err(ResolveError::TooLarge) => {
				method_responses.push(json!([
					"error",
					{ "type": "requestTooLarge" },
					call_id
				]));
				continue;
			}
			Err(ResolveError::Unresolvable) => {
				method_responses.push(json!([
					"error",
					{ "type": "invalidResultReference" },
					call_id
				]));
				continue;
			}
		};
		// Scope tightening: the middleware lets any scoped key through to
		// `POST /jmap/api`, so each method call is checked here against the
		// scope it needs ([`required_scope`]). Scopes are independent: a key
		// issued only to write or only to send does not read the mailbox, and
		// a read-only key does not reach `Mailbox/set`,
		// `EmailSubmission/set`, etc. The check runs against the resolved
		// principal so handlers do not re-look-up the bearer.
		if let Some(scope) = required_scope(&name)
			&& state.require_scope_for_principal(principal, scope).is_err()
		{
			let response = jmap_scope_error(&call_id);
			method_responses.push(response);
			continue;
		}
		if limits::too_many_objects(&name, &args) {
			let response = json!(["error", { "type": "requestTooLarge" }, call_id]);
			method_responses.push(response);
			continue;
		}
		let response = match name.as_str() {
			// Core/echo returns its arguments unchanged (RFC 8620 §4).
			"Core/echo" => json!([name, args, call_id]),
			"Mailbox/set" => mailbox_set::mailbox_set(state, principal, &args, &call_id),
			"Email/set" => email::email_set(state, principal, &args, &call_id, uploads),
			"Email/copy" => email::email_copy(state, principal, &args, &call_id),
			"EmailSubmission/set" => {
				email_submission::email_submission_set(state, principal, &args, &call_id)
			}
			"PushSubscription/set" => push_subscription::set(state, principal, &args, &call_id),
			"Mailbox/get" => methods::mailbox_get(state, principal, &args, &call_id),
			"Mailbox/query" => methods::mailbox_query(state, principal, &args, &call_id),
			"Email/query" => methods::email_query(state, principal, &args, &call_id),
			"Email/get" => methods::email_get(state, principal, &args, &call_id),
			"Thread/get" => methods::thread_get(state, principal, &args, &call_id),
			// `/changes` answers against the per-type change log
			// (RFC 8620 §5.2). The method name tells the handler which
			// counter to compare the since-state against.
			"Mailbox/changes" | "Email/changes" | "Thread/changes" => {
				state::changes(state, principal, &args, &call_id, name.as_str())
			}
			"Mailbox/queryChanges" => query_changes::mailbox(state, principal, &args, &call_id),
			"Email/queryChanges" => query_changes::email(state, principal, &args, &call_id),
			"Identity/get" => methods::identity_get(state, principal, &args, &call_id),
			"Quota/get" => methods::quota_get(state, principal, &args, &call_id),
			"PushSubscription/get" => push_subscription::get(state, principal, &args, &call_id),
			"VacationResponse/get" => vacation_response::get(state, principal, &args, &call_id),
			"VacationResponse/set" => vacation_response::set(state, principal, &args, &call_id),
			"SieveScript/get" => sieve_script::get(state, principal, &args, &call_id),
			"SieveScript/query" => sieve_script_query::query(state, principal, &args, &call_id),
			"SieveScript/set" => sieve_script_set::set(state, principal, &args, &call_id, uploads),
			"SieveScript/validate" => {
				sieve_script_validate::validate(state, principal, &args, &call_id, uploads)
			}
			_ => json!(["error", { "type": "unknownMethod" }, call_id]),
		};
		method_responses.push(response);
	}
	Ok(Response { method_responses })
}
/// Build a JMAP problem-details error response (RFC 8620 §3.6.1): a JSON body
/// `{ "type": "urn:ietf:params:jmap:error:<kind>", ... }` with the HTTP status.
fn jmap_error(status: StatusCode, kind: &str, detail: &str) -> axum::response::Response {
	(
		status,
		Json(json!({
			"type": format!("urn:ietf:params:jmap:error:{kind}"),
			"status": status.as_u16(),
			"detail": detail,
		})),
	)
		.into_response()
}
