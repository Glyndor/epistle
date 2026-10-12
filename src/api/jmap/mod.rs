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
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::Principal;
use super::state::{ApiState, MatchedAuth};
use crate::api::api_keys::Scope;

/// Maximum accepted upload size, mirroring the `maxSizeUpload` advertised in the
/// Session resource (RFC 8620 §6.1). Uploads above this are rejected with a
/// `urn:ietf:params:jmap:error:limit` problem-details response.
pub const MAX_UPLOAD_SIZE: usize = 50_000_000;

/// Default media type when none is supplied or recorded (RFC 8620 §6.1).
const DEFAULT_BLOB_TYPE: &str = "application/octet-stream";

mod address_tokenizer;
pub(crate) mod blob_path;
mod blobs;
mod dispatcher;
mod download;
mod email;
pub use download::download;
mod email_submission;
mod limits;
pub use limits::{MAX_CALLS_IN_REQUEST, MAX_SIZE_REQUEST};
mod methods;
mod objects;
pub(crate) mod push_subscription;
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
					},
				}),
			)
		})
		.collect();
	let primary: serde_json::Map<String, Value> = accounts
		.keys()
		.next()
		.map(|id| (CORE_CAPABILITY.to_string(), Value::String(id.clone())))
		.into_iter()
		.collect();

	Json(json!({
		"capabilities": {
			CORE_CAPABILITY: {
				"maxSizeUpload": 50_000_000u64,
				"maxConcurrentUpload": 4u32,
				"maxSizeRequest": MAX_SIZE_REQUEST as u64,
				"maxConcurrentRequests": 4u32,
				"maxCallsInRequest": MAX_CALLS_IN_REQUEST as u32,
				"maxObjectsInGet": 500u32,
				"maxObjectsInSet": 500u32,
				"collationAlgorithms": [],
			},
			MAIL_CAPABILITY: {
				"maxMailboxesPerEmail": null,
				"maxMailboxDepth": null,
				"maxSizeMailboxName": 128u32,
				"maxSizeAttachmentsPerEmail": 50_000_000u64,
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
		},
		"accounts": accounts,
		"primaryAccounts": primary,
		"username": "",
		"apiUrl": "/jmap/api",
		"downloadUrl": "/jmap/download/{accountId}/{blobId}/{name}",
		"uploadUrl": "/jmap/upload/{accountId}",
		"eventSourceUrl": "/jmap/eventsource",
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
	Json(request): Json<Request>,
) -> axum::response::Response {
	let principal = Principal::for_token(&state, &auth);
	match dispatch_request(&state, &principal, request) {
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
) -> Result<Response, Value> {
	let calls = request.method_calls.len();
	if calls > limits::MAX_CALLS_IN_REQUEST {
		return Err(limits::too_many_calls());
	}
	// `PushSubscription/*` and `Core/echo` are session-scoped: they do not
	// carry an `accountId`. `Core/echo` touches nothing; the push
	// subscriptions are filtered by the caller that created them. The rest
	// of the methods need an account check; the
	// `state.auth_extension_for(principal)` helper, where one exists, calls
	// `state.require_scope` and the per-method handler does the principal
	// check on the `accountId` it pulls out of the arguments.
	let mut method_responses = Vec::with_capacity(calls);
	let mut resolver = Resolver::new(MAX_REQUEST_LIMITS);
	for MethodCall(name, args, call_id) in request.method_calls {
		// Resolve result back-references (`#`-prefixed args) against earlier
		// responses. The resolver bounds the cumulative cost of a chain
		// a request where each call's argument is a `#ResultOf`
		// reference to the previous result would, without the bound,
		// double the materialised data every step and reach hundreds
		// of MB on a 25-call chain. The first call that crosses the
		// bound is refused with `requestTooLarge` (RFC 8620 §3.7.2 /
		// §3.6.2); an unresolvable reference fails with
		// `invalidResultReference`.
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
			resolver.record_result(&response);
			method_responses.push(response);
			continue;
		}
		let response = match name.as_str() {
			// Core/echo returns its arguments unchanged (RFC 8620 §4).
			"Core/echo" => json!([name, args, call_id]),
			"Mailbox/set" => methods::mailbox_set(state, principal, &args, &call_id),
			"Email/set" => email::email_set(state, principal, &args, &call_id),
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
			_ => json!(["error", { "type": "unknownMethod" }, call_id]),
		};
		resolver.record_result(&response);
		method_responses.push(response);
	}
	Ok(Response { method_responses })
}

/// The scope a method call needs: `Write` to change stored data or push
/// subscriptions, `Send` to submit mail, `Read` for everything that returns
/// account data. `None` for `Core/echo`, which touches nothing, and for a
/// method this server does not know, which is answered `unknownMethod`.
fn required_scope(method: &str) -> Option<Scope> {
	match method {
		"Mailbox/set" | "Email/set" | "Email/copy" | "PushSubscription/set" => Some(Scope::Write),
		"EmailSubmission/set" => Some(Scope::Send),
		"Mailbox/get"
		| "Mailbox/query"
		| "Mailbox/changes"
		| "Mailbox/queryChanges"
		| "Email/get"
		| "Email/query"
		| "Email/changes"
		| "Email/queryChanges"
		| "Thread/get"
		| "Thread/changes"
		| "Identity/get"
		| "Quota/get"
		| "PushSubscription/get" => Some(Scope::Read),
		_ => None,
	}
}

/// The JMAP spec does not define a "forbidden" method error; `forbidden` is
/// the closest general-purpose failure (RFC 8620 §3.6.2) and is what other
/// servers emit for an authorised-but-not-allowed-permission call.
fn jmap_scope_error(call_id: &str) -> Value {
	json!(["error", { "type": "forbidden" }, call_id])
}

/// `POST /jmap/upload/{accountId}` (RFC 8620 §6.1): store an uploaded blob and
/// return its id, type and size. Blobs live in the account's partition,
/// `<data_dir>/blobs/accounts/<account>/`.
pub async fn upload(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Path(account): Path<String>,
	headers: HeaderMap,
	body: axum::body::Bytes,
) -> impl IntoResponse {
	let principal = Principal::for_token(&state, &auth);
	// `Write` scope: a read-only key must not be able to fill the quota or
	// the blob store with arbitrary bytes.
	if state
		.require_scope_for_principal(&principal, Scope::Write)
		.is_err()
	{
		return jmap_error(StatusCode::UNAUTHORIZED, "forbidden", "missing write scope");
	}
	let Some(view) = state.accounts().into_iter().find(|a| a.name == account) else {
		return jmap_error(StatusCode::NOT_FOUND, "notFound", "account not found");
	};
	if !principal.admits_account(&view.name, &view.addresses) {
		return jmap_error(StatusCode::NOT_FOUND, "notFound", "account not found");
	}
	// Reject anything over the advertised maxSizeUpload with the spec's limit
	// error (RFC 8620 §6.1) rather than a transport-level 413.
	if body.len() > MAX_UPLOAD_SIZE {
		return (
			StatusCode::PAYLOAD_TOO_LARGE,
			Json(json!({
				"type": "urn:ietf:params:jmap:error:limit",
				"limit": "maxSizeUpload",
				"status": 413,
				"detail": "upload exceeds maxSizeUpload",
			})),
		)
			.into_response();
	}
	// Enforce the account's storage quota before persisting (RFC 8620 §6.1:
	// upload may be refused once a limit is reached). A configured limit is the
	// hard cap; 0 means unlimited. Fail closed — reject when the blob would push
	// usage over the limit. We answer with the JMAP limit error rather than a
	// bare 413: the type is `urn:ietf:params:jmap:error:limit` (the only limit
	// error core defines) and `limit: "storage"` names the resource that was
	// hit, distinguishing an over-quota rejection from the per-request
	// `maxSizeUpload` one above. The HTTP status is 507 Insufficient Storage,
	// the closest standard code for "would exceed the account's storage".
	let limit = state.quota_limit();
	if limit > 0 {
		let usage = blobs::account_usage_bytes(state.data_dir(), &account, state.crypto());
		if usage.saturating_add(body.len() as u64) > limit {
			return (
				StatusCode::INSUFFICIENT_STORAGE,
				Json(json!({
					"type": "urn:ietf:params:jmap:error:limit",
					"limit": "storage",
					"status": 507,
					"detail": "upload would exceed the account storage quota",
				})),
			)
				.into_response();
		}
	}
	// Per-tenant aggregate storage cap (RFC 8620 §6.1; the same JMAP limit
	// type as the per-account quota above). Sits on top of the per-account
	// limit; either can fail and the rejection looks the same to the client.
	// Empty `tenant_limits` is the identity, no extra work.
	let account_addresses: Vec<String> = state
		.accounts()
		.into_iter()
		.find(|view| view.name == account)
		.map(|view| view.addresses)
		.unwrap_or_default();
	if let Err(message) = state.tenant_limits().check_aggregate_quota(
		state.store(),
		state.data_dir(),
		state.crypto(),
		&account_addresses,
		body.len() as u64,
	) {
		return (
			StatusCode::INSUFFICIENT_STORAGE,
			Json(json!({
				"type": "urn:ietf:params:jmap:error:limit",
				"limit": "tenant_storage",
				"status": 507,
				"detail": message,
			})),
		)
			.into_response();
	}
	// The blob's media type is the request Content-Type, echoed back and
	// persisted so downloads serve it (RFC 8620 §6.1).
	let content_type = headers
		.get(header::CONTENT_TYPE)
		.and_then(|value| value.to_str().ok())
		.filter(|value| !value.is_empty())
		.unwrap_or(DEFAULT_BLOB_TYPE)
		.to_string();
	// Minted as a `Uuid` and kept as one: the string form is only for the
	// response body, so nothing downstream can be handed a path fragment.
	let blob_id = uuid::Uuid::now_v7();
	// Encrypt the blob payload at rest like stored mail; the `.type` and
	// `.owner` sidecars stay plaintext metadata.
	let stored = match state.crypto().encode(&body) {
		Ok(stored) => stored,
		Err(_) => {
			return jmap_error(
				StatusCode::INTERNAL_SERVER_ERROR,
				"serverFail",
				"cannot store blob",
			);
		}
	};
	// The blob goes into the account's partition. An account whose name is
	// not one plain path component cannot have one, so the upload fails
	// rather than landing anywhere shared.
	let backend = state.blob_backend();
	let Some(partition) = crate::storage::BlobAccount::new(&account) else {
		return jmap_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			"serverFail",
			"cannot store blob",
		);
	};
	if backend.put(&partition, blob_id, "", &stored).await.is_err()
		|| backend
			.put(&partition, blob_id, ".type", content_type.as_bytes())
			.await
			.is_err()
		|| blobs::write_blob_owner(backend, blob_id, &partition)
			.await
			.is_err()
	{
		return jmap_error(
			StatusCode::INTERNAL_SERVER_ERROR,
			"serverFail",
			"cannot store blob",
		);
	}
	(
		StatusCode::OK,
		Json(json!({
			"accountId": account,
			"blobId": blob_id,
			"type": content_type,
			"size": body.len(),
		})),
	)
		.into_response()
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
