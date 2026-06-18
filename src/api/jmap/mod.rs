//! JMAP (RFC 8620) foundation: the Session resource and the Core/echo method.
//!
//! This is the minimal, spec-valid entry point that opens the JMAP roadmap:
//! a client fetches the Session object to discover capabilities and the API
//! URL, then POSTs a request envelope whose method calls are dispatched here.
//! Only the mandatory `Core/echo` method is implemented so far.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::state::ApiState;

mod email;
mod methods;
mod objects;

/// JMAP core capability URN.
const CORE_CAPABILITY: &str = "urn:ietf:params:jmap:core";
/// JMAP mail capability URN (RFC 8621).
const MAIL_CAPABILITY: &str = "urn:ietf:params:jmap:mail";
/// JMAP submission capability URN (RFC 8621 §7) — carries identities.
const SUBMISSION_CAPABILITY: &str = "urn:ietf:params:jmap:submission";
/// JMAP quota capability URN (RFC 9425).
const QUOTA_CAPABILITY: &str = "urn:ietf:params:jmap:quota";

/// `GET /jmap/session`: the Session resource (RFC 8620 §2).
pub async fn session(State(state): State<ApiState>) -> Json<Value> {
	let accounts: serde_json::Map<String, Value> = state
		.accounts()
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
				"maxSizeRequest": 10_000_000u64,
				"maxConcurrentRequests": 4u32,
				"maxCallsInRequest": 16u32,
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
pub async fn api(State(state): State<ApiState>, Json(request): Json<Request>) -> Json<Response> {
	let mut method_responses = Vec::with_capacity(request.method_calls.len());
	for MethodCall(name, args, call_id) in request.method_calls {
		method_responses.push(match name.as_str() {
			// Core/echo returns its arguments unchanged (RFC 8620 §4).
			"Core/echo" => json!([name, args, call_id]),
			"Mailbox/get" => methods::mailbox_get(&state, &args, &call_id),
			"Mailbox/set" => methods::mailbox_set(&state, &args, &call_id),
			"Mailbox/query" => methods::mailbox_query(&state, &args, &call_id),
			"Email/query" => methods::email_query(&state, &args, &call_id),
			"Email/get" => methods::email_get(&state, &args, &call_id),
			"Thread/get" => methods::thread_get(&state, &args, &call_id),
			// We do not track a change log, so /changes is not calculable
			// (RFC 8620 §5.2); report it per spec rather than unknownMethod.
			"Mailbox/changes" | "Email/changes" | "Thread/changes" => {
				methods::cannot_calculate_changes(&state, &args, &call_id)
			}
			"Email/set" => email::email_set(&state, &args, &call_id),
			"Email/copy" => email::email_copy(&state, &args, &call_id),
			"Identity/get" => methods::identity_get(&state, &args, &call_id),
			"Quota/get" => methods::quota_get(&state, &args, &call_id),
			"EmailSubmission/set" => methods::email_submission_set(&state, &args, &call_id),
			_ => json!(["error", { "type": "unknownMethod" }, call_id]),
		});
	}
	Json(Response { method_responses })
}

/// `GET /jmap/download/{accountId}/{blobId}/{name}` (RFC 8620 §6.2): return the
/// raw bytes of a stored message or an uploaded blob, by id.
pub async fn download(
	State(state): State<ApiState>,
	Path((account, blob_id, _name)): Path<(String, String, String)>,
) -> impl IntoResponse {
	if !state.accounts().iter().any(|a| a.name == account) {
		return (StatusCode::NOT_FOUND, "account not found").into_response();
	}
	let bytes = objects::find_email_raw(state.data_dir(), &account, &blob_id)
		.or_else(|| read_blob(state.data_dir(), &blob_id));
	match bytes {
		Some(bytes) => {
			([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
		}
		None => (StatusCode::NOT_FOUND, "blob not found").into_response(),
	}
}

/// `POST /jmap/upload/{accountId}` (RFC 8620 §6.1): store an uploaded blob and
/// return its id, type and size. Blobs live under `<data_dir>/blobs/<uuid>`.
pub async fn upload(
	State(state): State<ApiState>,
	Path(account): Path<String>,
	body: axum::body::Bytes,
) -> impl IntoResponse {
	if !state.accounts().iter().any(|a| a.name == account) {
		return (StatusCode::NOT_FOUND, "account not found").into_response();
	}
	let blob_id = uuid::Uuid::now_v7().to_string();
	let dir = state.data_dir().join("blobs");
	if std::fs::create_dir_all(&dir).is_err() || std::fs::write(dir.join(&blob_id), &body).is_err()
	{
		return (StatusCode::INTERNAL_SERVER_ERROR, "cannot store blob").into_response();
	}
	(
		StatusCode::CREATED,
		Json(json!({
			"accountId": account,
			"blobId": blob_id,
			"type": "application/octet-stream",
			"size": body.len(),
		})),
	)
		.into_response()
}

/// Read an uploaded blob by id (rejecting any path separators in the id).
fn read_blob(data_dir: &std::path::Path, blob_id: &str) -> Option<Vec<u8>> {
	if uuid::Uuid::parse_str(blob_id).is_err() {
		return None;
	}
	std::fs::read(data_dir.join("blobs").join(blob_id)).ok()
}
