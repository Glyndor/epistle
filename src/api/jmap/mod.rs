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
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::state::ApiState;

/// Maximum accepted upload size, mirroring the `maxSizeUpload` advertised in the
/// Session resource (RFC 8620 §6.1). Uploads above this are rejected with a
/// `urn:ietf:params:jmap:error:limit` problem-details response.
pub const MAX_UPLOAD_SIZE: usize = 50_000_000;

/// Default media type when none is supplied or recorded (RFC 8620 §6.1).
const DEFAULT_BLOB_TYPE: &str = "application/octet-stream";

mod email;
mod methods;
mod objects;
pub mod websocket;

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
pub async fn api(State(state): State<ApiState>, Json(request): Json<Request>) -> Json<Response> {
	Json(dispatch_request(&state, request))
}

/// Dispatch a request envelope's method calls and collect the responses
/// (RFC 8620 §3.3–§3.7). Shared by the HTTP `POST /jmap/api` handler and the
/// WebSocket transport (RFC 8887), so the two never diverge. Pure aside from the
/// data-dir/state mutations the individual methods perform.
pub fn dispatch_request(state: &ApiState, request: Request) -> Response {
	let mut method_responses = Vec::with_capacity(request.method_calls.len());
	for MethodCall(name, args, call_id) in request.method_calls {
		// Resolve result back-references (`#`-prefixed args) against earlier
		// responses; an unresolvable reference fails just that call (RFC 8620 §3.7).
		let args = match resolve_references(args, &method_responses) {
			Ok(args) => args,
			Err(()) => {
				method_responses.push(json!([
					"error",
					{ "type": "invalidResultReference" },
					call_id
				]));
				continue;
			}
		};
		method_responses.push(match name.as_str() {
			// Core/echo returns its arguments unchanged (RFC 8620 §4).
			"Core/echo" => json!([name, args, call_id]),
			"Mailbox/get" => methods::mailbox_get(state, &args, &call_id),
			"Mailbox/set" => methods::mailbox_set(state, &args, &call_id),
			"Mailbox/query" => methods::mailbox_query(state, &args, &call_id),
			"Email/query" => methods::email_query(state, &args, &call_id),
			"Email/get" => methods::email_get(state, &args, &call_id),
			"Thread/get" => methods::thread_get(state, &args, &call_id),
			// We do not track a change log, so /changes and /queryChanges are
			// not calculable (RFC 8620 §5.2, §5.6); report it per spec rather
			// than unknownMethod.
			"Mailbox/changes"
			| "Email/changes"
			| "Thread/changes"
			| "Mailbox/queryChanges"
			| "Email/queryChanges" => methods::cannot_calculate_changes(state, &args, &call_id),
			"Email/set" => email::email_set(state, &args, &call_id),
			"Email/copy" => email::email_copy(state, &args, &call_id),
			"Identity/get" => methods::identity_get(state, &args, &call_id),
			"Quota/get" => methods::quota_get(state, &args, &call_id),
			"EmailSubmission/set" => methods::email_submission_set(state, &args, &call_id),
			// PushSubscription objects are session-scoped, not per-account
			// (RFC 8620 §7.2).
			"PushSubscription/get" => websocket::push_subscription_get(state, &args, &call_id),
			"PushSubscription/set" => websocket::push_subscription_set(state, &args, &call_id),
			_ => json!(["error", { "type": "unknownMethod" }, call_id]),
		});
	}
	Response { method_responses }
}

/// Replace each `#`-prefixed argument (a ResultReference) with the value pulled
/// from an earlier method's result, per RFC 8620 §3.7. Returns `Err(())` if any
/// reference cannot be resolved (the caller turns that into an error response).
fn resolve_references(mut args: Value, prior: &[Value]) -> Result<Value, ()> {
	let Some(object) = args.as_object_mut() else {
		return Ok(args);
	};
	let references: Vec<String> = object
		.keys()
		.filter(|key| key.starts_with('#'))
		.cloned()
		.collect();
	for key in references {
		let reference = object.remove(&key).expect("key present");
		let resolved = resolve_reference(&reference, prior).ok_or(())?;
		object.insert(key[1..].to_string(), resolved);
	}
	Ok(args)
}

/// Resolve one ResultReference `{resultOf, name, path}` against the prior
/// `[name, arguments, callId]` responses.
fn resolve_reference(reference: &Value, prior: &[Value]) -> Option<Value> {
	let result_of = reference.get("resultOf")?.as_str()?;
	let name = reference.get("name")?.as_str()?;
	let path = reference.get("path")?.as_str()?;
	let response = prior.iter().find(|response| {
		response.get(0).and_then(Value::as_str) == Some(name)
			&& response.get(2).and_then(Value::as_str) == Some(result_of)
	})?;
	pointer_with_wildcard(response.get(1)?, path)
}

/// JSON Pointer (RFC 6901) extended with the JMAP `*` wildcard: a `/*` segment
/// maps the rest of the path over an array, flattening one level of array
/// results (RFC 8620 §3.7).
fn pointer_with_wildcard(value: &Value, path: &str) -> Option<Value> {
	let Some(star) = path.find("/*") else {
		return value.pointer(path).cloned();
	};
	let (before, rest) = path.split_at(star);
	let rest = &rest[2..]; // drop the "/*"
	let array = value.pointer(before)?.as_array()?;
	let mut out = Vec::new();
	for item in array {
		let resolved = if rest.is_empty() {
			item.clone()
		} else {
			pointer_with_wildcard(item, rest)?
		};
		match resolved {
			Value::Array(items) => out.extend(items),
			other => out.push(other),
		}
	}
	Some(Value::Array(out))
}

#[cfg(test)]
#[path = "jmap_backref_tests.rs"]
mod backref_tests;

/// `GET /jmap/download/{accountId}/{blobId}/{name}` (RFC 8620 §6.2): return the
/// raw bytes of a stored message or an uploaded blob, by id.
pub async fn download(
	State(state): State<ApiState>,
	Path((account, blob_id, _name)): Path<(String, String, String)>,
) -> impl IntoResponse {
	if !state.accounts().iter().any(|a| a.name == account) {
		return jmap_error(StatusCode::NOT_FOUND, "notFound", "account not found");
	}
	let bytes = objects::find_email_raw(state.data_dir(), &account, &blob_id, state.crypto())
		.or_else(|| read_blob(state.data_dir(), &blob_id, state.crypto()));
	match bytes {
		Some(bytes) => {
			// Serve the media type recorded at upload time; stored messages and
			// legacy blobs without a sidecar fall back to octet-stream.
			let content_type = read_blob_type(state.data_dir(), &blob_id)
				.unwrap_or_else(|| DEFAULT_BLOB_TYPE.to_string());
			([(header::CONTENT_TYPE, content_type)], bytes).into_response()
		}
		None => jmap_error(StatusCode::NOT_FOUND, "notFound", "blob not found"),
	}
}

/// `POST /jmap/upload/{accountId}` (RFC 8620 §6.1): store an uploaded blob and
/// return its id, type and size. Blobs live under `<data_dir>/blobs/<uuid>`.
pub async fn upload(
	State(state): State<ApiState>,
	Path(account): Path<String>,
	headers: HeaderMap,
	body: axum::body::Bytes,
) -> impl IntoResponse {
	if !state.accounts().iter().any(|a| a.name == account) {
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
		let usage = account_usage_bytes(state.data_dir(), &account, state.crypto());
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
	// The blob's media type is the request Content-Type, echoed back and
	// persisted so downloads serve it (RFC 8620 §6.1).
	let content_type = headers
		.get(header::CONTENT_TYPE)
		.and_then(|value| value.to_str().ok())
		.filter(|value| !value.is_empty())
		.unwrap_or(DEFAULT_BLOB_TYPE)
		.to_string();
	let blob_id = uuid::Uuid::now_v7().to_string();
	let dir = state.data_dir().join("blobs");
	// Encrypt the blob payload at rest like stored mail; the `.type` sidecar
	// stays plaintext metadata.
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
	if std::fs::create_dir_all(&dir).is_err()
		|| std::fs::write(dir.join(&blob_id), &stored).is_err()
		|| std::fs::write(dir.join(format!("{blob_id}.type")), &content_type).is_err()
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

/// Read an uploaded blob by id (rejecting any path separators in the id),
/// decoding the at-rest envelope. Fails closed: a blob that cannot be decrypted
/// is not returned rather than served as ciphertext.
fn read_blob(
	data_dir: &std::path::Path,
	blob_id: &str,
	crypto: &crate::storage::MessageCrypto,
) -> Option<Vec<u8>> {
	if uuid::Uuid::parse_str(blob_id).is_err() {
		return None;
	}
	let stored = std::fs::read(data_dir.join("blobs").join(blob_id)).ok()?;
	crypto.decode(&stored).ok()
}

/// Read the recorded media type of an uploaded blob, if any (the `.type`
/// sidecar written at upload time). Returns `None` for stored messages.
fn read_blob_type(data_dir: &std::path::Path, blob_id: &str) -> Option<String> {
	if uuid::Uuid::parse_str(blob_id).is_err() {
		return None;
	}
	std::fs::read_to_string(data_dir.join("blobs").join(format!("{blob_id}.type")))
		.ok()
		.filter(|value| !value.is_empty())
}

/// Bytes counted against an account's storage quota: its stored mail (every
/// message across INBOX and folders) plus the uploaded blob store. JMAP blobs
/// live in one shared `<data_dir>/blobs` pool that is not partitioned per
/// account, so the whole pool is counted — a conservative, fail-closed choice
/// that never under-counts usage when enforcing the quota on upload.
pub fn account_usage_bytes(
	data_dir: &std::path::Path,
	account: &str,
	crypto: &crate::storage::MessageCrypto,
) -> u64 {
	crate::imap::mailbox::account_usage(data_dir, account, crypto)
		.saturating_add(blobs_usage_bytes(data_dir))
}

/// Total size in bytes of the uploaded blob store, counting blob payloads and
/// their `.type` sidecars under `<data_dir>/blobs`.
fn blobs_usage_bytes(data_dir: &std::path::Path) -> u64 {
	let mut total = 0u64;
	let Ok(entries) = std::fs::read_dir(data_dir.join("blobs")) else {
		return 0;
	};
	for entry in entries.flatten() {
		if let Ok(meta) = entry.metadata()
			&& meta.is_file()
		{
			total = total.saturating_add(meta.len());
		}
	}
	total
}

/// Reclaim transient uploaded blobs (RFC 8620 §6.1: an uploaded blob that is
/// not referenced may be deleted). Delete every blob — payload and its `.type`
/// sidecar — whose payload was last modified more than `ttl` ago, returning the
/// number of blobs removed. Only the upload store under `<data_dir>/blobs` is
/// touched; stored mail under `<data_dir>/accounts` is never affected.
pub fn reclaim_blobs(data_dir: &std::path::Path, ttl: std::time::Duration) -> usize {
	let dir = data_dir.join("blobs");
	let Ok(entries) = std::fs::read_dir(&dir) else {
		return 0;
	};
	let now = std::time::SystemTime::now();
	let mut removed = 0;
	for entry in entries.flatten() {
		let name = entry.file_name();
		// Sidecars are reclaimed alongside their payload, not on their own.
		if name.to_str().is_some_and(|name| name.ends_with(".type")) {
			continue;
		}
		// Only act on well-formed blob ids; ignore anything else in the dir.
		let Some(blob_id) = name.to_str().filter(|id| uuid::Uuid::parse_str(id).is_ok()) else {
			continue;
		};
		let expired = entry
			.metadata()
			.and_then(|meta| meta.modified())
			.ok()
			.and_then(|modified| now.duration_since(modified).ok())
			.is_some_and(|age| age > ttl);
		if expired {
			let _ = std::fs::remove_file(dir.join(blob_id));
			let _ = std::fs::remove_file(dir.join(format!("{blob_id}.type")));
			removed += 1;
		}
	}
	removed
}
