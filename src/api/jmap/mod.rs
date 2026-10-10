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
mod email;
mod methods;
mod objects;
pub mod websocket;

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
pub async fn api(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Json(request): Json<Request>,
) -> Json<Response> {
	Json(dispatch_request(&state, &auth, request))
}

/// Dispatch a request envelope's method calls and collect the responses
/// (RFC 8620 §3.3–§3.7). Shared by the HTTP `POST /jmap/api` handler and the
/// WebSocket transport (RFC 8887), so the two never diverge. Pure aside from the
/// data-dir/state mutations the individual methods perform.
pub fn dispatch_request(state: &ApiState, auth: &MatchedAuth, request: Request) -> Response {
	let mut method_responses = Vec::with_capacity(request.method_calls.len());
	let mut resolver = Resolver::new(MAX_REQUEST_LIMITS);
	for MethodCall(name, args, call_id) in request.method_calls {
		// Resolve result back-references (`#`-prefixed args) against earlier
		// responses. The resolver bounds the cumulative cost of a chain
		// — a request where each call's argument is a `#ResultOf`
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
		// Scope tightening: the middleware infers `Read` for any `POST
		// /jmap/api`, but mutating methods need `Write` (or `Send` for
		// outbound submission). A read-only key hitting the dispatcher would
		// otherwise reach `Mailbox/set`, `EmailSubmission/set`, etc.
		let response = match name.as_str() {
			// Core/echo returns its arguments unchanged (RFC 8620 §4).
			"Core/echo" => json!([name, args, call_id]),
			"Mailbox/set" => match state.require_scope(auth, Scope::Write) {
				Ok(()) => methods::mailbox_set(state, &args, &call_id),
				Err(_) => jmap_scope_error(&call_id),
			},
			"Email/set" => match state.require_scope(auth, Scope::Write) {
				Ok(()) => email::email_set(state, &args, &call_id),
				Err(_) => jmap_scope_error(&call_id),
			},
			"Email/copy" => match state.require_scope(auth, Scope::Write) {
				Ok(()) => email::email_copy(state, &args, &call_id),
				Err(_) => jmap_scope_error(&call_id),
			},
			"EmailSubmission/set" => match state.require_scope(auth, Scope::Send) {
				Ok(()) => methods::email_submission_set(state, &args, &call_id),
				Err(_) => jmap_scope_error(&call_id),
			},
			"PushSubscription/set" => match state.require_scope(auth, Scope::Write) {
				Ok(()) => websocket::push_subscription_set(state, &args, &call_id),
				Err(_) => jmap_scope_error(&call_id),
			},
			"Mailbox/get" => methods::mailbox_get(state, &args, &call_id),
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
			"Identity/get" => methods::identity_get(state, &args, &call_id),
			"Quota/get" => methods::quota_get(state, &args, &call_id),
			"PushSubscription/get" => websocket::push_subscription_get(state, &args, &call_id),
			_ => json!(["error", { "type": "unknownMethod" }, call_id]),
		};
		resolver.record_result(&response);
		method_responses.push(response);
	}
	Response { method_responses }
}

/// The JMAP spec does not define a "forbidden" method error; `forbidden` is
/// the closest general-purpose failure (RFC 8620 §3.6.2) and is what other
/// servers emit for an authorised-but-not-allowed-permission call.
fn jmap_scope_error(call_id: &str) -> Value {
	json!(["error", { "type": "forbidden" }, call_id])
}

/// Replace each `#`-prefixed argument (a ResultReference) with the value pulled
/// from an earlier method's result, per RFC 8620 §3.7. The unbounded
/// version kept for unit tests; the production dispatcher goes through
/// `Resolver::resolve` instead so it can bound the cumulative cost.
#[cfg(test)]
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

/// Per-request limits used by the back-reference resolver. Mirrors the
/// values advertised in the Session resource (RFC 8620 §6.1): the
/// `maxSizeRequest` byte cap and the sum of `maxObjectsInGet` and
/// `maxObjectsInSet`. A request whose chain of `#`-prefixed arguments
/// would materialise more than this is refused with `requestTooLarge`
/// on the first call that crosses the bound.
pub(crate) struct RequestLimits {
	/// Cumulative bytes of resolved arguments across the request. A
	/// request whose chain would materialise more than this is
	/// rejected on the first call that crosses the bound.
	pub max_size_request: u64,
	/// Cumulative element count of resolved arguments across the
	/// request. Mirrors the spec's `maxObjectsInGet + maxObjectsInSet`
	/// cap; a request whose chain would materialise more leaves than
	/// this is rejected the same way.
	pub max_objects_total: u64,
}

/// The default per-request limits, matching the Session resource.
pub(crate) const MAX_REQUEST_LIMITS: RequestLimits = RequestLimits {
	// 10 MiB, mirroring the Session's `maxSizeRequest`.
	max_size_request: 10 * 1024 * 1024,
	// maxObjectsInGet (500) + maxObjectsInSet (500). The cap is on
	// total resolved leaves, not on objects returned by a single
	// method, so this is the conservative sum.
	max_objects_total: 200,
};

/// Count the number of leaves (scalars, empty objects/arrays) in a
/// JSON value, recursively. Used by the resolver to bound a chain of
/// `#`-prefixed arguments: a back-reference loop that doubles the
/// materialised size every call would, without this bound, blow past
/// any reasonable cap.
fn element_count(value: &Value) -> u64 {
	match value {
		Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => 1,
		Value::Array(items) => {
			if items.is_empty() {
				1
			} else {
				items.iter().map(element_count).sum()
			}
		}
		Value::Object(map) => {
			if map.is_empty() {
				1
			} else {
				map.values().map(element_count).sum()
			}
		}
	}
}

/// Byte size of a JSON value when serialised, in bytes. Used by the
/// resolver to bound a chain of back-references against
/// `maxSizeRequest`. `serde_json::to_vec` is the canonical answer; we
/// use it to keep the accounting honest with what the wire would see.
fn byte_size(value: &Value) -> u64 {
	serde_json::to_vec(value)
		.map(|v| v.len() as u64)
		.unwrap_or(0)
}

/// A request-scoped counter that bounds the cumulative work the
/// back-reference resolver does for a single JMAP request. Without
/// this, a request of N `Core/echo` calls each carrying two
/// references to the previous result would double the materialised
/// data N times, so 25 calls could push a few KB into hundreds of MB
/// — the request would be processed and the answer would be huge.
/// The resolver instead refuses the first call that crosses either
/// bound with `requestTooLarge` (RFC 8620 §3.7.2 / §3.6.2).
pub(crate) struct Resolver {
	limits: RequestLimits,
	/// Cumulative resolved bytes materialised so far in the request.
	resolved_bytes: u64,
	/// Cumulative resolved elements materialised so far in the
	/// request.
	resolved_elements: u64,
}

impl Resolver {
	/// Build a resolver that enforces the given limits.
	pub fn new(limits: RequestLimits) -> Self {
		Self {
			limits,
			resolved_bytes: 0,
			resolved_elements: 0,
		}
	}

	/// Bytes and elements materialised so far. Read by the dispatcher
	/// when it needs to attribute work to a particular call.
	#[cfg(test)]
	pub fn materialised(&self) -> (u64, u64) {
		(self.resolved_bytes, self.resolved_elements)
	}

	/// Record the cost of a method response just produced, so the next
	/// call's references resolve against a counter that already
	/// includes the new bytes.
	pub fn record_result(&mut self, response: &Value) {
		if let Some(args) = response.get(1) {
			self.resolved_bytes = self.resolved_bytes.saturating_add(byte_size(args));
			self.resolved_elements = self.resolved_elements.saturating_add(element_count(args));
		}
	}

	/// Resolve the `#`-prefixed arguments of `args` against the
	/// accumulated `prior` responses. The two failure modes have
	/// distinct sentinels: `Ok` for a fully resolved `Value`,
	/// `Err(ResolveError::TooLarge)` when materialising this value
	/// would push the request over the per-request limits, and
	/// `Err(ResolveError::Unresolvable)` when a reference points to a
	/// missing call. The dispatcher turns each into the matching
	/// JMAP error type.
	pub fn resolve(&mut self, args: &Value, prior: &[Value]) -> Result<Value, ResolveError> {
		let mut args = args.clone();
		// Walk the whole argument tree for `#`-prefixed keys. JMAP
		// `ResultReference` values can appear at any depth; a chain
		// whose references are nested inside a wrapper key like
		// `{"x": {#k0: ref, #k1: ref}}` would otherwise slip past the
		// bound.
		let mut additions: Vec<(String, Value, u64, u64)> = Vec::new();
		match resolve_references_recursive(&mut args, prior, &mut additions) {
			Ok(true) => {}
			Ok(false) => return Err(ResolveError::Unresolvable),
			Err(()) => return Err(ResolveError::Unresolvable),
		}
		// Sum the per-reference cost; the whole call's materialised
		// value is the cap-relevant quantity.
		let total_bytes: u64 = additions.iter().map(|(_, _, b, _)| *b).sum();
		let total_elements: u64 = additions.iter().map(|(_, _, _, e)| *e).sum();
		if self.resolved_bytes.saturating_add(total_bytes) > self.limits.max_size_request
			|| self.resolved_elements.saturating_add(total_elements) > self.limits.max_objects_total
		{
			return Err(ResolveError::TooLarge);
		}
		self.resolved_bytes = self.resolved_bytes.saturating_add(total_bytes);
		self.resolved_elements = self.resolved_elements.saturating_add(total_elements);
		Ok(args)
	}
}

/// Recursively walk `value` looking for `#`-prefixed keys. Each match
/// resolves the `ResultReference` against `prior`, appends the cost
/// to `additions`, and substitutes the resolved value (with the
/// prefix stripped) in place. Returns `Ok(true)` on success,
/// `Ok(false)` when a reference cannot be resolved.
fn resolve_references_recursive(
	value: &mut Value,
	prior: &[Value],
	additions: &mut Vec<(String, Value, u64, u64)>,
) -> Result<bool, ()> {
	match value {
		Value::Object(map) => {
			let refs: Vec<String> = map
				.keys()
				.filter(|key| key.starts_with('#'))
				.cloned()
				.collect();
			for key in refs {
				let reference = map.remove(&key).expect("key present");
				let resolved = match resolve_reference(&reference, prior) {
					Some(r) => r,
					None => return Ok(false),
				};
				let bytes = byte_size(&resolved);
				let elements = element_count(&resolved);
				additions.push((key.clone(), resolved.clone(), bytes, elements));
				map.insert(key[1..].to_string(), resolved);
			}
			let keys: Vec<String> = map.keys().cloned().collect();
			for k in keys {
				if let Some(v) = map.get_mut(&k)
					&& !resolve_references_recursive(v, prior, additions)?
				{
					return Ok(false);
				}
			}
			Ok(true)
		}
		Value::Array(items) => {
			for item in items.iter_mut() {
				if !resolve_references_recursive(item, prior, additions)? {
					return Ok(false);
				}
			}
			Ok(true)
		}
		_ => Ok(true),
	}
}

/// Failure modes for the bounded resolver; the dispatcher maps each
/// to the matching JMAP error type (`requestTooLarge` or
/// `invalidResultReference`).
#[derive(Debug)]
pub(crate) enum ResolveError {
	/// Adding the resolved value would push the cumulative bytes or
	/// element count over the per-request cap. The first call that
	/// crosses the bound is rejected.
	TooLarge,
	/// A `#ResultOf` reference pointed at a missing call or path.
	Unresolvable,
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

#[cfg(test)]
#[path = "jmap_backref_caps_tests.rs"]
mod backref_caps_tests;

/// `GET /jmap/download/{accountId}/{blobId}/{name}` (RFC 8620 §6.2): return the
/// raw bytes of a stored message or an uploaded blob, by id.
pub async fn download(
	State(state): State<ApiState>,
	Path((account, blob_id, _name)): Path<(String, String, String)>,
) -> impl IntoResponse {
	if !state.accounts().iter().any(|a| a.name == account) {
		return jmap_error(StatusCode::NOT_FOUND, "notFound", "account not found");
	}
	let stored_message =
		objects::find_email_raw(state.data_dir(), &account, &blob_id, state.crypto());
	let uploaded = if stored_message.is_some() {
		None
	} else {
		blobs::read_blob(state.blob_backend(), &account, &blob_id, state.crypto()).await
	};
	let bytes = stored_message.or(uploaded);
	match bytes {
		Some(bytes) => {
			// Serve the media type recorded at upload time; stored messages and
			// legacy blobs without a sidecar fall back to octet-stream.
			let content_type = blobs::read_blob_type(state.blob_backend(), &blob_id)
				.await
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
	Extension(auth): Extension<MatchedAuth>,
	Path(account): Path<String>,
	headers: HeaderMap,
	body: axum::body::Bytes,
) -> impl IntoResponse {
	// `Write` scope: a read-only key must not be able to fill the quota or
	// the blob store with arbitrary bytes.
	if state.require_scope(&auth, Scope::Write).is_err() {
		return jmap_error(StatusCode::UNAUTHORIZED, "forbidden", "missing write scope");
	}
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
	let backend = state.blob_backend();
	if backend.put(blob_id, "", &stored).await.is_err()
		|| backend
			.put(blob_id, ".type", content_type.as_bytes())
			.await
			.is_err()
		|| blobs::write_blob_owner(backend, blob_id, &account)
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
