//! JMAP (RFC 8620) foundation: the Session resource and the Core/echo method.
//!
//! This is the minimal, spec-valid entry point that opens the JMAP roadmap:
//! a client fetches the Session object to discover capabilities and the API
//! URL, then POSTs a request envelope whose method calls are dispatched here.
//! Only the mandatory `Core/echo` method is implemented so far.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::state::ApiState;

/// JMAP core capability URN.
const CORE_CAPABILITY: &str = "urn:ietf:params:jmap:core";
/// JMAP mail capability URN (RFC 8621).
const MAIL_CAPABILITY: &str = "urn:ietf:params:jmap:mail";

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
					"accountCapabilities": { CORE_CAPABILITY: {}, MAIL_CAPABILITY: {} },
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
			"Mailbox/get" => mailbox_get(&state, &args, &call_id),
			_ => json!(["error", { "type": "unknownMethod" }, call_id]),
		});
	}
	Json(Response { method_responses })
}

/// `Mailbox/get` (RFC 8621 §2.2): return the account's mailboxes as objects.
fn mailbox_get(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	if !state.accounts().iter().any(|a| a.name == account) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	let data_dir = state.data_dir();
	// Optional `ids` filter: null/absent means all.
	let wanted: Option<Vec<String>> = args
		.get("ids")
		.filter(|v| !v.is_null())
		.and_then(Value::as_array)
		.map(|ids| {
			ids.iter()
				.filter_map(Value::as_str)
				.map(str::to_string)
				.collect()
		});

	let list: Vec<Value> = crate::imap::mailbox::list(data_dir, account)
		.into_iter()
		.filter(|name| wanted.as_ref().is_none_or(|ids| ids.contains(name)))
		.map(|name| mailbox_object(data_dir, account, &name))
		.collect();

	json!([
		"Mailbox/get",
		{ "accountId": account, "state": "0", "list": list, "notFound": [] },
		call_id,
	])
}

/// Build one JMAP Mailbox object from a mailbox name.
fn mailbox_object(data_dir: &std::path::Path, account: &str, name: &str) -> Value {
	let (total, unread) = crate::imap::mailbox::Snapshot::open(data_dir, account, name)
		.map(|snapshot| {
			let unread = snapshot
				.messages()
				.filter(|m| !m.flags.contains(&crate::imap::mailbox::Flag::Seen))
				.count();
			(snapshot.len(), unread)
		})
		.unwrap_or((0, 0));
	json!({
		"id": name,
		"name": name,
		"parentId": null,
		"role": mailbox_role(name),
		"sortOrder": 0,
		"totalEmails": total,
		"unreadEmails": unread,
		"totalThreads": total,
		"unreadThreads": unread,
		"isSubscribed": true,
		"myRights": {
			"mayReadItems": true, "mayAddItems": true, "mayRemoveItems": true,
			"maySetSeen": true, "maySetKeywords": true, "mayCreateChild": false,
			"mayRename": false, "mayDelete": false, "maySubmit": true,
		},
	})
}

/// Map a mailbox name to a JMAP role (RFC 8621 §2), or null.
fn mailbox_role(name: &str) -> Option<&'static str> {
	match name.to_ascii_lowercase().as_str() {
		"inbox" => Some("inbox"),
		"sent" => Some("sent"),
		"drafts" => Some("drafts"),
		"junk" | "spam" => Some("junk"),
		"trash" => Some("trash"),
		"archive" => Some("archive"),
		_ => None,
	}
}
