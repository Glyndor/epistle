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
			"Email/query" => email_query(&state, &args, &call_id),
			"Email/get" => email_get(&state, &args, &call_id),
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

/// `Email/query` (RFC 8621 §4.4): the email ids in a mailbox, newest first.
fn email_query(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	if !state.accounts().iter().any(|a| a.name == account) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	// Only the `inMailbox` filter is supported; absent means INBOX.
	let mailbox = args
		.get("filter")
		.and_then(|f| f.get("inMailbox"))
		.and_then(Value::as_str)
		.unwrap_or("INBOX");

	let mut ids: Vec<String> =
		crate::imap::mailbox::Snapshot::open(state.data_dir(), account, mailbox)
			.map(|snapshot| snapshot.messages().map(|m| m.id().to_string()).collect())
			.unwrap_or_default();
	// JMAP default sort is most-recent first; UUID v7 ids sort by time.
	ids.reverse();
	let total = ids.len();

	json!([
		"Email/query",
		{
			"accountId": account,
			"queryState": "0",
			"canCalculateChanges": false,
			"position": 0,
			"total": total,
			"ids": ids,
		},
		call_id,
	])
}

/// `Email/get` (RFC 8621 §4.1): return parsed Email objects by id.
fn email_get(state: &ApiState, args: &Value, call_id: &str) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	if !state.accounts().iter().any(|a| a.name == account) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	let requested: Vec<String> = args
		.get("ids")
		.and_then(Value::as_array)
		.map(|ids| {
			ids.iter()
				.filter_map(Value::as_str)
				.map(str::to_string)
				.collect()
		})
		.unwrap_or_default();

	let mut list = Vec::new();
	let mut not_found = Vec::new();
	for id in requested {
		match find_email(state.data_dir(), account, &id) {
			Some(email) => list.push(email),
			None => not_found.push(Value::String(id)),
		}
	}
	json!([
		"Email/get",
		{ "accountId": account, "state": "0", "list": list, "notFound": not_found },
		call_id,
	])
}

/// Locate a message by id across the account's mailboxes and build its Email.
fn find_email(data_dir: &std::path::Path, account: &str, id: &str) -> Option<Value> {
	let uuid = uuid::Uuid::parse_str(id).ok()?;
	for mailbox in crate::imap::mailbox::list(data_dir, account) {
		let snapshot = match crate::imap::mailbox::Snapshot::open(data_dir, account, &mailbox) {
			Ok(snapshot) => snapshot,
			Err(_) => continue,
		};
		if let Some(message) = snapshot.messages().find(|m| m.id() == uuid) {
			let raw = snapshot.read(message).unwrap_or_default();
			return Some(email_object(id, &mailbox, message, &raw));
		}
	}
	None
}

/// Build a JMAP Email object from a message and its raw bytes.
fn email_object(
	id: &str,
	mailbox: &str,
	message: &crate::imap::mailbox::MessageRef,
	raw: &[u8],
) -> Value {
	let headers = String::from_utf8_lossy(raw);
	let header = |name: &str| header_value(&headers, name);
	let body_start = headers
		.find("\r\n\r\n")
		.map(|p| p + 4)
		.unwrap_or(headers.len());
	let preview: String = headers[body_start..].chars().take(256).collect();

	let mut keywords = serde_json::Map::new();
	for flag in &message.flags {
		if let Some(keyword) = jmap_keyword(*flag) {
			keywords.insert(keyword.to_string(), Value::Bool(true));
		}
	}
	json!({
		"id": id,
		"blobId": id,
		"threadId": id,
		"mailboxIds": { mailbox: true },
		"keywords": keywords,
		"size": message.size,
		"receivedAt": unix_to_utc(message.internal_date),
		"subject": header("subject"),
		"from": address_list(header("from").as_deref()),
		"to": address_list(header("to").as_deref()),
		"messageId": header("message-id").map(|m| vec![m]),
		"preview": preview.trim(),
	})
}

/// First value of a header (case-insensitive), single-line.
fn header_value(headers: &str, name: &str) -> Option<String> {
	for line in headers.lines() {
		if line.is_empty() {
			break;
		}
		if let Some((key, value)) = line.split_once(':')
			&& key.trim().eq_ignore_ascii_case(name)
		{
			return Some(value.trim().to_string());
		}
	}
	None
}

/// A JMAP address list `[{name, email}]` from a header value (addresses only).
fn address_list(value: Option<&str>) -> Value {
	match value {
		Some(v) => Value::Array(
			v.split(',')
				.map(|addr| json!({ "name": null, "email": addr.trim() }))
				.collect(),
		),
		None => Value::Null,
	}
}

/// Map an IMAP flag to its JMAP keyword (RFC 8621 §4.1.1).
fn jmap_keyword(flag: crate::imap::mailbox::Flag) -> Option<&'static str> {
	use crate::imap::mailbox::Flag;
	match flag {
		Flag::Seen => Some("$seen"),
		Flag::Answered => Some("$answered"),
		Flag::Flagged => Some("$flagged"),
		Flag::Draft => Some("$draft"),
		Flag::Deleted => None,
	}
}

/// Format a `SystemTime` as a JMAP UTCDate (`YYYY-MM-DDThh:mm:ssZ`).
fn unix_to_utc(time: std::time::SystemTime) -> String {
	let secs = time
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let days = (secs / 86_400) as i64;
	let (h, mi, s) = ((secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
	let z = days + 719_468;
	let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
	let doe = z - era * 146_097;
	let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
	let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	let mp = (5 * doy + 2) / 153;
	let day = doy - (153 * mp + 2) / 5 + 1;
	let month = if mp < 10 { mp + 3 } else { mp - 9 };
	let year = yoe + era * 400 + i64::from(month <= 2);
	format!("{year:04}-{month:02}-{day:02}T{h:02}:{mi:02}:{s:02}Z")
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
