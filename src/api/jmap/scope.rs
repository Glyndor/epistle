//! The scope a JMAP method needs and the error for a token without it.

use super::*;

/// The scope a method call needs: `Write` to change stored data or push
/// subscriptions, `Send` to submit mail, `Read` for everything that returns
/// account data. `None` for `Core/echo`, which touches nothing, and for a
/// method this server does not know, which is answered `unknownMethod`.
pub(super) fn required_scope(method: &str) -> Option<Scope> {
	match method {
		"Mailbox/set" | "Email/set" | "Email/copy" | "PushSubscription/set" => Some(Scope::Write),
		"EmailSubmission/set" => Some(Scope::Send),
		"VacationResponse/set" | "SieveScript/set" => Some(Scope::Write),
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
		| "PushSubscription/get"
		| "VacationResponse/get"
		| "SieveScript/get"
		| "SieveScript/query"
		| "SieveScript/validate" => Some(Scope::Read),
		_ => None,
	}
}

/// The JMAP spec does not define a "forbidden" method error; `forbidden` is
/// the closest general-purpose failure (RFC 8620 §3.6.2) and is what other
/// servers emit for an authorised-but-not-allowed-permission call.
pub(super) fn jmap_scope_error(call_id: &str) -> Value {
	json!(["error", { "type": "forbidden" }, call_id])
}
