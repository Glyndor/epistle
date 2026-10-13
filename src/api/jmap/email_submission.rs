//! `EmailSubmission/set` (RFC 8621 §7.5) and the queue plumbing.

use serde_json::{Value, json};

use super::super::Principal;
use super::super::state::ApiState;
use super::objects;

use crate::smtp::trace::ensure_submission_headers;

/// `EmailSubmission/set` (RFC 8621 §7.5): queue stored emails for delivery.
pub(super) fn email_submission_set(
	state: &ApiState,
	principal: &Principal,
	args: &Value,
	call_id: &str,
) -> Value {
	let Some(account) = args.get("accountId").and_then(Value::as_str) else {
		return json!(["error", { "type": "invalidArguments" }, call_id]);
	};
	let Some(view) = state.accounts().into_iter().find(|a| a.name == account) else {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	};
	if !principal.admits_account(&view.name, &view.addresses) {
		return json!(["error", { "type": "accountNotFound" }, call_id]);
	}
	let mut created = serde_json::Map::new();
	let mut not_created = serde_json::Map::new();
	if let Some(create) = args.get("create").and_then(Value::as_object) {
		for (creation_id, submission) in create {
			match submit_email(state, account, submission) {
				Ok(id) => {
					created.insert(creation_id.clone(), json!({ "id": id, "sendAt": null }));
				}
				Err(reason) => {
					not_created.insert(creation_id.clone(), json!({ "type": reason }));
				}
			}
		}
	}
	json!([
		"EmailSubmission/set",
		{ "accountId": account, "oldState": "0", "newState": "0",
		  "created": created, "notCreated": not_created },
		call_id,
	])
}

/// Submit one email: read it, build the envelope, route it like SMTP
/// submission (DKIM for remote mail, local recipients to their mailboxes).
fn submit_email(
	state: &ApiState,
	account: &str,
	submission: &Value,
) -> Result<String, &'static str> {
	let email_id = submission
		.get("emailId")
		.and_then(Value::as_str)
		.ok_or("invalidProperties")?;
	let raw = objects::find_email_raw(state.data_dir(), account, email_id, state.crypto())
		.ok_or("notFound")?;
	let headers = String::from_utf8_lossy(&raw);
	let envelope = submission.get("envelope");
	let mail_from = envelope
		.and_then(|e| e.get("mailFrom"))
		.and_then(|m| m.get("email"))
		.and_then(Value::as_str)
		.or_else(|| submission.get("identityId").and_then(Value::as_str))
		.unwrap_or("")
		.to_string();
	let recipients: Vec<String> = match envelope
		.and_then(|e| e.get("rcptTo"))
		.and_then(Value::as_array)
	{
		Some(list) => list
			.iter()
			.filter_map(|r| r.get("email").and_then(Value::as_str))
			.map(str::to_string)
			.collect(),
		// RFC 8621 section 7.5: without an envelope, every address in To,
		// Cc and Bcc.
		None => ["to", "cc", "bcc"]
			.into_iter()
			.filter_map(|name| objects::header_value(&headers, name))
			.flat_map(|value| objects::header_emails(&value))
			.collect(),
	};
	if recipients.is_empty() {
		return Err("noRecipients");
	}
	// Send-as guard: the envelope mailFrom must belong to the account on whose
	// behalf the bearer authenticated, matching what SMTP enforces at
	// `src/smtp/session/mod.rs:380`. Empty mailFrom is the null reverse path
	// (JMAP `Envelope.mailFrom.email: null`), legal for bounces; a non-empty
	// mailFrom that does not parse, or that the account does not own, is
	// rejected with the RFC 8621 §7.5.2 `forbiddenFrom` error.
	crate::api::mail_from::check_mail_from(state, account, &mail_from).map_err(|refusal| {
		match refusal {
			crate::api::mail_from::MailFromRefusal::Invalid => "invalidEmail",
			crate::api::mail_from::MailFromRefusal::NotOwned => "forbiddenFrom",
		}
	})?;
	// The same rule for the message itself: its single From must be an
	// address the account owns (RFC 8621 section 7.5.2, `forbiddenFrom`).
	if !crate::api::mail_from::owns_author(state, account, &raw) {
		return Err("forbiddenFrom");
	}
	// Stamp Message-ID and Date on the queued copy when the client did not
	// include them. Domain is the envelope's MAIL FROM, falling back to the
	// first configured domain when the envelope has none (the null reverse
	// path, bounces and similar).
	let stamp_domain = mail_from
		.rsplit_once('@')
		.map(|(_, d)| d.to_ascii_lowercase())
		.or_else(|| state.domains().first().map(|d| d.to_ascii_lowercase()))
		.unwrap_or_else(|| "localhost".to_string());
	let stamped = ensure_submission_headers(&raw, &stamp_domain, std::time::SystemTime::now());
	// RFC 8621 section 7.5: the Bcc header never leaves; those recipients
	// are on the envelope.
	let stamped = crate::smtp::trace::strip_bcc(&stamped);
	// Record recipients even without a cap so replies remain known. The
	// rolling 24h cap uses the same reservation lock as SMTP and REST. The
	// account name is the JMAP `accountId` argument: the client is
	// acting on behalf of itself, so the per-day ceiling lives there.
	// `tooManyRecipients` is the JMAP error type that names the
	// resource; RFC 8621 §3.6.2 carries it through. The on-wire error
	// keeps the same wording as the SMTP / REST paths so an operator
	// reading either log can correlate by the message.
	if let Some(store) = state.correspondents() {
		let recipient_refs: Vec<&str> = recipients.iter().map(String::as_str).collect();
		match store.enforce_new_recipient_cap(
			account,
			&recipient_refs,
			state.new_recipients_per_day(),
		) {
			Ok(crate::storage::CapOutcome::Limited {
				new,
				already,
				limit,
			}) => {
				crate::api::log_send_limited(account, None, new.saturating_add(already), limit);
				return Err("tooManyRecipients");
			}
			Ok(
				crate::storage::CapOutcome::Allowed { .. } | crate::storage::CapOutcome::Uncapped,
			) => {}
			Err(error) => {
				tracing::warn!(
					account = %crate::log_id::account(account),
					%error,
					"correspondent store error; accepting"
				);
			}
		}
	}
	// A full local mailbox is refused now, not bounced days later
	// (RFC 8620 §5.3 `overQuota`).
	if crate::api::quota::full_recipient(state, &recipients, stamped.len() as u64).is_some() {
		return Err("overQuota");
	}
	let message = crate::smtp::session::AcceptedMessage {
		reverse_path: mail_from,
		recipients,
		data: stamped,
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		no_dsn: Vec::new(),
	};
	state
		.submit(message)
		.map(|id| id.to_string())
		.map_err(|_| "serverFail")
}
