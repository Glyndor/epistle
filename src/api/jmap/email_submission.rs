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
			match submit_email(state, account, &view.addresses, submission) {
				Ok(id) => {
					created.insert(creation_id.clone(), json!({ "id": id, "sendAt": null }));
				}
				Err(refusal) => {
					not_created.insert(creation_id.clone(), refusal.to_json());
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
	addresses: &[String],
	submission: &Value,
) -> Result<String, Refusal> {
	let email_id = submission
		.get("emailId")
		.and_then(Value::as_str)
		.ok_or("invalidProperties")?;
	let raw = objects::find_email_raw(state.data_dir(), account, email_id, state.crypto())
		.ok_or("notFound")?;
	let headers = String::from_utf8_lossy(&raw);
	let envelope = submission.get("envelope");
	// RFC 8621 section 7.5: without an envelope, MAIL FROM is the Sender
	// header if there is one, else the From header. The null reverse path
	// is for bounces only and never comes out of a missing envelope. Either
	// address is checked below like an explicit one.
	let mail_from = match envelope
		.and_then(|e| e.get("mailFrom"))
		.and_then(|m| m.get("email"))
		.and_then(Value::as_str)
	{
		Some(email) => email.to_string(),
		None => ["sender", "from"]
			.into_iter()
			.find_map(|name| {
				objects::header_value(&headers, name)
					.and_then(|value| objects::header_emails(&value).into_iter().next())
			})
			.unwrap_or_default(),
	};
	let recipients: Vec<String> = match envelope
		.and_then(|e| e.get("rcptTo"))
		.and_then(Value::as_array)
	{
		Some(list) => list
			.iter()
			.filter_map(|r| r.get("email").and_then(Value::as_str))
			.map(str::to_string)
			.collect(),
		// RFC 8621 section 7.5: without an envelope, the deduplicated set
		// of addresses in To, Cc and Bcc. Nothing else: Resent-* fields
		// left on a stored message name who received an earlier copy,
		// and sending to them would mail people the author never listed.
		None => {
			let mut recipients: Vec<String> = Vec::new();
			for address in ["to", "cc", "bcc"]
				.into_iter()
				.filter_map(|name| objects::header_value(&headers, name))
				.flat_map(|value| objects::header_emails(&value))
			{
				if !recipients.iter().any(|seen| same_address(seen, &address)) {
					recipients.push(address);
				}
			}
			recipients
		}
	};
	if recipients.is_empty() {
		return Err("noRecipients".into());
	}
	// Bound the recipient list to the same ceiling the SMTP and REST
	// paths enforce. RFC 9422 (the SPEC the EHLO LIMITS RCPTMAX line
	// points at) gives the per-message recipient count; JMAP callers
	// must hit the same wall so no protocol can carry a 101-recipient
	// message while the others refuse the 101st.
	if recipients.len() > crate::smtp::session::MAX_RECIPIENTS {
		return Err(Refusal {
			kind: "tooManyRecipients",
			description: Some(format!(
				"too many recipients ({} > {})",
				recipients.len(),
				crate::smtp::session::MAX_RECIPIENTS,
			)),
		});
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
		return Err("forbiddenFrom".into());
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
	// Submission rate limits: the per-account limit and every tenant of
	// the account, the same limiters SMTP and `POST /api/v1/send` charge.
	// Asked here so a sender with no room left is refused before anything
	// is recorded; charged one unit per recipient just before the message
	// is handed on, and given back when it is refused there. `rateLimit`
	// is the RFC 8620 section 5.3 error for a rate limit.
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let budget = state.submission_budget(account, addresses);
	if !budget.has_room(now) {
		return Err(rate_limited());
	}
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
				return Err("tooManyRecipients".into());
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
		return Err("overQuota".into());
	}
	// Save a copy of what the account submitted into its `Sent`
	// folder when the JMAP request does not already place the
	// Email there. The check inspects `onSuccessUpdateEmail`:
	// when the client asks the server to move or copy the email
	// into Sent as part of the submission, the saver must not
	// produce a second copy. The same `save_sent` per-account and
	// per-request gates the SMTP and `/api/v1/send` paths.
	let request_save_sent = submission
		.get("saveSent")
		.and_then(Value::as_bool)
		.or_else(|| submission.get("save_sent").and_then(Value::as_bool));
	let jmap_email_in_sent = submission
		.get("onSuccessUpdateEmail")
		.and_then(Value::as_object)
		.and_then(|update| update.get("mailboxIds"))
		.and_then(Value::as_object)
		.is_some_and(|ids| ids.keys().any(|key| key.eq_ignore_ascii_case("Sent")));
	let sent_copy = stamped.clone();
	let message = crate::smtp::session::AcceptedMessage {
		reverse_path: mail_from,
		recipients,
		data: stamped,
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		// The account logged in and owns the sender address.
		sender_verified: true,
		no_dsn: Vec::new(),
	};
	let recipient_count = u32::try_from(message.recipients.len()).unwrap_or(u32::MAX);
	let charge = budget
		.charge(recipient_count, now)
		.map_err(|_| rate_limited())?;
	let id = match state.submit(account, message, &std::collections::BTreeMap::new()) {
		Ok(id) => id,
		Err(error) => {
			charge.refund();
			return Err(match error {
				// RFC 8621 section 7.5.2: the server refuses to send this message.
				crate::smtp::sink::SinkError::VirusDetected(signature) => Refusal {
					kind: "forbiddenToSend",
					description: Some(format!("message rejected: virus detected ({signature})")),
				},
				crate::smtp::sink::SinkError::AttachmentRefused(reasons) => Refusal {
					kind: "forbiddenToSend",
					description: Some(format!("attachment type not accepted ({reasons})")),
				},
				crate::smtp::sink::SinkError::Unavailable(_) => "serverFail".into(),
				crate::smtp::sink::SinkError::ScanUnavailable => Refusal {
					kind: "serverFail",
					description: Some("content scan unavailable, try again later".into()),
				},
			});
		}
	};
	// Save the Sent copy unless the JMAP submission already places
	// the email in Sent, or the caller opted out with `saveSent:
	// false`, or the account-wide setting is off.
	if !jmap_email_in_sent {
		state.save_sent_copy(account, &sent_copy, request_save_sent);
	}
	Ok(id.to_string())
}

/// Whether `a` and `b` name the same mailbox: the domain compared without
/// case, the local part exactly (RFC 5321 section 2.4 leaves its case to
/// the receiving host, so folding it could drop a distinct recipient).
fn same_address(a: &str, b: &str) -> bool {
	match (a.rsplit_once('@'), b.rsplit_once('@')) {
		(Some((local_a, domain_a)), Some((local_b, domain_b))) => {
			local_a == local_b && domain_a.eq_ignore_ascii_case(domain_b)
		}
		_ => a == b,
	}
}

/// The `rateLimit` SetError for a submission over one of its rate limits.
fn rate_limited() -> Refusal {
	Refusal {
		kind: "rateLimit",
		description: Some(crate::smtp::submission_budget::RATE_LIMITED.to_string()),
	}
}

/// A `SetError` (RFC 8620 section 5.3): its type, and a description when
/// the type alone does not say why.
struct Refusal {
	kind: &'static str,
	description: Option<String>,
}

impl From<&'static str> for Refusal {
	fn from(kind: &'static str) -> Self {
		Refusal {
			kind,
			description: None,
		}
	}
}

impl Refusal {
	fn to_json(&self) -> Value {
		match &self.description {
			Some(description) => json!({ "type": self.kind, "description": description }),
			None => json!({ "type": self.kind }),
		}
	}
}
