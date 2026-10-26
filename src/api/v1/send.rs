//! `POST /api/v1/send`: transactional outbound submission. Builds an
//! RFC 5322 message from JSON (text and/or HTML, attachments, inline parts,
//! a bounded set of extra headers) and submits it like SMTP submission does.

use axum::Json;
use axum::extract::{Extension, State};
use serde::Serialize;

use super::send_request::SendRequest;
use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};
use crate::smtp::session::AcceptedMessage;
use crate::smtp::sink::SinkError;
use crate::storage::CapOutcome;
use crate::util::address_reason;

#[derive(Serialize)]
pub struct Queued {
	queued: String,
	/// The class the server granted.
	class: crate::evidence::MailClass,
	/// Recipients dropped because they are on a suppression list.
	#[serde(skip_serializing_if = "Vec::is_empty")]
	suppressed: Vec<String>,
}

/// The message the cap should be enforced against ("too many new
/// recipients today; retry tomorrow"). Distinct from the auth-failure
/// sliding window `rate_limited` so a client can tell the two apart.
const NEW_RECIPIENT_LIMIT_MESSAGE: &str = "too many new recipients today; retry tomorrow";

pub async fn send(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Json(request): Json<SendRequest>,
) -> Result<Json<Queued>, ApiError> {
	let explicit_class = request.class()?;
	let recipients = request.recipients();
	if recipients.is_empty() {
		return Err(ApiError::invalid_input(
			"At least one recipient is required.",
		));
	}
	// Bound the recipient list to the same ceiling the SMTP path enforces.
	let max_recipients = state.max_recipients();
	if recipients.len() > max_recipients {
		return Err(ApiError::invalid_input("Too many recipients."));
	}
	// Header-injection guard (mandatory), before anything is built: no CR,
	// LF or other control character (a tab aside) in any header-bound field,
	// or a caller could forge headers (classic email header injection). Also
	// bound each field's length so no single unfolded header line is
	// malformed. The MIME builder refuses a line break again on its own.
	if request.header_bound().into_iter().any(|v| {
		v.contains(['\r', '\n']) || v.chars().any(|c| c.is_control() && c != '\t') || v.len() > 1000
	}) {
		return Err(ApiError::invalid_input(
			"Header fields must not contain CR or LF or exceed 1000 bytes.",
		));
	}
	// Sender and every recipient must be syntactically valid addresses.
	if let Err(why) = address_reason::parse(&request.from) {
		return Err(ApiError::invalid_input(&format!(
			"Invalid sender address: {why}."
		)));
	}
	if let Some(why) = recipients
		.iter()
		.chain(&request.reply_to)
		.chain(&request.sender)
		.find_map(|address| address_reason::parse(address).err())
	{
		return Err(ApiError::invalid_input(&format!(
			"Invalid recipient address: {why}."
		)));
	}
	// The request acts for one account the credential may reach, and the
	// sender must be an address that account owns: the rule
	// `EmailSubmission/set` applies to `mailFrom`. Checked before the
	// tenant rate limit, so a refused request cannot spend another
	// tenant's budget.
	let principal = Principal::for_token(&state, &auth);
	let account =
		acting_account(&state, &principal, &request.from).ok_or_else(ApiError::forbidden_from)?;
	crate::api::mail_from::check_mail_from(&state, &account, &request.from)
		.map_err(|_| ApiError::forbidden_from())?;
	// `Sender` names who actually sent the message: the same rule as From.
	if let Some(sender) = &request.sender {
		crate::api::mail_from::check_mail_from(&state, &account, sender)
			.map_err(|_| ApiError::forbidden_from())?;
	}

	// Submission rate limits: the per-account limit and every tenant of
	// the account, shared with SMTP and JMAP. Asked here so a sender with
	// no room left is refused before anything is recorded; charged one
	// unit per recipient just before the message is handed on, and given
	// back when it is refused there.
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let budget = state.submission_budget(&account, std::slice::from_ref(&request.from));
	if !budget.has_room(now) {
		return Err(rate_limited());
	}

	// Reserve correspondents under the same account lock as SMTP and JMAP.
	// Recording also runs without a cap so inbound replies remain known.
	let recipient_refs: Vec<&str> = recipients.iter().map(String::as_str).collect();
	if let Some(store) = state.correspondents() {
		match store.enforce_new_recipient_cap(
			&account,
			&recipient_refs,
			state.new_recipients_per_day(),
		) {
			Ok(CapOutcome::Limited {
				new,
				already,
				limit,
			}) => {
				crate::api::log_send_limited(&account, None, new.saturating_add(already), limit);
				return Err(ApiError::rate_limited_with_message(
					NEW_RECIPIENT_LIMIT_MESSAGE,
				));
			}
			Ok(CapOutcome::Allowed { .. } | CapOutcome::Uncapped) => {}
			Err(error) => {
				tracing::warn!(
					account = %crate::log_id::account(&account),
					%error,
					"correspondent store error; accepting"
				);
			}
		}
	}

	let domain = state
		.domains()
		.first()
		.map(String::as_str)
		.unwrap_or("localhost");
	let date = crate::clock::rfc5322(std::time::SystemTime::now());
	let message_id = format!("<{}@{domain}>", uuid::Uuid::now_v7());
	let display_name = match request.from_name.as_deref() {
		Some(raw) => crate::directory_store::display_name::validate(raw)
			.map_err(|why| ApiError::invalid_input(&format!("Invalid from_name: {why}.")))?,
		None => state.store().display_name(&account),
	};
	let from = super::send_from::from_header(display_name.as_deref(), &request.from);
	let data = super::send_message::build(
		&request,
		&super::send_message::Envelope {
			from: &from,
			date: &date,
			message_id: &message_id,
		},
		state.max_message_size(),
	)?;

	if let Some(full) = crate::api::quota::full_recipient(&state, &recipients, data.len() as u64) {
		return Err(ApiError::mailbox_full(&full));
	}
	let save_sent = request.save_sent();
	// The same outbound path as SMTP submission: DKIM for remote mail,
	// local recipients straight to their mailboxes. The `extra` correlation
	// map is already validated and bounded in the request body, and the
	// spool / delivery log carry it without ever writing it into the message.
	let extra = request.validated_extra()?;
	let message = AcceptedMessage {
		reverse_path: request.from,
		recipients,
		data,
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		// The account logged in and owns the sender address.
		sender_verified: true,
		no_dsn: Vec::new(),
	};
	let mut message = message;
	let sources = state.class_sources(Some(&auth), &account, explicit_class);
	let prepared = crate::evidence::submission::prepare(
		&mut message,
		sources,
		Some(state.data_dir()),
		state.identification(),
		state.directory_snapshot().as_deref(),
	)
	.map_err(|refusal| ApiError::marketing_refused(refusal.message()))?;
	if message.recipients.is_empty() {
		return Err(ApiError::marketing_refused(
			"every recipient is on the suppression list",
		));
	}
	// Clone the bytes so the Sent copy can be written after the routing
	// sink takes ownership of the original.
	let sent_copy = prepared
		.class
		.allows_sent_copy()
		.then(|| message.data.clone());
	let recipient_count = u32::try_from(message.recipients.len()).unwrap_or(u32::MAX);
	let charge = budget
		.charge(recipient_count, now)
		.map_err(|_| rate_limited())?;
	let submission = crate::smtp::sink::Submission {
		extra,
		class: prepared.class,
	};
	let id = match state.submit(&account, message, &submission) {
		Ok(id) => id,
		Err(error) => {
			charge.refund();
			return Err(sink_refusal(error));
		}
	};
	// Save a copy of what the account sent into its `Sent` folder
	// when the per-request and account-wide settings admit it. The
	// default is "on"; the request may opt out.
	// Transactional mail is never copied to Sent.
	if let Some(sent_copy) = sent_copy {
		state.save_sent_copy(&account, &sent_copy, save_sent);
	}
	Ok(Json(Queued {
		queued: id.to_string(),
		class: prepared.class,
		suppressed: prepared.suppressed,
	}))
}

/// `429 rate_limited` for a send over one of its submission rate limits.
fn rate_limited() -> ApiError {
	ApiError::rate_limited_with_message(crate::smtp::submission_budget::RATE_LIMITED)
}

/// The account a send request acts for. An account-bound credential acts
/// for its own account, whatever the sender; any other credential acts for
/// the account that owns `from`, provided the principal may reach it.
/// `None` when no reachable account owns `from`, the same answer whether
/// another account owns it or none does.
fn acting_account(state: &ApiState, principal: &Principal, from: &str) -> Option<String> {
	if let Some(bound) = principal.bound_account() {
		// The bound account is reachable only while it also satisfies the
		// other restrictions the key declares.
		let view = state
			.accounts()
			.into_iter()
			.find(|view| view.name == bound)?;
		if !principal.admits_account(&view.name, &view.addresses) {
			return None;
		}
		return Some(view.name);
	}
	let lower = crate::util::address::normalize(from);
	state
		.accounts()
		.into_iter()
		.find(|view| {
			view.addresses
				.iter()
				.any(|address| crate::util::address::normalize(address) == lower)
		})
		.filter(|view| principal.admits_account(&view.name, &view.addresses))
		.map(|view| view.name)
}

/// The API error for a submission the sink refused.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn sink_refusal(error: SinkError) -> ApiError {
	match error {
		SinkError::VirusDetected(signature) => ApiError::virus_detected(&signature),
		SinkError::AttachmentRefused(reasons) => ApiError::attachment_refused(&reasons),
		SinkError::ScanUnavailable => ApiError::scan_unavailable(),
		SinkError::ScanTooLarge => ApiError::scan_too_large(),
		SinkError::Unavailable(_) | SinkError::Gone(_) => ApiError::internal(),
		SinkError::EvidenceUnavailable(_) => ApiError::evidence_unavailable(),
		SinkError::TooManyHeaderFields => ApiError::too_many_header_fields(),
	}
}
