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
	/// The `Message-ID` header of the message as written, angle brackets
	/// included: the value a reply puts in `in_reply_to` and `references`.
	message_id: String,
	/// The class the server granted.
	class: crate::evidence::MailClass,
	/// When the send delay releases the message, as an RFC 3339 instant,
	/// until which `DELETE /api/v1/send/{id}` takes it back. Absent when
	/// nothing holds the message (the default).
	#[serde(skip_serializing_if = "Option::is_none")]
	cancel_until: Option<String>,
	/// Recipients dropped because they are on a suppression list.
	#[serde(skip_serializing_if = "Vec::is_empty")]
	suppressed: Vec<String>,
}

/// The message the cap should be enforced against ("too many new
/// recipients today; retry tomorrow"). Distinct from the auth-failure
/// sliding window `rate_limited` so a client can tell the two apart.
/// `Retry-After` of a send limit: its window is one minute, so a client that
/// waits this long finds the window over.
const SEND_LIMIT_RETRY_AFTER: u64 = 60;

/// `Retry-After` of the new-recipient cap, which counts the last 24 hours:
/// the most a client can wait for the oldest new recipient to leave the day.
const NEW_RECIPIENT_RETRY_AFTER: u64 = 24 * 60 * 60;

const NEW_RECIPIENT_LIMIT_MESSAGE: &str = "too many new recipients today; retry tomorrow";

pub async fn send(
	State(state): State<ApiState>,
	Extension(auth): Extension<MatchedAuth>,
	Json(mut request): Json<SendRequest>,
) -> Result<Json<Queued>, ApiError> {
	// The sender is one lowercase address from here on, whatever case the
	// client typed; the recipients are lowercased by `recipients()`.
	request.from = crate::util::address::normalize(&request.from);
	// The headers epistle writes and signs carry the same lowercase addresses.
	for list in [&mut request.to, &mut request.cc, &mut request.bcc] {
		for recipient in list.iter_mut() {
			let address = recipient.address_mut();
			*address = crate::util::address::normalize(address);
		}
	}
	for recipient in request.reply_to.recipients_mut() {
		let address = recipient.address_mut();
		*address = crate::util::address::normalize(address);
	}
	for address in [request.sender.as_mut(), request.envelope_from.as_mut()]
		.into_iter()
		.flatten()
	{
		*address = crate::util::address::normalize(address);
	}
	let explicit_class = request.class()?;
	let recipients = request.recipients();
	if recipients.is_empty() {
		return Err(ApiError::field_missing(
			"to",
			"At least one recipient is required.",
		));
	}
	// Bound the recipient list to the same ceiling the SMTP path enforces.
	let max_recipients = state.max_recipients();
	if recipients.len() > max_recipients {
		return Err(ApiError::field_out_of_range(
			"to",
			&format!("Too many recipients; the maximum is {max_recipients}."),
		));
	}
	// Header-injection guard (mandatory), before anything is built: no CR,
	// LF or other control character (a tab aside) in any header-bound field,
	// or a caller could forge headers (classic email header injection). Also
	// bound each field's length so no single unfolded header line is
	// malformed. The MIME builder refuses a line break again on its own.
	if request.header_bound().into_iter().any(|v| {
		v.contains(['\r', '\n']) || v.chars().any(|c| c.is_control() && c != '\t') || v.len() > 1000
	}) {
		return Err(ApiError::value_not_allowed(
			"headers",
			"Header fields must not contain CR or LF or exceed 1000 bytes.",
		));
	}
	// A display name is checked like `from_name`, before any address is.
	request.check_recipients()?;
	// Sender and every recipient must be syntactically valid addresses.
	if let Err(why) = address_reason::parse(&request.from) {
		return Err(ApiError::value_not_allowed(
			"from",
			&format!("Invalid sender address: {why}."),
		));
	}
	// The null sender is not offered here: every message this endpoint sends
	// answers to an address the account owns.
	if let Some(address) = &request.envelope_from
		&& let Err(why) = address_reason::parse(address)
	{
		return Err(ApiError::value_not_allowed(
			"envelope_from",
			&format!("Invalid envelope_from: {why}."),
		));
	}
	if let Some(why) = recipients
		.iter()
		.map(String::as_str)
		.chain(request.reply_to.recipients().iter().map(|r| r.address()))
		.chain(request.sender.as_deref())
		.find_map(|address| address_reason::parse(address).err())
	{
		return Err(ApiError::value_not_allowed(
			"to",
			&format!("Invalid recipient address: {why}."),
		));
	}
	// The request acts for one account the credential may reach, and the
	// sender must be an address that account owns: the rule
	// `EmailSubmission/set` applies to `mailFrom`. Checked before the
	// tenant rate limit, so a refused request cannot spend another
	// tenant's budget.
	let principal = Principal::for_token(&state, &auth);
	// The middleware asked whether a bound account is still live before the
	// body was read; the body may have taken as long as the client wished.
	if !crate::api::account_bound::bound_account_is_live(&state, &principal) {
		return Err(ApiError::bound_account_unavailable());
	}
	// The same for the key itself: the principal is read again now that the
	// body is here, and a key that lost the `send` scope, or was revoked,
	// since the middleware let the request in does not send.
	if !principal.admits_scope(crate::api::api_keys::Scope::Send) {
		return Err(ApiError::credential_no_longer_valid());
	}
	let account =
		acting_account(&state, &principal, &request.from).ok_or_else(ApiError::forbidden_from)?;
	// An account whose sending is switched off sends nothing, from any of
	// its addresses or with the null sender.
	if !state.can_send(&account) {
		return Err(ApiError::sending_off());
	}
	// `Sender` names who actually sent the message and `envelope_from` is the
	// address bounces return to: the same rule as From for all three. An
	// address an account owns through a list can sit in a domain a confined
	// key does not reach, so the key's domains are asked for each of them.
	let senders = senders(&request);
	for sender in &senders {
		crate::api::mail_from::check_mail_from(&state, &account, sender)
			.map_err(|_| ApiError::forbidden_from())?;
		if !principal.admits_sender(sender) {
			return Err(ApiError::forbidden_from());
		}
	}

	// The optional headers are read now, and a message with nothing in it is
	// refused, before any budget or recipient record is touched. The headers
	// go first so an empty message never hides a more specific refusal.
	request.check_shape(principal.auto_submitted())?;

	// Submission rate limits: the per-account limit and every tenant of
	// the account, shared with SMTP and JMAP. Asked here so a sender with
	// no room left is refused before anything is recorded; charged one
	// unit per recipient just before the message is handed on, and given
	// back when it is refused there.
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	// Every tenant whose domain the message is sent under is asked and charged:
	// the sender, the `Sender` and the envelope sender may all differ.
	let budget = state.submission_budget(&account, &senders);
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
					NEW_RECIPIENT_RETRY_AFTER,
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

	let hosted = state.domains();
	let first_hosted = hosted.first().map(String::as_str).unwrap_or("localhost");
	let domain = super::send_from::message_id_domain(&request.from, first_hosted);
	let date = crate::clock::rfc5322(std::time::SystemTime::now());
	let message_id = format!("<{}@{domain}>", uuid::Uuid::now_v7());
	let display_name = match request.from_name.as_deref() {
		Some(raw) => crate::directory_store::display_name::validate(raw).map_err(|why| {
			ApiError::value_not_allowed("from_name", &format!("Invalid from_name: {why}."))
		})?,
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
		principal.auto_submitted(),
		state.max_message_size(),
	)?;

	// The size cap of the sending account, its tenant and its domains, below
	// the server's `max_message_size` that `build` enforced.
	if let Err(reached) = state
		.store()
		.handle()
		.current()
		.admit_message(&account, data.len() as u64)
	{
		reached.log(&account);
		return Err(ApiError::message_over_cap(&reached));
	}
	if crate::api::quota::over_recipient_size_cap(&state, &recipients, data.len() as u64) {
		return Err(ApiError::recipient_over_cap());
	}
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
		reverse_path: request.envelope_from.take().unwrap_or(request.from),
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
		cancel_until: state.held_until(&account, id).map(crate::clock::rfc3339),
		queued: id.to_string(),
		message_id,
		class: prepared.class,
		suppressed: prepared.suppressed,
	}))
}

/// `429 rate_limited` for a send over one of its submission rate limits.
fn rate_limited() -> ApiError {
	ApiError::rate_limited_with_message(
		crate::smtp::submission_budget::RATE_LIMITED,
		SEND_LIMIT_RETRY_AFTER,
	)
}

/// The addresses a request sends under: `from`, `sender` and `envelope_from`,
/// each once.
fn senders(request: &SendRequest) -> Vec<String> {
	let mut out: Vec<String> = Vec::new();
	let named = [
		Some(&request.from),
		request.sender.as_ref(),
		request.envelope_from.as_ref(),
	];
	for address in named.into_iter().flatten() {
		if !out.contains(address) {
			out.push(address.clone());
		}
	}
	out
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
		SinkError::MailboxFull(recipient) => ApiError::mailbox_full(&recipient),
		SinkError::VirusDetected(signature) => ApiError::virus_detected(&signature),
		SinkError::AttachmentRefused(reasons) => ApiError::attachment_refused(&reasons),
		SinkError::ScanUnavailable => ApiError::scan_unavailable(),
		SinkError::ScanTooLarge => ApiError::scan_too_large(),
		SinkError::Unavailable(_) | SinkError::Gone(_) => ApiError::internal(),
		SinkError::EvidenceUnavailable(_) => ApiError::evidence_unavailable(),
		SinkError::TooManyHeaderFields => ApiError::too_many_header_fields(),
	}
}
