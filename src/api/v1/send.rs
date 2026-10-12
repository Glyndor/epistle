//! `POST /api/v1/send`: transactional outbound submission. Builds a minimal
//! RFC 5322 text message from JSON and enqueues it on the outbound spool.

use axum::Json;
use axum::extract::{Extension, State};
use serde::{Deserialize, Serialize};

use crate::api::Principal;
use crate::api::error::ApiError;
use crate::api::state::{ApiState, MatchedAuth};
use crate::smtp::session::AcceptedMessage;
use crate::storage::CapOutcome;
use crate::util::address_reason;

#[derive(Deserialize)]
pub struct SendRequest {
	from: String,
	to: Vec<String>,
	#[serde(default)]
	subject: String,
	#[serde(default)]
	text: String,
	/// The sender's name for the `From` header. Absent uses the account's
	/// display name.
	#[serde(default)]
	from_name: Option<String>,
}

#[derive(Serialize)]
pub struct Queued {
	queued: String,
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
	if request.to.is_empty() {
		return Err(ApiError::invalid_input(
			"At least one recipient is required.",
		));
	}
	// Bound the recipient list to the same ceiling the SMTP path enforces.
	if request.to.len() > crate::smtp::session::MAX_RECIPIENTS {
		return Err(ApiError::invalid_input("Too many recipients."));
	}
	// Header-injection guard (mandatory): no CR/LF in any header-bound field, or
	// a caller could forge headers (classic email header injection). Also bound
	// each field's length so no single unfolded header line is malformed.
	let header_fields = std::iter::once(&request.from)
		.chain(request.to.iter())
		.chain(std::iter::once(&request.subject));
	if header_fields
		.into_iter()
		.any(|v| v.contains(['\r', '\n']) || v.len() > 1000)
	{
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
	if let Some(why) = request
		.to
		.iter()
		.find_map(|to| address_reason::parse(to).err())
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

	// Per-tenant aggregate submission rate limit. Sits on top of the
	// existing per-account limiter (which the SMTP session enforces); the
	// empty `tenant_limits` is the identity and short-circuits.
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	if let Err(message) = state
		.tenant_limits()
		.check_aggregate_rate(std::slice::from_ref(&request.from), now)
	{
		return Err(ApiError::rate_limited_with_message(message));
	}

	// Reserve correspondents under the same account lock as SMTP and JMAP.
	// Recording also runs without a cap so inbound replies remain known.
	let recipient_refs: Vec<&str> = request.to.iter().map(String::as_str).collect();
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
	let data = format!(
		"From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: {date}\r\n\
		 Message-ID: {message_id}\r\nMIME-Version: 1.0\r\n\
		 Content-Type: text/plain; charset=utf-8\r\n\r\n{text}",
		from = super::send_from::from_header(display_name.as_deref(), &request.from),
		to = request.to.join(", "),
		subject = request.subject,
		text = request.text,
	)
	.into_bytes();

	let message = AcceptedMessage {
		reverse_path: request.from,
		recipients: request.to,
		data,
		require_tls: false,
		mailbox: None,
		tlsrpt_verified: false,
		no_dsn: Vec::new(),
	};
	let id = state
		.spool()
		.store(&message)
		.map_err(|_| ApiError::internal())?;
	Ok(Json(Queued {
		queued: id.to_string(),
	}))
}

/// The account a send request acts for. An account-bound credential acts
/// for its own account, whatever the sender; any other credential acts for
/// the account that owns `from`, provided the principal may reach it.
/// `None` when no reachable account owns `from`, the same answer whether
/// another account owns it or none does.
fn acting_account(state: &ApiState, principal: &Principal, from: &str) -> Option<String> {
	if let Principal::Account { name, .. } = principal {
		return Some(name.clone());
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
