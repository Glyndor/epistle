//! `POST /api/v1/send`: transactional outbound submission. Builds a minimal
//! RFC 5322 text message from JSON and enqueues it on the outbound spool.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::smtp::address::Address;
use crate::smtp::session::AcceptedMessage;
use crate::storage::CapOutcome;

#[derive(Deserialize)]
pub struct SendRequest {
	from: String,
	to: Vec<String>,
	#[serde(default)]
	subject: String,
	#[serde(default)]
	text: String,
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
	if Address::parse(&request.from).is_err() {
		return Err(ApiError::invalid_input("Invalid sender address."));
	}
	if request.to.iter().any(|to| Address::parse(to).is_err()) {
		return Err(ApiError::invalid_input("Invalid recipient address."));
	}
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

	// Resolve `request.from` to the local account that owns it. The
	// brief asks us to use what the directory already exposes; we read
	// the account views on the store (the same walk `owns_address`
	// performs on the SMTP path) so the API and SMTP paths can never
	// disagree on ownership.
	let account = match resolve_account(&state, &request.from) {
		Some(account) => account,
		None => {
			return Err(ApiError::invalid_input(
				"Sender address is not owned by any configured account.",
			));
		}
	};

	// Rolling 24h cap on first-time recipients (plan 4.10). Same
	// helper as the SMTP session uses, so the three submission paths
	// compute the same number. Only when both the cap and the store
	// are configured does the check fire; an unset pair short-circuits
	// to "no cap" rather than failing closed.
	let recipient_refs: Vec<&str> = request.to.iter().map(String::as_str).collect();
	if let (Some(store), Some(limit)) = (state.correspondents(), state.new_recipients_per_day()) {
		match store.enforce_new_recipient_cap(&account, &recipient_refs, Some(limit)) {
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
			Ok(CapOutcome::Allowed { .. } | CapOutcome::Uncapped) => {
				let _ = store.record(&account, &recipient_refs);
			}
			Err(error) => {
				tracing::warn!(account = %account, %error, "correspondent store error; accepting");
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
	let data = format!(
		"From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: {date}\r\n\
		 Message-ID: {message_id}\r\nMIME-Version: 1.0\r\n\
		 Content-Type: text/plain; charset=utf-8\r\n\r\n{text}",
		from = request.from,
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

/// Resolve `from` to the local account name that owns the address.
/// Static config and dynamic accounts both win; on conflict the first
/// match (the same precedence `Directory::owns_address` uses). Returns
/// `None` when no account owns the address; the handler then rejects
/// the submission as an invalid sender.
fn resolve_account(state: &ApiState, from: &str) -> Option<String> {
	let lower = from.to_ascii_lowercase();
	state
		.store()
		.account_views()
		.into_iter()
		.find_map(|(name, addresses, _dynamic)| {
			let owns = addresses
				.iter()
				.any(|addr| addr.to_ascii_lowercase() == lower);
			if owns { Some(name) } else { None }
		})
}
