//! `POST /api/v1/send`: transactional outbound submission. Builds a minimal
//! RFC 5322 text message from JSON and enqueues it on the outbound spool.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::smtp::address::Address;
use crate::smtp::session::AcceptedMessage;

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
