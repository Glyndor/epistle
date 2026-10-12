//! The message `POST /api/v1/send` queues, built with the shared MIME
//! builder from the validated request.

use base64::Engine;

use super::send_request::{MAX_PARTS, PartRequest, SendRequest};
use crate::api::error::ApiError;
use crate::compose::{self, Bodies, Content, Disposition, Leaf};

/// The fixed headers the endpoint writes itself.
pub(super) struct Envelope<'a> {
	/// The `From` field value, display name included.
	pub(super) from: &'a str,
	pub(super) date: &'a str,
	pub(super) message_id: &'a str,
}

/// The full message for `request`, refused when it would not fit
/// [`crate::smtp::session::MAX_MESSAGE_SIZE`] once built.
pub(super) fn build(request: &SendRequest, envelope: &Envelope<'_>) -> Result<Vec<u8>, ApiError> {
	let mut headers = vec![format!("From: {}\r\n", envelope.from)];
	if let Some(sender) = &request.sender {
		headers.push(line(compose::address_list(
			"Sender",
			std::slice::from_ref(sender),
		))?);
	}
	if !request.to.is_empty() {
		headers.push(line(compose::address_list("To", &request.to))?);
	}
	if !request.cc.is_empty() {
		headers.push(line(compose::address_list("Cc", &request.cc))?);
	}
	if let Some(reply_to) = &request.reply_to {
		headers.push(line(compose::address_list(
			"Reply-To",
			std::slice::from_ref(reply_to),
		))?);
	}
	headers.push(line(compose::unstructured("Subject", &request.subject))?);
	headers.push(format!("Date: {}\r\n", envelope.date));
	headers.push(format!("Message-ID: {}\r\n", envelope.message_id));
	headers.extend(request.extra_headers()?);

	if request.attachments.len() + request.inline.len() > MAX_PARTS {
		return Err(ApiError::invalid_input("Too many attachments."));
	}
	let mut bodies = Bodies {
		text: request
			.text
			.as_deref()
			.map(|text| Leaf::text("plain", text)),
		html: request.html.as_deref().map(|html| Leaf::text("html", html)),
		..Bodies::default()
	};
	for part in &request.attachments {
		bodies
			.attachments
			.push(leaf(part, Disposition::Attachment)?);
	}
	for part in &request.inline {
		if part.content_id.is_none() {
			return Err(ApiError::invalid_input(
				"Every inline part needs a content_id.",
			));
		}
		bodies.inline.push(leaf(part, Disposition::Inline)?);
	}
	let data = line(compose::write(&headers, &bodies.assemble()))?;
	if data.len() > crate::smtp::session::MAX_MESSAGE_SIZE {
		return Err(ApiError::message_too_large(
			crate::smtp::session::MAX_MESSAGE_SIZE,
		));
	}
	Ok(data)
}

/// One attachment or inline part, its type detected when left empty.
fn leaf(part: &PartRequest, disposition: Disposition) -> Result<Leaf, ApiError> {
	let data = base64::engine::general_purpose::STANDARD
		.decode(part.data.as_bytes())
		.map_err(|_| ApiError::invalid_input("Attachment data must be base64."))?;
	let content_type = match part.content_type.trim() {
		"" => compose::content_type_for(part.name.as_deref(), &data).to_string(),
		given => given.to_string(),
	};
	Ok(Leaf {
		content_type,
		content: Content::Bytes(data),
		disposition: Some(disposition),
		name: part.name.clone(),
		content_id: part.content_id.clone(),
	})
}

fn line<T>(result: Result<T, compose::ComposeError>) -> Result<T, ApiError> {
	result.map_err(|error| ApiError::invalid_input(&format!("Invalid message: {error}.")))
}
