//! RFC 9457 problem details, for the client that asks for them.
//!
//! A request with `Accept: application/problem+json` gets the problem form
//! of every [`ApiError`](super::ApiError) answer; any other request gets the
//! `{"error": ...}` body it always got. The headers of the answer
//! (`Retry-After`, `WWW-Authenticate`) are the same in both.

use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use serde::Serialize;

use super::ErrorInfo;

/// The media type of a problem answer.
const MEDIA_TYPE: &str = "application/problem+json";

/// The prefix of the `type` URI of every problem. A URN, so the identifier
/// is stable and names no host; the table of codes is in `docs/api.md`.
const TYPE_PREFIX: &str = "urn:epistle:problem:";

#[derive(Serialize)]
struct Problem {
	r#type: String,
	title: &'static str,
	status: u16,
	detail: String,
	code: &'static str,
	instance: String,
	request_id: String,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	errors: Vec<FieldError>,
}

#[derive(Serialize)]
struct FieldError {
	field: &'static str,
	detail: String,
}

/// Middleware: rewrite an `ApiError` answer as a problem when the request
/// asked for one. Anything else passes through untouched.
pub(in crate::api) async fn negotiate(request: Request, next: Next) -> Response {
	let wants_problem = accepts_problem(request.headers());
	let method = request.method().clone();
	let path = request.uri().path().to_string();
	let mut response = next.run(request).await;
	if !wants_problem {
		return response;
	}
	let Some(info) = response.extensions_mut().remove::<ErrorInfo>() else {
		return response;
	};
	let request_id = uuid::Uuid::now_v7().to_string();
	// The identifier is only useful if the operator can find it: the log
	// line carries it with the code and the route.
	tracing::info!(
		%request_id,
		status = info.status.as_u16(),
		code = info.code,
		%method,
		%path,
		"API error answered as a problem"
	);
	let problem = Problem {
		r#type: format!("{TYPE_PREFIX}{}", info.code),
		title: title(info.code, info.status),
		status: info.status.as_u16(),
		errors: info
			.field
			.map(|field| FieldError {
				field,
				detail: info.message.clone(),
			})
			.into_iter()
			.collect(),
		detail: info.message,
		code: info.code,
		instance: format!("urn:uuid:{request_id}"),
		request_id,
	};
	let (mut parts, _) = response.into_parts();
	parts.headers.remove(CONTENT_LENGTH);
	parts
		.headers
		.insert(CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
	let body = serde_json::to_vec(&problem).unwrap_or_default();
	Response::from_parts(parts, Body::from(body))
}

/// Whether `Accept` names `application/problem+json` with a quality above
/// zero. A wildcard does not: the problem form is opt-in.
fn accepts_problem(headers: &HeaderMap) -> bool {
	headers
		.get_all(ACCEPT)
		.iter()
		.filter_map(|value| value.to_str().ok())
		.flat_map(|value| value.split(','))
		.any(|range| {
			let mut parts = range.split(';');
			let media = parts.next().unwrap_or("").trim();
			let rejected = parts.any(|param| {
				let (name, value) = param.split_once('=').unwrap_or((param, ""));
				name.trim().eq_ignore_ascii_case("q")
					&& value.trim().parse::<f32>().is_ok_and(|q| q <= 0.0)
			});
			media.eq_ignore_ascii_case(MEDIA_TYPE) && !rejected
		})
}

/// The short, stable title of a problem type.
fn title(code: &str, status: StatusCode) -> &'static str {
	match code {
		"unauthenticated" => "Authentication required",
		"rate_limited" => "Too many requests",
		"field_missing" => "A required field is missing",
		"field_out_of_range" => "A field is out of range",
		"value_not_allowed" => "A value is not allowed",
		"invalid_input" => "Invalid input",
		"not_found" => "Not found",
		"conflict" => "Conflict",
		"already_sent" => "The message was already sent",
		"limit_reached" => "A limit was reached",
		_ => status.canonical_reason().unwrap_or("Error"),
	}
}
