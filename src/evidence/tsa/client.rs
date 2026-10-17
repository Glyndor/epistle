//! Asking a timestamp authority over HTTP (RFC 3161 section 3.4).
//!
//! The request body is the DER TimeStampReq and nothing else: the digest,
//! a nonce and `certReq`. Redirects are not followed, every exchange is
//! bounded in time, and the response is read in chunks up to
//! [`super::token::MAX_RESPONSE`] bytes, so a misbehaving authority cannot
//! hold the server or fill its memory.

use std::time::Duration;

use super::request::{Request, build, random_nonce};
use super::settings::Authority;
use super::token::MAX_RESPONSE;
use super::verify::{Expected, Stamp, verify_expected};

/// How long one exchange may take, connection included.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the connection may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A verified token from one authority.
#[derive(Debug, Clone)]
pub struct Obtained {
	/// The DER TimeStampResp, as received.
	pub response: Vec<u8>,
	/// What it says.
	pub stamp: Stamp,
	/// The authority that answered.
	pub url: String,
}

/// Ask `authorities` in order for a token over `digest`, returning the
/// first one that verifies, or every authority's error joined.
pub async fn obtain(authorities: &[Authority], digest: &[u8; 32]) -> Result<Obtained, String> {
	let client = reqwest::Client::builder()
		.timeout(EXCHANGE_TIMEOUT)
		.connect_timeout(CONNECT_TIMEOUT)
		.redirect(reqwest::redirect::Policy::none())
		.build()
		.map_err(|error| format!("HTTP client: {error}"))?;
	let mut errors = Vec::new();
	for authority in authorities {
		let request = build(digest, random_nonce());
		let token = match &authority.token_file {
			Some(path) => match super::settings::read_token(path) {
				Ok(token) => Some(token),
				Err(error) => {
					errors.push(format!("{}: token file: {error}", authority.display()));
					continue;
				}
			},
			None => None,
		};
		match exchange(&client, &authority.url, &request, token.as_deref()).await {
			Ok(response) => {
				let anchors = authority.anchor_hashes();
				let policy = authority.policy_oid();
				let expected = Expected {
					digest,
					nonce: Some(request.nonce),
					anchors: &anchors,
					policy: policy.as_deref(),
				};
				match verify_expected(&response, &expected) {
					Ok(stamp) => {
						return Ok(Obtained {
							response,
							stamp,
							url: authority.url.clone(),
						});
					}
					Err(error) => errors.push(format!("{}: {error}", authority.display())),
				}
			}
			Err(error) => errors.push(format!("{}: {error}", authority.display())),
		}
	}
	Err(if errors.is_empty() {
		"no timestamp authority is configured".to_string()
	} else {
		errors.join("; ")
	})
}

async fn exchange(
	client: &reqwest::Client,
	url: &str,
	request: &Request,
	token: Option<&str>,
) -> Result<Vec<u8>, String> {
	let mut builder = client
		.post(url)
		.header(reqwest::header::CONTENT_TYPE, "application/timestamp-query")
		.body(request.der.clone());
	if let Some(token) = token {
		builder = builder.bearer_auth(token);
	}
	let mut response = builder
		.send()
		.await
		.map_err(|error| format!("request failed: {}", without_url(&error)))?;
	if !response.status().is_success() {
		return Err(format!("answered HTTP {}", response.status().as_u16()));
	}
	let mut body = Vec::new();
	while let Some(chunk) = response
		.chunk()
		.await
		.map_err(|error| format!("response failed: {}", without_url(&error)))?
	{
		if body.len() + chunk.len() > MAX_RESPONSE {
			return Err(format!("response larger than {MAX_RESPONSE} bytes"));
		}
		body.extend_from_slice(&chunk);
	}
	Ok(body)
}

/// A reqwest error without the URL it repeats (the caller names it once).
fn without_url(error: &reqwest::Error) -> String {
	let kind = if error.is_timeout() {
		"timed out"
	} else if error.is_connect() {
		"could not connect"
	} else {
		"transport error"
	};
	kind.to_string()
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
