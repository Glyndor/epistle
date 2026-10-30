//! reqwest-backed [`AcmeTransport`] (RFC 8555 §6).
//!
//! Carries the ACME requests the client builds: GET for the directory and
//! certificate, HEAD for a fresh nonce, and POST of the signed JWS. Network
//! I/O, so it is excluded from the no-network coverage gate; the client logic
//! it serves is unit-tested over a mock transport.

use std::pin::Pin;
use std::time::Duration;

use super::client::{AcmeError, AcmeTransport, PostResponse, ca_refusal};

const REPLAY_NONCE: &str = "Replay-Nonce";

/// Cap for any ACME HTTP response body. The CA is trusted, so this is defence
/// in depth rather than a hard trust boundary; it stops a misbehaving or
/// hostile peer from inflating a single response past what the protocol
/// legitimately produces (directory, account, order, authorization: kilobytes;
/// certificate chain: still well under a megabyte).
///
/// Enforced by chunk-by-chunk accumulation in [`read_response_body`], not by
/// `content_length` — that header can be absent or lie, so trusting it would
/// not be a cap at all.
const MAX_ACME_BODY_BYTES: usize = 1024 * 1024;

type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, AcmeError>> + Send + 'a>>;

/// HTTP transport over reqwest with conservative timeouts.
pub struct HttpTransport {
	client: reqwest::Client,
}

impl HttpTransport {
	/// Build a transport with a 30-second total request timeout applied to every
	/// call. Returns `AcmeError::Transport` if the underlying reqwest client
	/// cannot be constructed (for example, an invalid TLS backend).
	pub fn new() -> Result<Self, AcmeError> {
		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(30))
			.build()
			.map_err(|e| AcmeError::Transport(e.to_string()))?;
		Ok(HttpTransport { client })
	}
}

fn header(response: &reqwest::Response, name: &str) -> Option<String> {
	response
		.headers()
		.get(name)
		.and_then(|v| v.to_str().ok())
		.map(str::to_string)
}

/// Drain the body of a reqwest response into a single buffer, refusing any
/// payload whose total length would exceed [`MAX_ACME_BODY_BYTES`] bytes.
///
/// The cap is enforced chunk-by-chunk (`response.chunk()`), not by reading
/// `content_length` — that header can be absent, or be wrong, and trusting
/// it for a security cap is not a cap at all. An over-cap response yields
/// `AcmeError::Transport` named with the byte limit, so the operator can
/// tell at a glance that the failure was the body guard, not a network
/// outage.
async fn read_response_body(response: reqwest::Response) -> Result<Vec<u8>, AcmeError> {
	let mut response = response;
	let mut buf = Vec::new();
	while let Some(chunk) = response
		.chunk()
		.await
		.map_err(|e| AcmeError::Transport(e.to_string()))?
	{
		let projected = buf.len().saturating_add(chunk.len());
		if projected > MAX_ACME_BODY_BYTES {
			return Err(AcmeError::Transport(format!(
				"ACME response exceeded {MAX_ACME_BODY_BYTES}-byte body cap"
			)));
		}
		buf.extend_from_slice(&chunk);
	}
	Ok(buf)
}

impl AcmeTransport for HttpTransport {
	fn get(&self, url: &str) -> Fut<'_, Vec<u8>> {
		let url = url.to_string();
		Box::pin(async move {
			let response = self
				.client
				.get(&url)
				.send()
				.await
				.map_err(|e| AcmeError::Transport(e.to_string()))?;
			let status = response.status().as_u16();
			let body = read_response_body(response).await?;
			// The directory is the one resource fetched with GET. A refusal
			// carries a problem document, not a directory, so the status is
			// read before the body is taken for one.
			if !(200..300).contains(&status) {
				return Err(ca_refusal(status, &body));
			}
			Ok(body)
		})
	}

	fn new_nonce(&self, url: &str) -> Fut<'_, String> {
		let url = url.to_string();
		Box::pin(async move {
			let response = self
				.client
				.head(&url)
				.send()
				.await
				.map_err(|e| AcmeError::Transport(e.to_string()))?;
			let status = response.status().as_u16();
			if !(200..300).contains(&status) {
				// A HEAD answer carries no body: the status is all there is.
				return Err(ca_refusal(status, &[]));
			}
			header(&response, REPLAY_NONCE)
				.ok_or_else(|| AcmeError::Transport("newNonce response had no Replay-Nonce".into()))
		})
	}

	fn post(&self, url: &str, jws: &str) -> Fut<'_, PostResponse> {
		let url = url.to_string();
		let jws = jws.to_string();
		Box::pin(async move {
			let response = self
				.client
				.post(&url)
				.header(reqwest::header::CONTENT_TYPE, "application/jose+json")
				.body(jws)
				.send()
				.await
				.map_err(|e| AcmeError::Transport(e.to_string()))?;
			let nonce = header(&response, REPLAY_NONCE).unwrap_or_default();
			let location = header(&response, reqwest::header::LOCATION.as_str());
			let status = response.status().as_u16();
			let body = read_response_body(response).await?;
			Ok(PostResponse {
				nonce,
				location,
				status,
				body,
			})
		})
	}
}

#[cfg(test)]
mod tests;
