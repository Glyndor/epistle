//! reqwest-backed [`AcmeTransport`] (RFC 8555 §6).
//!
//! Carries the ACME requests the client builds: GET for the directory and
//! certificate, HEAD for a fresh nonce, and POST of the signed JWS. Network
//! I/O, so it is excluded from the no-network coverage gate; the client logic
//! it serves is unit-tested over a mock transport.

use std::pin::Pin;
use std::time::Duration;

use super::client::{AcmeError, AcmeTransport, PostResponse};

const REPLAY_NONCE: &str = "Replay-Nonce";

type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, AcmeError>> + Send + 'a>>;

/// HTTP transport over reqwest with conservative timeouts.
pub struct HttpTransport {
	client: reqwest::Client,
}

impl HttpTransport {
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
			let bytes = response
				.bytes()
				.await
				.map_err(|e| AcmeError::Transport(e.to_string()))?;
			Ok(bytes.to_vec())
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
			let body = response
				.bytes()
				.await
				.map_err(|e| AcmeError::Transport(e.to_string()))?
				.to_vec();
			Ok(PostResponse {
				nonce,
				location,
				status,
				body,
			})
		})
	}
}
