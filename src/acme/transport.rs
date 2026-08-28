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
			read_response_body(response).await
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
mod tests {
	use super::*;
	use axum::body::Bytes;
	use axum::http::{HeaderName, StatusCode};
	use axum::response::IntoResponse;
	use axum::routing::{get, head, post};

	/// Spawn an in-process ACME-like server and return its base URL.
	async fn mock_server() -> String {
		async fn directory() -> &'static str {
			r#"{"newNonce":"/nonce"}"#
		}
		async fn nonce() -> impl IntoResponse {
			([(HeaderName::from_static("replay-nonce"), "nonce-1")], "")
		}
		async fn order() -> impl IntoResponse {
			(
				StatusCode::CREATED,
				[
					(HeaderName::from_static("replay-nonce"), "nonce-2"),
					(HeaderName::from_static("location"), "/order/1"),
				],
				r#"{"status":"pending"}"#,
			)
		}
		// Body sizes the test fixtures pin to a value in their own scope, so the
		// cap can shrink or grow without resizing the payloads the server
		// actually sends (which would OOM if we grew the payload with a
		// usize::MAX cap during the deletion-control experiment). `SMALL` sits
		// at 1 KiB and `OVER_CAP` at twice the production cap; both are well
		// within what an in-process test should allocate.
		const SMALL: usize = 1024;
		const OVER_CAP: usize = 1024 * 1024 * 2;

		// /small: well under the cap. The transport must pass it through.
		async fn small() -> Bytes {
			Bytes::from(vec![b'x'; SMALL])
		}
		// /over_cap: a body two times the production cap, so the fixture
		// always overshoots the configured cap by a healthy margin. The
		// transport must reject it as soon as the chunked accumulation
		// crosses the cap, regardless of what `content_length` would claim.
		async fn over_cap() -> Bytes {
			Bytes::from(vec![b'y'; OVER_CAP])
		}
		async fn over_cap_post() -> Bytes {
			over_cap().await
		}
		let app = axum::Router::new()
			.route("/dir", get(directory))
			.route("/nonce", head(nonce))
			.route("/order", post(order))
			.route("/small", get(small))
			.route("/over_cap", get(over_cap))
			.route("/over_cap_post", post(over_cap_post));
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
			.await
			.expect("bind");
		let addr = listener.local_addr().expect("addr");
		tokio::spawn(async move {
			axum::serve(listener, app).await.expect("serve");
		});
		format!("http://{addr}")
	}

	#[tokio::test]
	async fn get_nonce_and_post_round_trip() {
		let base = mock_server().await;
		let transport = HttpTransport::new().expect("transport");

		let body = transport.get(&format!("{base}/dir")).await.expect("get");
		assert!(body.starts_with(b"{\"newNonce\""));

		let nonce = transport
			.new_nonce(&format!("{base}/nonce"))
			.await
			.expect("nonce");
		assert_eq!(nonce, "nonce-1");

		let response = transport
			.post(&format!("{base}/order"), "signed-jws")
			.await
			.expect("post");
		assert_eq!(response.status, 201);
		assert_eq!(response.nonce, "nonce-2");
		assert_eq!(response.location.as_deref(), Some("/order/1"));
		assert!(response.body.starts_with(b"{\"status\""));
	}

	#[tokio::test]
	async fn new_nonce_without_header_errors() {
		// /dir answers GET but not a HEAD with a nonce header.
		let base = mock_server().await;
		let transport = HttpTransport::new().expect("transport");
		assert!(transport.new_nonce(&format!("{base}/dir")).await.is_err());
	}

	#[tokio::test]
	async fn unreachable_endpoint_is_transport_error() {
		let transport = HttpTransport::new().expect("transport");
		assert!(transport.get("http://127.0.0.1:1/dir").await.is_err());
		assert!(transport.new_nonce("http://127.0.0.1:1/n").await.is_err());
		assert!(transport.post("http://127.0.0.1:1/o", "j").await.is_err());
	}

	#[tokio::test]
	async fn get_body_under_cap_passes_through() {
		let base = mock_server().await;
		let transport = HttpTransport::new().expect("transport");
		let body = transport
			.get(&format!("{base}/small"))
			.await
			.expect("small body should pass the cap");
		assert_eq!(body.len(), 1024);
	}

	#[tokio::test]
	async fn get_body_over_cap_fails_naming_the_limit() {
		let base = mock_server().await;
		let transport = HttpTransport::new().expect("transport");
		let error = transport
			.get(&format!("{base}/over_cap"))
			.await
			.expect_err("cap should reject bodies past the limit");
		let message = match error {
			AcmeError::Transport(s) => s,
			other => panic!("expected AcmeError::Transport, got {other:?}"),
		};
		assert!(
			message.contains("body cap"),
			"error must name the cap: {message}"
		);
		assert!(
			message.contains(&MAX_ACME_BODY_BYTES.to_string()),
			"error must name the cap value ({}): {message}",
			MAX_ACME_BODY_BYTES
		);
	}

	#[tokio::test]
	async fn post_body_over_cap_fails_naming_the_limit() {
		// Same cap applies to POST responses, where the cert chain comes back.
		let base = mock_server().await;
		let transport = HttpTransport::new().expect("transport");
		let error = transport
			.post(&format!("{base}/over_cap_post"), "signed-jws")
			.await
			.expect_err("post cap should reject bodies past the limit");
		let message = match error {
			AcmeError::Transport(s) => s,
			other => panic!("expected AcmeError::Transport, got {other:?}"),
		};
		assert!(
			message.contains(&MAX_ACME_BODY_BYTES.to_string()),
			"error must name the cap value ({}): {message}",
			MAX_ACME_BODY_BYTES
		);
	}
}
