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

#[cfg(test)]
mod tests {
	use super::*;
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
		let app = axum::Router::new()
			.route("/dir", get(directory))
			.route("/nonce", head(nonce))
			.route("/order", post(order));
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
}
