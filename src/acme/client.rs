//! ACME client orchestration (RFC 8555): account registration and ordering.
//!
//! The HTTP transport is behind a trait so the order/nonce flow is testable
//! without a network; the reqwest implementation lives separately. Nonces are
//! threaded request-to-request and the account URL becomes the `kid` for all
//! requests after registration.

use std::pin::Pin;
use std::sync::Mutex;

use super::directory::Directory;
use super::jws::AccountKey;
use super::protocol::{self, Order};

/// Errors from the ACME flow.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
	#[error("transport error: {0}")]
	Transport(String),
	#[error("protocol error: {0}")]
	Protocol(String),
}

/// A signed-POST response: the next nonce, an optional resource location, the
/// HTTP status, and the body.
#[derive(Debug, Clone)]
pub struct PostResponse {
	pub nonce: String,
	pub location: Option<String>,
	pub status: u16,
	pub body: Vec<u8>,
}

type Fut<'a, T> = Pin<Box<dyn Future<Output = Result<T, AcmeError>> + Send + 'a>>;

/// HTTP transport for ACME, abstracted for testing.
pub trait AcmeTransport: Send + Sync {
	/// GET a URL (directory, certificate).
	fn get(&self, url: &str) -> Fut<'_, Vec<u8>>;
	/// Fetch a fresh anti-replay nonce (the `Replay-Nonce` header of newNonce).
	fn new_nonce(&self, url: &str) -> Fut<'_, String>;
	/// POST a signed JWS body to a URL.
	fn post(&self, url: &str, jws: &str) -> Fut<'_, PostResponse>;
}

/// An ACME client bound to one CA directory and account key.
pub struct AcmeClient<T: AcmeTransport> {
	transport: T,
	key: AccountKey,
	directory: Directory,
	nonce: Mutex<String>,
	account_url: Mutex<Option<String>>,
}

impl<T: AcmeTransport> AcmeClient<T> {
	/// Fetch the directory and an initial nonce.
	pub async fn connect(
		transport: T,
		key: AccountKey,
		directory_url: &str,
	) -> Result<Self, AcmeError> {
		let body = transport.get(directory_url).await?;
		let directory = Directory::parse(&body).map_err(|e| AcmeError::Protocol(e.to_string()))?;
		let nonce = transport.new_nonce(&directory.new_nonce).await?;
		Ok(AcmeClient {
			transport,
			key,
			directory,
			nonce: Mutex::new(nonce),
			account_url: Mutex::new(None),
		})
	}

	fn take_nonce(&self) -> String {
		self.nonce.lock().expect("nonce lock").clone()
	}

	/// Sign and POST `payload` to `url`, threading the nonce and `kid`.
	async fn signed_post(&self, url: &str, payload: &[u8]) -> Result<PostResponse, AcmeError> {
		let nonce = self.take_nonce();
		let kid = self.account_url.lock().expect("account lock").clone();
		let jws = self
			.key
			.sign(url, &nonce, payload, kid.as_deref())
			.map_err(|e| AcmeError::Protocol(e.to_string()))?;
		let response = self.transport.post(url, &jws).await?;
		*self.nonce.lock().expect("nonce lock") = response.nonce.clone();
		Ok(response)
	}

	/// Register the account; the returned location becomes the `kid`.
	pub async fn register(&self, contacts: &[String]) -> Result<(), AcmeError> {
		let payload = protocol::new_account_payload(contacts, true);
		let response = self
			.signed_post(
				&self.directory.new_account,
				&serde_json::to_vec(&payload).expect("json"),
			)
			.await?;
		if let Some(location) = response.location {
			*self.account_url.lock().expect("account lock") = Some(location);
		}
		Ok(())
	}

	/// Whether the account has been registered (a `kid` is held).
	pub fn is_registered(&self) -> bool {
		self.account_url.lock().expect("account lock").is_some()
	}

	/// Place a certificate order for `domains`.
	pub async fn new_order(&self, domains: &[String]) -> Result<Order, AcmeError> {
		let payload = protocol::new_order_payload(domains);
		let response = self
			.signed_post(
				&self.directory.new_order,
				&serde_json::to_vec(&payload).expect("json"),
			)
			.await?;
		serde_json::from_slice(&response.body).map_err(|e| AcmeError::Protocol(e.to_string()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;

	/// Transport returning canned responses keyed by URL, recording POSTs.
	struct ScriptedTransport {
		directory: Vec<u8>,
		posts: Mutex<HashMap<String, PostResponse>>,
	}

	impl AcmeTransport for ScriptedTransport {
		fn get(&self, _url: &str) -> Fut<'_, Vec<u8>> {
			let body = self.directory.clone();
			Box::pin(async move { Ok(body) })
		}
		fn new_nonce(&self, _url: &str) -> Fut<'_, String> {
			Box::pin(async { Ok("nonce-0".to_string()) })
		}
		fn post(&self, url: &str, _jws: &str) -> Fut<'_, PostResponse> {
			let resp = self
				.posts
				.lock()
				.expect("posts")
				.get(url)
				.cloned()
				.expect("scripted response");
			Box::pin(async move { Ok(resp) })
		}
	}

	fn directory_json() -> Vec<u8> {
		br#"{
			"newNonce": "https://acme.example/new-nonce",
			"newAccount": "https://acme.example/new-acct",
			"newOrder": "https://acme.example/new-order"
		}"#
		.to_vec()
	}

	#[tokio::test]
	async fn register_then_order_threads_account_and_parses_order() {
		let (key, _) = AccountKey::generate().expect("key");
		let mut posts = HashMap::new();
		posts.insert(
			"https://acme.example/new-acct".to_string(),
			PostResponse {
				nonce: "nonce-1".to_string(),
				location: Some("https://acme.example/acct/42".to_string()),
				status: 201,
				body: b"{}".to_vec(),
			},
		);
		posts.insert(
			"https://acme.example/new-order".to_string(),
			PostResponse {
				nonce: "nonce-2".to_string(),
				location: Some("https://acme.example/order/7".to_string()),
				status: 201,
				body: br#"{"status":"pending","authorizations":["https://acme.example/authz/1"],"finalize":"https://acme.example/finalize/7"}"#.to_vec(),
			},
		);
		let transport = ScriptedTransport {
			directory: directory_json(),
			posts: Mutex::new(posts),
		};

		let client = AcmeClient::connect(transport, key, "https://acme.example/dir")
			.await
			.expect("connect");
		assert!(!client.is_registered());
		client
			.register(&["admin@example.org".to_string()])
			.await
			.expect("register");
		assert!(client.is_registered());

		let order = client
			.new_order(&["mail.example.org".to_string()])
			.await
			.expect("order");
		assert_eq!(order.finalize, "https://acme.example/finalize/7");
		assert_eq!(order.authorizations.len(), 1);
	}
}
