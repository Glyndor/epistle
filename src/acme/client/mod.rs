//! ACME client orchestration (RFC 8555): account registration and ordering.
//!
//! The HTTP transport is behind a trait so the order/nonce flow is testable
//! without a network; the reqwest implementation lives separately. Nonces are
//! threaded request-to-request and the account URL becomes the `kid` for all
//! requests after registration.

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use super::directory::Directory;
use super::jws::AccountKey;
use super::problem::Refusal;
use super::protocol::{self, Authorization, Order};

mod published;
use published::Published;

/// Errors from the ACME flow.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
	/// HTTP-layer failure talking to the CA: network error, timeout, a non-2xx
	/// answer whose body is not a problem document (so no reason can be read
	/// out of it), or a malformed `Replay-Nonce` header.
	#[error("transport error: {0}")]
	Transport(String),
	/// ACME-protocol failure: the CA refused the request and said why in a
	/// problem document, an account that was not created, unparseable JSON,
	/// unexpected order/authorization status, missing `Location`, missing
	/// expected challenge, or a state the flow cannot recover from.
	#[error("protocol error: {0}")]
	Protocol(String),
}

/// The error a refused answer carries.
///
/// A CA that does not accept a request answers with a non-2xx status and a
/// problem document naming the reason (RFC 8555 §6.7). Read as the resource
/// that was asked for, that document stops the JSON parser on its numeric
/// `status` and the real reason is lost; read here, it is the error.
///
/// A body that is not a problem document did not come from the CA, so it is
/// reported as a transport failure with the bytes it carried.
pub(crate) fn ca_refusal(status: u16, body: &[u8]) -> AcmeError {
	let refusal = Refusal::read(status, body);
	if refusal.is_problem() {
		AcmeError::Protocol(refusal.describe())
	} else {
		AcmeError::Transport(refusal.describe())
	}
}

/// A signed-POST response: the next nonce, an optional resource location, the
/// HTTP status, and the body.
#[derive(Debug, Clone)]
pub struct PostResponse {
	/// The CA's next anti-replay nonce, taken from the `Replay-Nonce` header
	/// (empty string if the server omitted it).
	pub nonce: String,
	/// `Location` header value from the response, if the server set one. For
	/// `newAccount` and `newOrder` this carries the account or order URL.
	pub location: Option<String>,
	/// Numeric HTTP status returned by the CA (for example 201 on a freshly
	/// created account or order).
	pub status: u16,
	/// Raw response body bytes; the caller deserializes as the relevant
	/// resource type (order, authorization, etc.).
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
	key: Arc<AccountKey>,
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
			key: Arc::new(key),
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
		// Every answer carries the next nonce, a refusal included.
		*self.nonce.lock().expect("nonce lock") = response.nonce.clone();
		// A CA that refuses answers with a non-2xx status and a problem
		// document. The status is the only thing that tells the two apart,
		// and the body of a refusal is never the resource that was asked
		// for, so it is read as what it is.
		if !(200..300).contains(&response.status) {
			return Err(ca_refusal(response.status, &response.body));
		}
		Ok(response)
	}

	/// Register the account; the returned location becomes the `kid`.
	///
	/// Fails when the CA did not create an account: a refusal carries no
	/// `Location`, and so does an answer that quietly created nothing. Going
	/// on without one would send every later request with no `kid`, and the
	/// CA would refuse those for a reason that hides this one.
	pub async fn register(&self, contacts: &[String]) -> Result<(), AcmeError> {
		let payload = protocol::new_account_payload(contacts, true);
		let response = self
			.signed_post(
				&self.directory.new_account,
				&serde_json::to_vec(&payload).expect("json"),
			)
			.await?;
		let location = response.location.ok_or_else(|| {
			AcmeError::Protocol(
				"the CA answered newAccount without a Location: no account was created".into(),
			)
		})?;
		*self.account_url.lock().expect("account lock") = Some(location);
		Ok(())
	}

	/// Whether the account has been registered (a `kid` is held).
	pub fn is_registered(&self) -> bool {
		self.account_url.lock().expect("account lock").is_some()
	}

	/// Place a certificate order for `domains`, returning the order and its URL
	/// (the `Location` header, used to poll the order's status).
	pub async fn new_order(&self, domains: &[String]) -> Result<(Order, String), AcmeError> {
		let payload = protocol::new_order_payload(domains);
		let response = self
			.signed_post(
				&self.directory.new_order,
				&serde_json::to_vec(&payload).expect("json"),
			)
			.await?;
		let order: Order = serde_json::from_slice(&response.body)
			.map_err(|e| AcmeError::Protocol(e.to_string()))?;
		let url = response
			.location
			.ok_or_else(|| AcmeError::Protocol("newOrder response had no Location".into()))?;
		Ok((order, url))
	}

	/// Fetch a resource with POST-as-GET (RFC 8555 §6.3: empty payload).
	async fn post_as_get(&self, url: &str) -> Result<PostResponse, AcmeError> {
		self.signed_post(url, b"").await
	}

	/// Fetch an authorization (its identifier and challenges).
	pub async fn authorization(&self, url: &str) -> Result<Authorization, AcmeError> {
		let response = self.post_as_get(url).await?;
		serde_json::from_slice(&response.body).map_err(|e| AcmeError::Protocol(e.to_string()))
	}

	/// Tell the CA a challenge is ready to be validated (POST `{}`).
	pub async fn respond_challenge(&self, challenge_url: &str) -> Result<(), AcmeError> {
		self.signed_post(challenge_url, b"{}").await.map(|_| ())
	}

	/// Submit the CSR to finalize the order.
	pub async fn finalize(
		&self,
		finalize_url: &str,
		csr_der_b64url: &str,
	) -> Result<Order, AcmeError> {
		let payload = protocol::finalize_payload(csr_der_b64url);
		let response = self
			.signed_post(finalize_url, &serde_json::to_vec(&payload).expect("json"))
			.await?;
		serde_json::from_slice(&response.body).map_err(|e| AcmeError::Protocol(e.to_string()))
	}

	/// Poll an order's current state by URL.
	pub async fn order_status(&self, order_url: &str) -> Result<Order, AcmeError> {
		let response = self.post_as_get(order_url).await?;
		serde_json::from_slice(&response.body).map_err(|e| AcmeError::Protocol(e.to_string()))
	}

	/// Download the issued certificate chain (PEM).
	pub async fn download_certificate(&self, certificate_url: &str) -> Result<Vec<u8>, AcmeError> {
		Ok(self.post_as_get(certificate_url).await?.body)
	}

	/// Issue a certificate for `domains` end to end: order, answer each
	/// authorization's challenge through `responder`, validate, finalize a
	/// fresh CSR, and download the chain. Returns the certificate chain PEM
	/// and its key PEM. `poll` bounds how many times each pending resource is
	/// re-checked.
	///
	/// Every challenge published is withdrawn once validation is over,
	/// whether it succeeded or not: a DNS-01 TXT record or a TLS-ALPN-01
	/// certificate left behind would keep answering for an order that no
	/// longer exists. The same holds when the returned future is dropped
	/// mid-order (shutdown, an aborted renewal): what was still published is
	/// withdrawn by a task spawned on the running runtime, which is why the
	/// responder is shared rather than borrowed.
	pub async fn obtain_certificate(
		&self,
		domains: &[String],
		responder: Arc<dyn super::challenge::ChallengeResponder>,
		poll: u32,
	) -> Result<(String, String), AcmeError> {
		let (order, order_url) = self.new_order(domains).await?;
		let mut published = Published::new(responder, self.key.clone());
		let validated = self
			.validate_authorizations(&order, &mut published, poll)
			.await;
		published.withdraw_all().await;
		validated?;

		let csr = super::csr::generate(domains).map_err(|e| AcmeError::Protocol(e.to_string()))?;
		let finalized = self.finalize(&order.finalize, &csr.der_b64url).await?;
		let certificate_url = self.poll_order(&order_url, &finalized, poll).await?;
		let chain = self.download_certificate(&certificate_url).await?;
		let chain = String::from_utf8(chain).map_err(|e| AcmeError::Protocol(e.to_string()))?;
		Ok((chain, csr.key_pem))
	}

	/// Answer and validate every authorization of `order`, recording each
	/// challenge in `published` before it is published so that even a
	/// half-published one is withdrawn.
	async fn validate_authorizations(
		&self,
		order: &Order,
		published: &mut Published,
		poll: u32,
	) -> Result<(), AcmeError> {
		let responder = published.responder.clone();
		let kind = responder.kind();
		for authz_url in &order.authorizations {
			let authz = self.authorization(authz_url).await?;
			let challenge = authz
				.challenge(kind)
				.ok_or_else(|| AcmeError::Protocol(format!("no {kind} challenge")))?;
			let domain = authz.identifier.value.clone();
			published.record(&domain, &challenge.token);
			responder
				.publish(&domain, &challenge.token, &self.key)
				.await?;
			self.respond_challenge(&challenge.url).await?;
			self.poll_authorization(authz_url, poll).await?;
		}
		Ok(())
	}

	/// Re-check an authorization until it is `valid` (or bail on `invalid`).
	async fn poll_authorization(&self, url: &str, max: u32) -> Result<(), AcmeError> {
		for _ in 0..max.max(1) {
			let authz = self.authorization(url).await?;
			match authz.status.as_str() {
				"valid" => return Ok(()),
				"invalid" => return Err(AcmeError::Protocol("authorization invalid".into())),
				_ => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
			}
		}
		Err(AcmeError::Protocol(
			"authorization not valid in time".into(),
		))
	}

	/// Re-check an order until `valid`, returning its certificate URL.
	async fn poll_order(
		&self,
		order_url: &str,
		initial: &Order,
		max: u32,
	) -> Result<String, AcmeError> {
		let mut order = initial.clone();
		for attempt in 0..max.max(1) {
			if let (protocol::OrderStatus::Valid, Some(url)) = (order.status, &order.certificate) {
				return Ok(url.clone());
			}
			if order.status == protocol::OrderStatus::Invalid {
				return Err(AcmeError::Protocol("order invalid".into()));
			}
			if attempt + 1 < max.max(1) {
				tokio::time::sleep(std::time::Duration::from_secs(1)).await;
				order = self.order_status(order_url).await?;
			}
		}
		Err(AcmeError::Protocol("order not valid in time".into()))
	}
}

#[cfg(test)]
mod tests;
