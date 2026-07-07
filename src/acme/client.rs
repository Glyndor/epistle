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
use super::protocol::{self, Authorization, Order};

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

	/// Issue a certificate for `domains` end to end via HTTP-01: order, publish
	/// each challenge's key authorization, validate, finalize a fresh CSR, and
	/// download the chain. Returns the certificate chain PEM and its key PEM.
	/// `poll` bounds how many times each pending resource is re-checked.
	pub async fn obtain_certificate(
		&self,
		domains: &[String],
		http01: &super::http01::ChallengeStore,
		poll: u32,
	) -> Result<(String, String), AcmeError> {
		let (order, order_url) = self.new_order(domains).await?;
		let mut published = Vec::new();

		for authz_url in &order.authorizations {
			let authz = self.authorization(authz_url).await?;
			let challenge = authz
				.challenge("http-01")
				.ok_or_else(|| AcmeError::Protocol("no http-01 challenge".into()))?;
			http01.set(
				&challenge.token,
				&self.key.key_authorization(&challenge.token),
			);
			published.push(challenge.token.clone());
			self.respond_challenge(&challenge.url).await?;
			self.poll_authorization(authz_url, poll).await?;
		}

		let csr = super::csr::generate(domains).map_err(|e| AcmeError::Protocol(e.to_string()))?;
		let finalized = self.finalize(&order.finalize, &csr.der_b64url).await?;
		let certificate_url = self.poll_order(&order_url, &finalized, poll).await?;
		let chain = self.download_certificate(&certificate_url).await?;

		for token in published {
			http01.remove(&token);
		}
		let chain = String::from_utf8(chain).map_err(|e| AcmeError::Protocol(e.to_string()))?;
		Ok((chain, csr.key_pem))
	}

	/// Issue a certificate for `domains` end to end via DNS-01: order, publish
	/// each `_acme-challenge` TXT record through `provider`, validate, finalize,
	/// and download the chain. The challenge records are removed afterward.
	pub async fn obtain_certificate_dns01(
		&self,
		domains: &[String],
		provider: &dyn crate::dns::provider::DnsProvider,
		poll: u32,
	) -> Result<(String, String), AcmeError> {
		use crate::dns::provider::{DnsRecord, RecordKind};
		let (order, order_url) = self.new_order(domains).await?;
		let mut published: Vec<(String, DnsRecord)> = Vec::new();

		for authz_url in &order.authorizations {
			let authz = self.authorization(authz_url).await?;
			let challenge = authz
				.challenge("dns-01")
				.ok_or_else(|| AcmeError::Protocol("no dns-01 challenge".into()))?;
			let domain = authz.identifier.value.clone();
			let record = DnsRecord {
				name: format!("_acme-challenge.{domain}"),
				kind: RecordKind::Txt,
				value: self.key.dns01_value(&challenge.token),
				ttl: 60,
			};
			provider
				.upsert(&domain, record.clone())
				.await
				.map_err(|e| AcmeError::Protocol(e.to_string()))?;
			published.push((domain, record));
			self.respond_challenge(&challenge.url).await?;
			self.poll_authorization(authz_url, poll).await?;
		}

		let csr = super::csr::generate(domains).map_err(|e| AcmeError::Protocol(e.to_string()))?;
		let finalized = self.finalize(&order.finalize, &csr.der_b64url).await?;
		let certificate_url = self.poll_order(&order_url, &finalized, poll).await?;
		let chain = self.download_certificate(&certificate_url).await?;

		for (zone, record) in published {
			let _ = provider.delete(&zone, record).await;
		}
		let chain = String::from_utf8(chain).map_err(|e| AcmeError::Protocol(e.to_string()))?;
		Ok((chain, csr.key_pem))
	}

	/// Issue a certificate for `domains` end to end via TLS-ALPN-01: order,
	/// register each domain's challenge certificate in `alpn`, validate, finalize,
	/// and download the chain. The challenge certificates are dropped afterward.
	pub async fn obtain_certificate_tls_alpn01(
		&self,
		domains: &[String],
		alpn: &super::tlsalpn::AlpnChallengeStore,
		poll: u32,
	) -> Result<(String, String), AcmeError> {
		let (order, order_url) = self.new_order(domains).await?;
		let mut published = Vec::new();

		for authz_url in &order.authorizations {
			let authz = self.authorization(authz_url).await?;
			let challenge = authz
				.challenge("tls-alpn-01")
				.ok_or_else(|| AcmeError::Protocol("no tls-alpn-01 challenge".into()))?;
			let domain = authz.identifier.value.clone();
			alpn.set(&domain, &self.key.key_authorization(&challenge.token))
				.map_err(|e| AcmeError::Protocol(e.to_string()))?;
			published.push(domain);
			self.respond_challenge(&challenge.url).await?;
			self.poll_authorization(authz_url, poll).await?;
		}

		let csr = super::csr::generate(domains).map_err(|e| AcmeError::Protocol(e.to_string()))?;
		let finalized = self.finalize(&order.finalize, &csr.der_b64url).await?;
		let certificate_url = self.poll_order(&order_url, &finalized, poll).await?;
		let chain = self.download_certificate(&certificate_url).await?;

		for domain in published {
			alpn.remove(&domain);
		}
		let chain = String::from_utf8(chain).map_err(|e| AcmeError::Protocol(e.to_string()))?;
		Ok((chain, csr.key_pem))
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
#[path = "client_tests.rs"]
mod tests;
