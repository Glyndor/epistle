//! ACME request payloads and response objects (RFC 8555 §7.3–§7.5).
//!
//! Pure (de)serialization: the HTTP client signs the request payloads with the
//! account key and parses these objects from the CA's responses.

use serde::Deserialize;
use serde_json::{Value, json};

/// `newAccount` request body: agree to the terms and offer contacts.
pub fn new_account_payload(contacts: &[String], terms_agreed: bool) -> Value {
	json!({
		"termsOfServiceAgreed": terms_agreed,
		"contact": contacts.iter().map(|c| format!("mailto:{c}")).collect::<Vec<_>>(),
	})
}

/// `newOrder` request body for a set of DNS identifiers.
pub fn new_order_payload(domains: &[String]) -> Value {
	json!({
		"identifiers": domains
			.iter()
			.map(|d| json!({ "type": "dns", "value": d }))
			.collect::<Vec<_>>(),
	})
}

/// `finalize` request body carrying the base64url DER CSR.
pub fn finalize_payload(csr_der_b64url: &str) -> Value {
	json!({ "csr": csr_der_b64url })
}

/// An order's lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
	/// The CA has accepted the order; the client must complete the
	/// authorizations for each identifier before the order moves on.
	Pending,
	/// All authorizations are valid; the client may POST a CSR to `finalize`.
	Ready,
	/// The CA is processing the CSR; poll until status moves to `valid` or
	/// `invalid`.
	Processing,
	/// The certificate has been issued; `Order::certificate` carries the URL
	/// to download the chain.
	Valid,
	/// The order will not be issued: an authorization failed or the CSR was
	/// rejected. The client should not retry with the same CSR.
	Invalid,
}

/// A certificate order.
#[derive(Debug, Clone, Deserialize)]
pub struct Order {
	/// Where the order currently sits in its lifecycle. The client polls
	/// until it is `Valid` (then `certificate` is set) or `Invalid`.
	pub status: OrderStatus,
	/// URLs for each per-identifier authorization. The client must complete
	/// one challenge per authorization before the order becomes `Ready`.
	#[serde(default)]
	pub authorizations: Vec<String>,
	/// URL to POST the CSR to for order finalization (RFC 8555 §7.4).
	pub finalize: String,
	/// URL to download the issued certificate chain (PEM) once `status` is
	/// `Valid`. Absent until issuance completes.
	#[serde(default)]
	pub certificate: Option<String>,
}

/// The DNS identifier an authorization or order covers.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Identifier {
	/// The identifier value (a DNS name when `type` is `dns`). Defaults to
	/// an empty string when the server omits the field.
	#[serde(default)]
	pub value: String,
}

/// An authorization for one identifier, listing its challenges.
#[derive(Debug, Clone, Deserialize)]
pub struct Authorization {
	/// The authorization status: `pending`, `valid`, or `invalid`. The client
	/// treats `pending` as a signal to respond to a challenge and re-poll.
	pub status: String,
	/// The domain this authorization covers (needed for the DNS-01 record name).
	#[serde(default)]
	pub identifier: Identifier,
	/// The challenges offered by the CA for this identifier (typically
	/// `http-01`, `dns-01`, and/or `tls-alpn-01`); the client picks one.
	#[serde(default)]
	pub challenges: Vec<Challenge>,
}

/// A single challenge within an authorization.
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
	/// The challenge type identifier (for example `http-01`, `dns-01`,
	/// `tls-alpn-01`); the client matches this against the responder it
	/// supports.
	#[serde(rename = "type")]
	pub kind: String,
	/// URL to POST `{}` to when the client is ready for the CA to validate
	/// the challenge (RFC 8555 §7.5.1).
	pub url: String,
	/// The opaque per-challenge token; combined with the account key
	/// thumbprint to form the `keyAuthorization` string.
	pub token: String,
	/// The challenge status: `pending`, `valid`, or `invalid`. `pending`
	/// means the CA is still trying to validate; the client polls until it
	/// changes.
	pub status: String,
}

impl Authorization {
	/// The challenge of the given type (e.g. `http-01`, `dns-01`), if offered.
	pub fn challenge(&self, kind: &str) -> Option<&Challenge> {
		self.challenges.iter().find(|c| c.kind == kind)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn builds_request_payloads() {
		let acct = new_account_payload(&["admin@example.org".to_string()], true);
		assert_eq!(acct["termsOfServiceAgreed"], true);
		assert_eq!(acct["contact"][0], "mailto:admin@example.org");

		let order = new_order_payload(&["a.example".to_string(), "b.example".to_string()]);
		assert_eq!(order["identifiers"][0]["type"], "dns");
		assert_eq!(order["identifiers"][1]["value"], "b.example");

		assert_eq!(finalize_payload("Q1NS")["csr"], "Q1NS");
	}

	#[test]
	fn parses_order() {
		let body = br#"{
			"status": "pending",
			"authorizations": ["https://acme.example/authz/1"],
			"finalize": "https://acme.example/finalize/1"
		}"#;
		let order: Order = serde_json::from_slice(body).expect("parse");
		assert_eq!(order.status, OrderStatus::Pending);
		assert_eq!(order.authorizations.len(), 1);
		assert!(order.certificate.is_none());
	}

	#[test]
	fn parses_authorization_and_selects_challenge() {
		let body = br#"{
			"status": "pending",
			"identifier": {"type": "dns", "value": "a.example"},
			"challenges": [
				{"type": "http-01", "url": "https://acme.example/chal/1", "token": "tok-http", "status": "pending"},
				{"type": "dns-01", "url": "https://acme.example/chal/2", "token": "tok-dns", "status": "pending"}
			]
		}"#;
		let authz: Authorization = serde_json::from_slice(body).expect("parse");
		assert_eq!(authz.challenge("http-01").unwrap().token, "tok-http");
		assert_eq!(authz.challenge("dns-01").unwrap().token, "tok-dns");
		assert!(authz.challenge("tls-alpn-01").is_none());
	}
}
