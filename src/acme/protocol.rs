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
	Pending,
	Ready,
	Processing,
	Valid,
	Invalid,
}

/// A certificate order.
#[derive(Debug, Clone, Deserialize)]
pub struct Order {
	pub status: OrderStatus,
	#[serde(default)]
	pub authorizations: Vec<String>,
	pub finalize: String,
	#[serde(default)]
	pub certificate: Option<String>,
}

/// The DNS identifier an authorization or order covers.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Identifier {
	#[serde(default)]
	pub value: String,
}

/// An authorization for one identifier, listing its challenges.
#[derive(Debug, Clone, Deserialize)]
pub struct Authorization {
	pub status: String,
	/// The domain this authorization covers (needed for the DNS-01 record name).
	#[serde(default)]
	pub identifier: Identifier,
	#[serde(default)]
	pub challenges: Vec<Challenge>,
}

/// A single challenge within an authorization.
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
	#[serde(rename = "type")]
	pub kind: String,
	pub url: String,
	pub token: String,
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
