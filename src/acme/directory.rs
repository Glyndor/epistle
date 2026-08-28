//! The ACME directory (RFC 8555 §7.1.1): the CA's endpoint URLs.

use serde::Deserialize;

/// Resource URLs advertised by an ACME server's directory document.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Directory {
	/// URL for fetching a fresh anti-replay nonce (RFC 8555 §7.2). Reached
	/// with `HEAD`; the response's `Replay-Nonce` header is the next nonce.
	#[serde(rename = "newNonce")]
	pub new_nonce: String,
	/// URL for `newAccount` registration (RFC 8555 §7.3). The first request
	/// embeds the account JWK; the response's `Location` becomes the `kid`
	/// for every subsequent request.
	#[serde(rename = "newAccount")]
	pub new_account: String,
	/// URL for `newOrder` (RFC 8555 §7.4): the entry point for ordering a
	/// certificate. Each `newOrder` response carries the order URL to poll.
	#[serde(rename = "newOrder")]
	pub new_order: String,
	/// Optional `revokeCert` URL (RFC 8555 §7.6) for certificate revocation.
	#[serde(rename = "revokeCert")]
	pub revoke_cert: Option<String>,
	/// Optional `keyChange` URL (RFC 8555 §7.5) for rolling the account key.
	#[serde(rename = "keyChange")]
	pub key_change: Option<String>,
}

impl Directory {
	/// Parse a directory document.
	pub fn parse(body: &[u8]) -> Result<Self, serde_json::Error> {
		serde_json::from_slice(body)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_directory_with_required_endpoints() {
		let body = br#"{
			"newNonce": "https://acme.example/new-nonce",
			"newAccount": "https://acme.example/new-acct",
			"newOrder": "https://acme.example/new-order",
			"revokeCert": "https://acme.example/revoke-cert",
			"keyChange": "https://acme.example/key-change",
			"meta": {"termsOfService": "https://acme.example/tos"}
		}"#;
		let dir = Directory::parse(body).expect("parse");
		assert_eq!(dir.new_order, "https://acme.example/new-order");
		assert_eq!(
			dir.revoke_cert.as_deref(),
			Some("https://acme.example/revoke-cert")
		);
	}

	#[test]
	fn optional_endpoints_may_be_absent() {
		let body = br#"{
			"newNonce": "https://acme.example/new-nonce",
			"newAccount": "https://acme.example/new-acct",
			"newOrder": "https://acme.example/new-order"
		}"#;
		let dir = Directory::parse(body).expect("parse");
		assert!(dir.revoke_cert.is_none());
		assert_eq!(dir.new_nonce, "https://acme.example/new-nonce");
	}

	#[test]
	fn missing_required_endpoint_is_an_error() {
		let body = br#"{"newNonce": "x", "newAccount": "y"}"#;
		assert!(Directory::parse(body).is_err());
	}
}
