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
mod tests;
