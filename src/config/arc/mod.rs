//! ARC sealing configuration (RFC 8617).

use std::path::PathBuf;

use serde::Deserialize;

/// ARC sealing material. The signing domain is the server hostname; the key is
/// published like a DKIM key at `<selector>._domainkey.<domain>`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arc {
	/// Selector published at `<selector>._domainkey.<domain>`.
	pub selector: String,
	/// ed25519 private key, PKCS#8 PEM (the same format DKIM uses).
	pub key_file: PathBuf,
}

#[cfg(test)]
mod tests;
