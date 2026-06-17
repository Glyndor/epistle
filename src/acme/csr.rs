//! Certificate Signing Request generation for ACME finalize (RFC 8555 §7.4).
//!
//! A fresh certificate key pair is generated per order; the CSR carries the
//! order's domains as SANs and is sent base64url-DER to the `finalize`
//! endpoint. The certificate private key is returned as PEM to persist
//! alongside the issued chain.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

/// Errors from CSR generation.
#[derive(Debug, thiserror::Error)]
pub enum CsrError {
	#[error("CSR generation failed: {0}")]
	Generate(String),
}

/// A generated CSR and its certificate private key.
pub struct Csr {
	/// DER-encoded PKCS#10 CSR, base64url (no padding) — ready for `finalize`.
	pub der_b64url: String,
	/// The certificate private key (PKCS#8 PEM) to persist with the chain.
	pub key_pem: String,
}

/// Generate a CSR covering `domains` (the first is the subject CN; all are
/// SANs), signed by a fresh ECDSA key pair.
pub fn generate(domains: &[String]) -> Result<Csr, CsrError> {
	if domains.is_empty() {
		return Err(CsrError::Generate("no domains".into()));
	}
	let key = rcgen::KeyPair::generate().map_err(|e| CsrError::Generate(e.to_string()))?;
	let params = rcgen::CertificateParams::new(domains.to_vec())
		.map_err(|e| CsrError::Generate(e.to_string()))?;
	let request = params
		.serialize_request(&key)
		.map_err(|e| CsrError::Generate(e.to_string()))?;
	Ok(Csr {
		der_b64url: B64.encode(request.der()),
		key_pem: key.serialize_pem(),
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn generates_der_csr_and_key() {
		let csr = generate(&["mail.example.org".to_string(), "example.org".to_string()])
			.expect("generate");
		// base64url decodes to a DER SEQUENCE (0x30).
		let der = B64.decode(&csr.der_b64url).expect("b64url");
		assert_eq!(der.first(), Some(&0x30));
		// A private key PEM is returned.
		assert!(csr.key_pem.contains("PRIVATE KEY"));
	}

	#[test]
	fn rejects_empty_domains() {
		assert!(generate(&[]).is_err());
	}
}
