//! DKIM signing (RFC 6376 section 5) for outbound mail.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};

use super::canon;
use super::signature::{Algorithm, Canon};

#[path = "sign_wire.rs"]
mod wire;

/// Headers included in the signature when present.
const SIGNED_HEADERS: &[&str] = &[
	"from",
	"to",
	"cc",
	"subject",
	"date",
	"message-id",
	"reply-to",
	"sender",
	"mime-version",
	"content-type",
	"content-transfer-encoding",
	"references",
	"in-reply-to",
	"list-id",
	"list-unsubscribe",
	"list-unsubscribe-post",
	"list-help",
	"list-post",
	"list-owner",
	"list-archive",
	"feedback-id",
	"disposition-notification-to",
	"return-receipt-to",
	"auto-submitted",
	"organization",
	"x-epistle",
];

/// List each name once beyond its present count, even when absent (RFC 6376 section 5.4).
const OVERSIGNED_HEADERS: &[&str] = &[
	"from",
	"to",
	"cc",
	"subject",
	"reply-to",
	"date",
	"message-id",
	"list-unsubscribe",
	"list-unsubscribe-post",
	"content-type",
	"disposition-notification-to",
	"return-receipt-to",
	// The server writes this one; a client that adds a second copy of it
	// has to keep both, or the signature breaks. Nothing in the path
	// legitimately writes `Auto-Submitted`, so oversigning it costs
	// nothing at delivery and stops a forged "this was automatic" claim.
	"auto-submitted",
];

/// A DKIM signer: always ed25519, optionally also RSA for dual-signing.
pub struct Signer {
	selector: String,
	key: Ed25519KeyPair,
	rsa: Option<Arc<RsaSigner>>,
}

/// An additional RSA-SHA256 signing key with its own selector.
struct RsaSigner {
	selector: String,
	key: RsaKeyPair,
}

/// Why signing material could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
	/// The PEM key file could not be read from disk: missing file, permission
	/// denied, or another I/O failure. Carries the path string and the
	/// underlying `std::io::Error`.
	#[error("cannot read key file {path}: {source}")]
	Read {
		/// Path that was attempted, formatted with `Display`.
		path: String,
		/// Underlying I/O error returned by `std::fs`.
		source: std::io::Error,
	},
	/// The PEM file was read but its body is not a valid ed25519 PKCS#8 key
	/// (or the file is not PEM at all). Carries the path string for the
	/// error message.
	#[error("invalid ed25519 key in {0}: expected PKCS#8 PEM")]
	InvalidKey(String),
}

impl Signer {
	/// Load a PKCS#8 PEM ed25519 private key.
	pub fn load(selector: &str, key_file: &std::path::Path) -> Result<Self, SignerError> {
		Ok(Signer {
			selector: selector.to_string(),
			key: load_ed25519_key(key_file)?,
			rsa: None,
		})
	}

	/// Add an RSA-SHA256 signature with its own selector and PKCS#8 PEM key, so
	/// the message carries both ed25519 and RSA DKIM signatures (RFC 8463).
	pub fn with_rsa(
		mut self,
		selector: &str,
		key_file: &std::path::Path,
	) -> Result<Self, SignerError> {
		self.rsa = Some(Arc::new(RsaSigner {
			selector: selector.to_string(),
			key: load_rsa_key(key_file)?,
		}));
		Ok(self)
	}

	/// Replace the ed25519 signing material and, when `rsa` names a
	/// selector and key file, the RSA key too. Without `rsa` the loaded RSA
	/// key (if any) is retained. Nothing is replaced unless every new key
	/// loads.
	pub(crate) fn with_rotated_keys(
		&self,
		selector: &str,
		key_file: &std::path::Path,
		rsa: Option<(&str, &std::path::Path)>,
	) -> Result<Self, SignerError> {
		let signer = Self::load(selector, key_file)?;
		match rsa {
			Some((rsa_selector, rsa_key_file)) => signer.with_rsa(rsa_selector, rsa_key_file),
			None => Ok(Signer {
				rsa: self.rsa.clone(),
				..signer
			}),
		}
	}

	/// The selector of the RSA key this signer also signs with, if any.
	pub fn rsa_selector(&self) -> Option<&str> {
		self.rsa.as_ref().map(|rsa| rsa.selector.as_str())
	}

	/// The selector of the ed25519 key this signer signs with.
	pub fn selector(&self) -> &str {
		&self.selector
	}

	/// The DNS TXT record value publishing this signer's public key.
	pub fn dns_record_value(&self) -> String {
		format!(
			"v=DKIM1; k=ed25519; p={}",
			BASE64.encode(self.key.public_key().as_ref())
		)
	}

	/// The DNS TXT record value for the optional RSA selector, in the form
	/// `v=DKIM1; k=rsa; p=<base64 SubjectPublicKeyInfo DER>`. `None` when no
	/// RSA key is configured. The `p=` value is the SPKI (RFC 6376 §3.6.1),
	/// not the PKCS#1 `RSAPublicKey` ring produces: `openssl rsa -pubout`
	/// prints the same envelope, which is what receivers verify against.
	pub fn rsa_dns_record_value(&self) -> Option<String> {
		Some(rsa_record(&self.rsa.as_ref()?.key))
	}

	/// Sign a raw message for `domain`, returning the full DKIM-Signature
	/// fields (with folding and trailing CRLF) to prepend.
	pub fn sign(&self, domain: &str, raw: &[u8]) -> Option<String> {
		let (headers, body) = split_message(raw)?;
		// Require the single From field used by the send-as check and DMARC.
		let from_fields = headers
			.iter()
			.filter(|(name, _)| name.eq_ignore_ascii_case("from"))
			.count();
		if from_fields != 1 {
			return None;
		}

		let canonical_body = canon::body(Canon::Relaxed, body);
		let body_hash = BASE64.encode(ring::digest::digest(&ring::digest::SHA256, &canonical_body));

		// Consume every selected instance bottom-up (RFC 6376 section 5.4.2).
		let unsafe_resent = collect_unsafe_resent_names(raw);
		let mut signed_names = Vec::new();
		let mut header_input = String::new();
		for (header_name, header_value) in headers.iter().rev() {
			let name = header_name.to_ascii_lowercase();
			let known = SIGNED_HEADERS.contains(&name.as_str());
			let resent = !known
				&& name.starts_with("resent-")
				&& is_safe_header_name(&name)
				&& !unsafe_resent.contains(&name);
			if known || resent {
				signed_names.push(name);
				header_input.push_str(&canon::header(Canon::Relaxed, header_name, header_value));
			}
		}
		// Absent instances contribute no bytes, but prevent later additions.
		signed_names.extend(OVERSIGNED_HEADERS.iter().map(|name| (*name).to_string()));
		let names = signed_names.join(":");

		// ed25519 first, then the optional RSA signature.
		let mut out = self.one_signature(
			"ed25519-sha256",
			&self.selector,
			domain,
			&names,
			&body_hash,
			&header_input,
			&|input| {
				// RFC 8463 section 3: an Ed25519-SHA256 signature covers the
				// SHA-256 digest of the header data, not the data itself.
				let signed = Algorithm::Ed25519Sha256.signed_bytes(input);
				Some(self.key.sign(signed.as_ref()).as_ref().to_vec())
			},
		)?;
		if let Some(rsa) = &self.rsa
			&& let Some(line) = self.one_signature(
				"rsa-sha256",
				&rsa.selector,
				domain,
				&names,
				&body_hash,
				&header_input,
				&|input| rsa_sign(&rsa.key, input),
			) {
			out.push_str(&line);
		}
		Some(out)
	}

	/// Build one `DKIM-Signature` header line for a given algorithm/selector.
	#[allow(clippy::too_many_arguments)]
	fn one_signature(
		&self,
		algorithm: &str,
		selector: &str,
		domain: &str,
		names: &str,
		body_hash: &str,
		header_input: &str,
		sign: &dyn Fn(&[u8]) -> Option<Vec<u8>>,
	) -> Option<String> {
		let value = wire::unsigned(algorithm, selector, domain, names, body_hash)?;
		let mut dkim_line = canon::header(Canon::Relaxed, "DKIM-Signature", &value);
		dkim_line.truncate(dkim_line.len() - 2);
		let mut hash_input = header_input.to_string();
		hash_input.push_str(&dkim_line);

		let signature = BASE64.encode(sign(hash_input.as_bytes())?);
		wire::finish(value, &signature)
	}
}

/// Generate a fresh ed25519 key, returning (PKCS#8 PEM, DNS record value).
pub fn generate_key() -> Result<(String, String), SignerError> {
	let rng = ring::rand::SystemRandom::new();
	let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
		.map_err(|_| SignerError::InvalidKey("key generation failed".into()))?;
	let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
		.map_err(|_| SignerError::InvalidKey("key generation failed".into()))?;

	let body = BASE64.encode(pkcs8.as_ref());
	let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
	for chunk in body.as_bytes().chunks(64) {
		pem.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
		pem.push('\n');
	}
	pem.push_str("-----END PRIVATE KEY-----\n");

	let record = format!(
		"v=DKIM1; k=ed25519; p={}",
		BASE64.encode(key.public_key().as_ref())
	);
	Ok((pem, record))
}

/// Load a PKCS#8 PEM ed25519 private key from a file. Shared by DKIM signing
/// and ARC sealing, which use the same key format.
pub(crate) fn load_ed25519_key(key_file: &std::path::Path) -> Result<Ed25519KeyPair, SignerError> {
	let pem = std::fs::read_to_string(key_file).map_err(|source| SignerError::Read {
		path: key_file.display().to_string(),
		source,
	})?;
	let der =
		pem_body(&pem).ok_or_else(|| SignerError::InvalidKey(key_file.display().to_string()))?;
	Ed25519KeyPair::from_pkcs8(&der)
		.map_err(|_| SignerError::InvalidKey(key_file.display().to_string()))
}

pub(crate) fn load_rsa_key(key_file: &std::path::Path) -> Result<RsaKeyPair, SignerError> {
	let pem = std::fs::read_to_string(key_file).map_err(|source| SignerError::Read {
		path: key_file.display().to_string(),
		source,
	})?;
	let der =
		pem_body(&pem).ok_or_else(|| SignerError::InvalidKey(key_file.display().to_string()))?;
	RsaKeyPair::from_pkcs8(&der)
		.map_err(|_| SignerError::InvalidKey(key_file.display().to_string()))
}

/// The DNS TXT record value publishing the RSA key in `key_file`, in the
/// form [`Signer::rsa_dns_record_value`] prints.
pub(crate) fn rsa_record_value(key_file: &std::path::Path) -> Result<String, SignerError> {
	Ok(rsa_record(&load_rsa_key(key_file)?))
}

fn rsa_record(key: &RsaKeyPair) -> String {
	let spki = super::spki::spki_for_rsa(key.public_key().as_ref());
	format!("v=DKIM1; k=rsa; p={}", BASE64.encode(spki))
}

/// RSASSA-PKCS1-v1_5 over SHA-256, the RSA variant DKIM uses.
fn rsa_sign(key: &RsaKeyPair, input: &[u8]) -> Option<Vec<u8>> {
	let mut signature = vec![0u8; key.public().modulus_len()];
	key.sign(
		&RSA_PKCS1_SHA256,
		&SystemRandom::new(),
		input,
		&mut signature,
	)
	.ok()?;
	Some(signature)
}

/// Extract the DER body of a single-block PEM file.
pub(super) fn pem_body(pem: &str) -> Option<Vec<u8>> {
	let mut body = String::new();
	let mut inside = false;
	for line in pem.lines() {
		if line.starts_with("-----BEGIN ") {
			inside = true;
			continue;
		}
		if line.starts_with("-----END ") {
			break;
		}
		if inside {
			body.push_str(line.trim());
		}
	}
	if body.is_empty() {
		return None;
	}
	BASE64.decode(body).ok()
}

/// Header (name, value) pairs of a message.
type HeaderPairs<'a> = Vec<(&'a str, &'a str)>;

/// Split raw message into header (name, value) pairs and body.
fn split_message(raw: &[u8]) -> Option<(HeaderPairs<'_>, &[u8])> {
	let (raw_block, body) = crate::util::header_block::split_at_blank_line(raw);
	let block = std::str::from_utf8(raw_block).ok()?;

	let mut headers = Vec::new();
	let mut current: Option<(usize, usize)> = None;
	let mut offset = 0;
	for line in block.split_inclusive('\n') {
		let start = offset;
		offset += line.len();
		let had_line_feed = line.ends_with('\n');
		let content = line.strip_suffix('\n').unwrap_or(line);
		let content = if had_line_feed {
			content.strip_suffix('\r').unwrap_or(content)
		} else {
			content
		};
		if content.starts_with(' ') || content.starts_with('\t') {
			if let Some((_, end)) = &mut current {
				*end = offset;
			}
			continue;
		}
		if let Some((from, to)) = current.take() {
			headers.push(&block[from..to]);
		}
		if !content.is_empty() {
			current = Some((start, offset));
		}
	}
	if let Some((from, to)) = current.take() {
		headers.push(&block[from..to]);
	}

	let mut parsed = Vec::with_capacity(headers.len());
	for header in headers {
		let had_line_feed = header.ends_with('\n');
		let header = header.strip_suffix('\n').unwrap_or(header);
		let header = if had_line_feed {
			header.strip_suffix('\r').unwrap_or(header)
		} else {
			header
		};
		let colon = header.find(':')?;
		parsed.push((header[..colon].trim_end(), &header[colon + 1..]));
	}
	Some((parsed, body))
}

/// Field names from the message that begin with `Resent-` but cannot appear
/// verbatim in a DKIM `h=` tag: a name with `:` or `;` would terminate the
/// tag or split it, and RFC 5322 §2.2 only allows printable US-ASCII without
/// `:`. The names are read from the raw bytes so a malformed one with
/// trailing whitespace that `split_message` would otherwise trim is still
/// caught.
fn collect_unsafe_resent_names(raw: &[u8]) -> std::collections::HashSet<String> {
	let mut unsafe_names = std::collections::HashSet::new();
	// Only the header block is read: a line of the body that looks like a
	// field must not change what the signature covers.
	let end = crate::util::header_block::split_at_blank_line(raw).0.len();
	for raw_line in raw[..end].split(|&b| b == b'\r' || b == b'\n') {
		if raw_line
			.first()
			.is_none_or(|byte| matches!(byte, b' ' | b'\t'))
		{
			continue;
		}
		let Ok(line) = std::str::from_utf8(raw_line) else {
			continue;
		};
		let Some((raw_name, _)) = line.split_once(':') else {
			continue;
		};
		if !is_safe_header_name(raw_name) {
			let trimmed = raw_name.trim_end().to_ascii_lowercase();
			if trimmed.starts_with("resent-") {
				unsafe_names.insert(trimmed);
			}
		}
	}
	unsafe_names
}

/// Whether `name` can be written into the DKIM `h=` tag. RFC 5322 §2.2
/// restricts field names to printable US-ASCII without `:`; DKIM §3.2 adds
/// `;` as the tag separator, so the name cannot contain one either.
fn is_safe_header_name(name: &str) -> bool {
	!name.is_empty()
		&& name
			.bytes()
			.all(|b| (33..=126).contains(&b) && b != b':' && b != b';')
}

#[cfg(test)]
#[path = "sign_tests_from.rs"]
mod tests_from;

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;
	use std::io::Write;
	use std::pin::Pin;

	use crate::spf::{DnsFailure, DnsLookup};

	fn temp_signer() -> (Signer, String) {
		let (pem, record) = generate_key().expect("generate");
		let mut file = tempfile::NamedTempFile::new().expect("temp file");
		file.write_all(pem.as_bytes()).expect("write key");
		let signer = Signer::load("sel", file.path()).expect("load key");
		// Keep the file alive long enough.
		std::mem::forget(file);
		(signer, record)
	}

	struct OneKeyDns {
		records: HashMap<String, Vec<String>>,
	}

	impl DnsLookup for OneKeyDns {
		fn txt(
			&self,
			name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
			let result = Ok(self.records.get(name).cloned().unwrap_or_default());
			Box::pin(async move { result })
		}

		fn addresses(
			&self,
			_name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>>
		{
			Box::pin(async { Ok(Vec::new()) })
		}

		fn mx(
			&self,
			_name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
			Box::pin(async { Ok(Vec::new()) })
		}
	}

	#[tokio::test]
	async fn signed_message_verifies_with_own_verifier() {
		let (signer, record) = temp_signer();
		let raw =
			b"From: alice@example.org\r\nSubject: hi\r\nTo: bob@elsewhere.example\r\n\r\nHello\r\n";
		let header = signer.sign("example.org", raw).expect("signs");
		let mut signed = header.into_bytes();
		signed.extend_from_slice(raw);

		let mut records = HashMap::new();
		records.insert("sel._domainkey.example.org".to_string(), vec![record]);
		let dns = OneKeyDns { records };

		let results = crate::dkim::verify_message(&dns, &signed).await;
		assert_eq!(results.len(), 1);
		assert_eq!(
			results[0].outcome,
			crate::dkim::DkimOutcome::Pass,
			"{results:?}"
		);
		assert_eq!(results[0].domain.as_deref(), Some("example.org"));
	}

	#[test]
	fn refuses_to_sign_without_from() {
		let (signer, _) = temp_signer();
		assert!(
			signer
				.sign("example.org", b"Subject: x\r\n\r\nbody\r\n")
				.is_none()
		);
	}

	#[test]
	fn dns_record_value_matches_generated_record() {
		let (signer, record) = temp_signer();
		assert_eq!(signer.dns_record_value(), record);
	}

	#[test]
	fn load_rejects_garbage() {
		let mut file = tempfile::NamedTempFile::new().expect("temp file");
		file.write_all(b"not a key").expect("write");
		assert!(Signer::load("sel", file.path()).is_err());
		assert!(Signer::load("sel", std::path::Path::new("/nonexistent")).is_err());
	}

	/// A 2048-bit RSA private key (PKCS#8 PEM) for the dual-signing test only.
	const RSA_TEST_KEY: &str = include_str!("test_rsa_key.pem");

	#[test]
	fn dual_signs_with_ed25519_and_rsa() {
		let (signer, _) = temp_signer();
		let mut rsa_file = tempfile::NamedTempFile::new().expect("temp file");
		rsa_file.write_all(RSA_TEST_KEY.as_bytes()).expect("write");
		let signer = signer.with_rsa("rsa", rsa_file.path()).expect("rsa key");

		let message = b"From: a@example.org\r\nSubject: hi\r\n\r\nbody\r\n";
		let signed = signer.sign("example.org", message).expect("sign");
		// Two DKIM-Signature headers, one per algorithm.
		assert_eq!(signed.matches("DKIM-Signature:").count(), 2, "{signed}");
		assert!(signed.contains("a=ed25519-sha256"), "{signed}");
		assert!(signed.contains("a=rsa-sha256"), "{signed}");
		assert!(signed.contains("s=sel;"), "{signed}");
		assert!(signed.contains("s=rsa;"), "{signed}");
	}

	#[test]
	fn signs_folded_header_and_empty_body() {
		let (signer, _) = temp_signer();
		// A folded From header and no trailing blank line / body.
		let message = b"From: Alice\r\n <alice@example.org>\r\nSubject: hi\r\n";
		let header = signer.sign("example.org", message).expect("signs");
		assert!(header.starts_with("DKIM-Signature:"), "{header}");
	}

	#[test]
	fn sign_rejects_non_utf8_headers() {
		let (signer, _) = temp_signer();
		assert!(
			signer
				.sign("example.org", b"From: \xff\xfe\r\n\r\nbody\r\n")
				.is_none()
		);
	}

	#[test]
	fn with_rsa_rejects_invalid_key() {
		let (signer, _) = temp_signer();
		let mut bad = tempfile::NamedTempFile::new().expect("temp file");
		bad.write_all(b"-----BEGIN PRIVATE KEY-----\nnotbase64!!!\n-----END PRIVATE KEY-----\n")
			.expect("write");
		assert!(signer.with_rsa("rsa", bad.path()).is_err());
		// A missing file fails too.
		let (signer, _) = temp_signer();
		assert!(
			signer
				.with_rsa("rsa", std::path::Path::new("/nonexistent"))
				.is_err()
		);
	}

	#[tokio::test]
	async fn resolver_stub_methods_are_inert() {
		let dns = OneKeyDns {
			records: HashMap::new(),
		};
		assert!(dns.addresses("x").await.expect("ok").is_empty());
		assert!(dns.mx("x").await.expect("ok").is_empty());
	}
}

#[cfg(test)]
#[path = "sign_tests_headers.rs"]
mod tests_headers;
