//! Parsing a TimeStampResp (RFC 3161 section 2.4.2) into its parts.
//!
//! The parser takes the structure apart and checks its shape; whether the
//! parts are true (the signature, the certificate chain, the digest) is
//! [`super::verify()`]'s job. Every list is capped, so a response cannot make
//! the parser do more than a fixed amount of work per byte.

use super::der::{DerError, Tlv, generalized_time, parse_one, small_unsigned, tag};
use super::oid;

/// The most certificates a token may carry.
pub const MAX_CERTIFICATES: usize = 8;
/// The most signed attributes a signer may carry.
pub const MAX_ATTRIBUTES: usize = 16;
/// The largest response accepted, in bytes.
pub const MAX_RESPONSE: usize = 64 * 1024;

/// What a token claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TstInfo<'a> {
	/// The TSA policy OID (content octets).
	pub policy: &'a [u8],
	/// The hash algorithm OID of the imprint.
	pub hash_algorithm: &'a [u8],
	/// The stamped digest.
	pub hashed_message: &'a [u8],
	/// The serial number (content octets).
	pub serial: &'a [u8],
	/// The time of stamping, epoch seconds.
	pub gen_time: u64,
	/// The nonce (INTEGER content octets), when present.
	pub nonce: Option<&'a [u8]>,
}

/// How the signer names its certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerId<'a> {
	/// Issuer name (raw DER) and serial number (content octets).
	IssuerSerial(&'a [u8], &'a [u8]),
	/// Subject key identifier.
	KeyId(&'a [u8]),
}

/// The one SignerInfo of a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer<'a> {
	/// Which certificate signed.
	pub id: SignerId<'a>,
	/// The digest algorithm OID.
	pub digest_algorithm: &'a [u8],
	/// The signed attributes as encoded (`[0]` tag), to be re-tagged SET
	/// for verification (RFC 5652 section 5.4).
	pub signed_attributes: &'a [u8],
	/// The `messageDigest` attribute value.
	pub message_digest: &'a [u8],
	/// The `contentType` attribute value (an OID), when present.
	pub content_type: Option<&'a [u8]>,
	/// The hash algorithm OID and certificate hash of the first ESSCertID
	/// of `signingCertificate` (SHA-1) or `signingCertificateV2`, when
	/// present. Its absence is a verification failure, reported as such.
	pub certificate_hash: Option<(&'a [u8], &'a [u8])>,
	/// The signature algorithm OID.
	pub signature_algorithm: &'a [u8],
	/// The signature.
	pub signature: &'a [u8],
}

/// A parsed token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token<'a> {
	/// The DER TSTInfo, as signed.
	pub tst_der: &'a [u8],
	/// Its fields.
	pub tst: TstInfo<'a>,
	/// The certificates the token carries, DER.
	pub certificates: Vec<&'a [u8]>,
	/// The signer.
	pub signer: Signer<'a>,
}

/// Why a response is not a usable token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
	/// Malformed DER.
	Der(DerError),
	/// The TSA refused (PKIStatus other than granted).
	Refused(u64),
	/// Well-formed DER of the wrong structure.
	Shape(&'static str),
}

impl From<DerError> for TokenError {
	fn from(error: DerError) -> Self {
		TokenError::Der(error)
	}
}

impl std::fmt::Display for TokenError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			TokenError::Der(error) => write!(formatter, "{error}"),
			TokenError::Refused(status) => {
				write!(formatter, "the TSA refused the request (status {status})")
			}
			TokenError::Shape(what) => write!(formatter, "not a timestamp token: {what}"),
		}
	}
}

/// Parse a whole TimeStampResp.
pub fn parse_response(bytes: &[u8]) -> Result<Token<'_>, TokenError> {
	if bytes.len() > MAX_RESPONSE {
		return Err(TokenError::Shape("response too large"));
	}
	let response = parse_one(bytes, tag::SEQUENCE)?;
	let mut fields = response.reader();
	let status_info = fields.expect(tag::SEQUENCE)?;
	let status = small_unsigned(&status_info.reader().expect(tag::INTEGER)?)?;
	// 0 granted, 1 grantedWithMods.
	if status > 1 {
		return Err(TokenError::Refused(status));
	}
	let token = fields.expect(tag::SEQUENCE)?;
	fields.finish()?;
	parse_content_info(token)
}

fn parse_content_info(content_info: Tlv<'_>) -> Result<Token<'_>, TokenError> {
	let mut fields = content_info.reader();
	if fields.expect(tag::OID)?.value != oid::SIGNED_DATA {
		return Err(TokenError::Shape("content is not SignedData"));
	}
	let explicit = fields.expect(tag::CONTEXT_0)?;
	fields.finish()?;
	let signed_data = parse_one(explicit.value, tag::SEQUENCE)?;
	let mut fields = signed_data.reader();
	fields.expect(tag::INTEGER)?;
	fields.expect(tag::SET)?;
	let (tst_der, tst) = parse_encapsulated(fields.expect(tag::SEQUENCE)?)?;
	let mut certificates = Vec::new();
	if let Some(set) = fields.optional(tag::CONTEXT_0)? {
		let mut items = set.reader();
		while !items.is_empty() {
			if certificates.len() == MAX_CERTIFICATES {
				return Err(TokenError::Shape("too many certificates"));
			}
			certificates.push(items.expect(tag::SEQUENCE)?.raw);
		}
	}
	fields.optional(tag::CONTEXT_1)?;
	let signer_infos = fields.expect(tag::SET)?;
	fields.finish()?;
	let mut signers = signer_infos.reader();
	let signer = parse_signer(signers.expect(tag::SEQUENCE)?)?;
	if !signers.is_empty() {
		return Err(TokenError::Shape("more than one signer"));
	}
	Ok(Token {
		tst_der,
		tst,
		certificates,
		signer,
	})
}

fn parse_encapsulated(encap: Tlv<'_>) -> Result<(&[u8], TstInfo<'_>), TokenError> {
	let mut fields = encap.reader();
	if fields.expect(tag::OID)?.value != oid::TST_INFO {
		return Err(TokenError::Shape("content is not TSTInfo"));
	}
	let explicit = fields.expect(tag::CONTEXT_0)?;
	fields.finish()?;
	let octets = parse_one(explicit.value, tag::OCTET_STRING)?;
	let tst = parse_one(octets.value, tag::SEQUENCE)?;
	let mut fields = tst.reader();
	if small_unsigned(&fields.expect(tag::INTEGER)?)? != 1 {
		return Err(TokenError::Shape("TSTInfo version is not 1"));
	}
	let policy = fields.expect(tag::OID)?.value;
	let imprint = fields.expect(tag::SEQUENCE)?;
	let mut imprint_fields = imprint.reader();
	let algorithm = imprint_fields.expect(tag::SEQUENCE)?;
	let hash_algorithm = algorithm.reader().expect(tag::OID)?.value;
	let hashed_message = imprint_fields.expect(tag::OCTET_STRING)?.value;
	imprint_fields.finish()?;
	let serial = fields.expect(tag::INTEGER)?.value;
	let gen_time = generalized_time(&fields.expect(tag::GENERALIZED_TIME)?)?;
	fields.optional(tag::SEQUENCE)?; // accuracy
	fields.optional(tag::BOOLEAN)?; // ordering
	let nonce = fields.optional(tag::INTEGER)?.map(|tlv| tlv.value);
	Ok((
		octets.value,
		TstInfo {
			policy,
			hash_algorithm,
			hashed_message,
			serial,
			gen_time,
			nonce,
		},
	))
}

fn parse_signer(info: Tlv<'_>) -> Result<Signer<'_>, TokenError> {
	let mut fields = info.reader();
	fields.expect(tag::INTEGER)?;
	let id = match fields.read()? {
		sid if sid.tag == tag::SEQUENCE => {
			let mut parts = sid.reader();
			let issuer = parts.expect(tag::SEQUENCE)?.raw;
			let serial = parts.expect(tag::INTEGER)?.value;
			parts.finish()?;
			SignerId::IssuerSerial(issuer, serial)
		}
		sid if sid.tag == tag::CONTEXT_0_PRIMITIVE => SignerId::KeyId(sid.value),
		other => return Err(TokenError::Der(DerError::Unexpected(other.tag))),
	};
	let digest_algorithm = fields
		.expect(tag::SEQUENCE)?
		.reader()
		.expect(tag::OID)?
		.value;
	let attributes = fields.expect(tag::CONTEXT_0)?;
	let signature_algorithm = fields
		.expect(tag::SEQUENCE)?
		.reader()
		.expect(tag::OID)?
		.value;
	let signature = fields.expect(tag::OCTET_STRING)?.value;
	fields.optional(tag::CONTEXT_1)?;
	fields.finish()?;
	let mut message_digest = None;
	let mut content_type = None;
	let mut certificate_hash = None;
	let mut items = attributes.reader();
	let mut count = 0;
	while !items.is_empty() {
		count += 1;
		if count > MAX_ATTRIBUTES {
			return Err(TokenError::Shape("too many signed attributes"));
		}
		let attribute = items.expect(tag::SEQUENCE)?;
		let mut parts = attribute.reader();
		let kind = parts.expect(tag::OID)?.value;
		let values = parts.expect(tag::SET)?;
		parts.finish()?;
		let value = parse_one(values.value, values.value.first().copied().unwrap_or(0))?;
		match kind {
			k if k == oid::MESSAGE_DIGEST => {
				message_digest = Some(parse_one(value.raw, tag::OCTET_STRING)?.value)
			}
			k if k == oid::CONTENT_TYPE => {
				content_type = Some(parse_one(value.raw, tag::OID)?.value)
			}
			k if k == oid::SIGNING_CERTIFICATE || k == oid::SIGNING_CERTIFICATE_V2 => {
				certificate_hash = Some(first_cert_hash(value, k == oid::SIGNING_CERTIFICATE_V2)?)
			}
			_ => {}
		}
	}
	Ok(Signer {
		id,
		digest_algorithm,
		signed_attributes: attributes.raw,
		message_digest: message_digest.ok_or(TokenError::Shape("no messageDigest attribute"))?,
		content_type,
		certificate_hash,
		signature_algorithm,
		signature,
	})
}

/// The hash of the first ESSCertID(v2) of a SigningCertificate(V2): the
/// signer's own certificate (RFC 2634 section 5.4, RFC 5035 section 4).
fn first_cert_hash(value: Tlv<'_>, v2: bool) -> Result<(&[u8], &[u8]), TokenError> {
	let signing = parse_one(value.raw, tag::SEQUENCE)?;
	let certs = signing.reader().expect(tag::SEQUENCE)?;
	let first = certs.reader().expect(tag::SEQUENCE)?;
	let mut parts = first.reader();
	let algorithm = if v2 {
		match parts.optional(tag::SEQUENCE)? {
			Some(algorithm) => algorithm.reader().expect(tag::OID)?.value,
			None => oid::SHA256,
		}
	} else {
		oid::SHA1
	};
	let hash = parts.expect(tag::OCTET_STRING)?.value;
	Ok((algorithm, hash))
}

#[cfg(test)]
#[path = "token_tests.rs"]
mod tests;
