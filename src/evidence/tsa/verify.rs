//! Verifying a timestamp token, check by check.
//!
//! A token proves a time only when all of these hold, and [`check`] reports
//! each one on its own:
//!
//! - (a) the signer certificate chains, certificate by certificate, to a
//!   key the operator pinned. Certificates the response carries are only
//!   intermediates: the chain must end at a key whose SubjectPublicKeyInfo
//!   hashes to a pinned anchor, so a response cannot vouch for itself;
//! - (b) the signer has the extended key usage `timeStamping`, critical, and
//!   no other (RFC 3161 section 2.3);
//! - (c) the time stamped lies within the validity of the signer and of
//!   every certificate of the chain;
//! - (d) an ESSCertID or ESSCertIDv2 in the signed attributes names the
//!   signer certificate (RFC 2634, RFC 5035, RFC 5816);
//! - (e) the imprint is SHA-256 of our digest;
//! - (f) the nonce is the one we sent (checked when the token is received;
//!   a stored token is verified without it);
//! - (g) the signed content type is TSTInfo, the signed `messageDigest` is
//!   the digest of the TSTInfo, and the signature over the DER of the
//!   signed attributes verifies with the signer's key;
//! - (h) the policy is the configured one, when one is configured.
//!
//! Revocation (CRL, OCSP) is not checked: a token is judged by what the
//! certificates said at the stamped time.

use x509_parser::prelude::{FromDer, X509Certificate};

use super::der::{tag, unsigned_content};
use super::keys::{cms_algorithm, signed_by, verify_with};
use super::oid;
use super::token::{SignerId, Token, TokenError, parse_response};
use crate::evidence::record::{sha256, to_hex};

/// The longest chain walked from the signer to an anchor.
const MAX_CHAIN: usize = 6;

/// One of the conditions a token must meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
	/// (a) chain to a pinned anchor.
	Anchor,
	/// (b) critical timeStamping usage, and no other.
	KeyUsage,
	/// (c) every certificate valid at the stamped time.
	Validity,
	/// (d) ESSCertID(v2) names the signer.
	SigningCertificate,
	/// (e) the imprint is our SHA-256 digest.
	Imprint,
	/// (f) the nonce is ours.
	Nonce,
	/// (g) content type, messageDigest and signature.
	Signature,
	/// (h) the configured policy.
	Policy,
}

impl Check {
	/// Every check, in the order they are reported.
	pub const ALL: [Check; 8] = [
		Check::Anchor,
		Check::KeyUsage,
		Check::Validity,
		Check::SigningCertificate,
		Check::Imprint,
		Check::Nonce,
		Check::Signature,
		Check::Policy,
	];

	/// What the check establishes, for a report.
	pub fn label(self) -> &'static str {
		match self {
			Check::Anchor => "(a) the signer chains to a pinned anchor",
			Check::KeyUsage => "(b) the signer is a critical timeStamping-only key",
			Check::Validity => "(c) every certificate was valid at the stamped time",
			Check::SigningCertificate => "(d) ESSCertID names the signer certificate",
			Check::Imprint => "(e) the imprint is the SHA-256 being verified",
			Check::Nonce => "(f) the nonce is the one requested",
			Check::Signature => "(g) content type, messageDigest and signature verify",
			Check::Policy => "(h) the policy is the configured one",
		}
	}
}

/// How one check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
	/// It holds.
	Passed,
	/// It does not, and why.
	Failed(&'static str),
	/// It was not asked for (no nonce or policy to compare with).
	NotApplicable,
}

/// What a verification expects.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
	/// The SHA-256 the token must stamp.
	pub digest: &'a [u8; 32],
	/// The nonce sent, when it is known.
	pub nonce: Option<u64>,
	/// Pinned anchors: SHA-256 of trusted SubjectPublicKeyInfos.
	pub anchors: &'a [[u8; 32]],
	/// The policy OID (content octets) required, when one is configured.
	pub policy: Option<&'a [u8]>,
}

/// The outcome of every check, and what the token says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
	/// One outcome per [`Check::ALL`] entry, in that order.
	pub checks: Vec<(Check, Outcome)>,
	/// When the TSA stamped, epoch seconds.
	pub gen_time: u64,
	/// The serial number, hex.
	pub serial: String,
	/// The anchor reached, hex, when the chain reached one.
	pub anchor: Option<String>,
	/// The certificates the token carried, DER, signer first when found.
	pub certificates: Vec<Vec<u8>>,
}

impl Report {
	/// The first failed check, in [`Check::ALL`] order.
	pub fn first_failure(&self) -> Option<(Check, &'static str)> {
		self.checks
			.iter()
			.find_map(|(check, outcome)| match outcome {
				Outcome::Failed(why) => Some((*check, *why)),
				_ => None,
			})
	}
}

/// What a verified token says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
	/// When the TSA stamped the digest, epoch seconds.
	pub gen_time: u64,
	/// The token's serial number, hex.
	pub serial: String,
	/// Hex SHA-256 of the anchor key the chain reached.
	pub anchor: String,
}

/// Why a token does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
	/// The response is not a token.
	Token(TokenError),
	/// The token stamps something else.
	Imprint,
	/// The token carries another nonce.
	Nonce,
	/// Another check failed.
	Untrusted(&'static str),
}

impl From<TokenError> for VerifyError {
	fn from(error: TokenError) -> Self {
		VerifyError::Token(error)
	}
}

impl std::fmt::Display for VerifyError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			VerifyError::Token(error) => write!(formatter, "{error}"),
			VerifyError::Imprint => formatter.write_str("the token stamps a different digest"),
			VerifyError::Nonce => formatter.write_str("the token carries a different nonce"),
			VerifyError::Untrusted(why) => write!(formatter, "the token does not verify: {why}"),
		}
	}
}

/// Verify `response` and return the stamp, or the first failed check.
pub fn verify_expected(response: &[u8], expected: &Expected<'_>) -> Result<Stamp, VerifyError> {
	let report = check(response, expected)?;
	match report.first_failure() {
		Some((Check::Imprint, _)) => Err(VerifyError::Imprint),
		Some((Check::Nonce, _)) => Err(VerifyError::Nonce),
		Some((_, why)) => Err(VerifyError::Untrusted(why)),
		None => Ok(Stamp {
			gen_time: report.gen_time,
			serial: report.serial,
			anchor: report.anchor.unwrap_or_default(),
		}),
	}
}

/// [`verify_expected`] without a policy requirement.
pub fn verify(
	response: &[u8],
	digest: &[u8; 32],
	nonce: Option<u64>,
	anchors: &[[u8; 32]],
) -> Result<Stamp, VerifyError> {
	verify_expected(
		response,
		&Expected {
			digest,
			nonce,
			anchors,
			policy: None,
		},
	)
}

/// Run every check on `response`. Only a response that is not a token at
/// all is an error; every other problem is a failed check in the report.
pub fn check(response: &[u8], expected: &Expected<'_>) -> Result<Report, TokenError> {
	let token = parse_response(response)?;
	let when = i64::try_from(token.tst.gen_time).unwrap_or(i64::MAX);
	let certificates: Vec<X509Certificate<'_>> = token
		.certificates
		.iter()
		.filter_map(|der| X509Certificate::from_der(der).ok().map(|(_, cert)| cert))
		.collect();
	let signer = find_signer(&token, &certificates);
	let chain = signer.map(|signer| chain_to_anchor(signer, &certificates, expected.anchors));
	let missing = Outcome::Failed("the signer's certificate is not in the token");
	let mut checks = Vec::with_capacity(Check::ALL.len());
	for kind in Check::ALL {
		let outcome = match (kind, signer, &chain) {
			(Check::Imprint, ..) => imprint(&token, expected.digest),
			(Check::Nonce, ..) => nonce(&token, expected.nonce),
			(Check::Policy, ..) => policy(&token, expected.policy),
			(_, None, _) => missing,
			(Check::Anchor, _, Some(Ok(_))) => Outcome::Passed,
			(Check::Anchor, _, Some(Err(why))) => Outcome::Failed(why),
			(Check::Anchor, ..) => missing,
			(Check::KeyUsage, Some(signer), _) => key_usage(signer),
			(Check::Validity, Some(signer), chain) => validity(signer, chain, when),
			(Check::SigningCertificate, Some(signer), _) => signing_certificate(&token, signer),
			(Check::Signature, Some(signer), _) => signature(&token, signer),
		};
		checks.push((kind, outcome));
	}
	let mut ders: Vec<Vec<u8>> = Vec::new();
	if let Some(signer) = signer {
		ders.push(signer.as_raw().to_vec());
	}
	for der in &token.certificates {
		if !ders.iter().any(|kept| kept == der) {
			ders.push(der.to_vec());
		}
	}
	Ok(Report {
		checks,
		gen_time: token.tst.gen_time,
		serial: to_hex(token.tst.serial),
		anchor: match &chain {
			Some(Ok((anchor, _))) => Some(to_hex(anchor)),
			_ => None,
		},
		certificates: ders,
	})
}

fn imprint(token: &Token<'_>, digest: &[u8; 32]) -> Outcome {
	if token.tst.hash_algorithm != oid::SHA256 {
		Outcome::Failed("the imprint is not SHA-256")
	} else if token.tst.hashed_message != digest {
		Outcome::Failed("the token stamps a different digest")
	} else {
		Outcome::Passed
	}
}

fn nonce(token: &Token<'_>, nonce: Option<u64>) -> Outcome {
	match nonce {
		None => Outcome::NotApplicable,
		Some(nonce) if token.tst.nonce == Some(unsigned_content(nonce).as_slice()) => {
			Outcome::Passed
		}
		Some(_) => Outcome::Failed("the token carries a different nonce"),
	}
}

fn policy(token: &Token<'_>, policy: Option<&[u8]>) -> Outcome {
	match policy {
		None => Outcome::NotApplicable,
		Some(policy) if token.tst.policy == policy => Outcome::Passed,
		Some(_) => Outcome::Failed("the token was issued under another policy"),
	}
}

fn digest_of(algorithm: &[u8], bytes: &[u8]) -> Option<Vec<u8>> {
	let algorithm = match algorithm {
		a if a == oid::SHA256 => &ring::digest::SHA256,
		a if a == oid::SHA384 => &ring::digest::SHA384,
		a if a == oid::SHA512 => &ring::digest::SHA512,
		a if a == oid::SHA1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
		_ => return None,
	};
	Some(ring::digest::digest(algorithm, bytes).as_ref().to_vec())
}

fn signing_certificate(token: &Token<'_>, signer: &X509Certificate<'_>) -> Outcome {
	match token.signer.certificate_hash {
		None => Outcome::Failed("no ESSCertID or ESSCertIDv2 in the signed attributes"),
		Some((algorithm, hash))
			if digest_of(algorithm, signer.as_raw()).as_deref() == Some(hash) =>
		{
			Outcome::Passed
		}
		Some(_) => Outcome::Failed("signingCertificate does not name the signer"),
	}
}

fn signature(token: &Token<'_>, signer: &X509Certificate<'_>) -> Outcome {
	if token.signer.content_type != Some(oid::TST_INFO) {
		return Outcome::Failed("the signed content type is not TSTInfo");
	}
	match digest_of(token.signer.digest_algorithm, token.tst_der) {
		None => return Outcome::Failed("unsupported digest algorithm"),
		Some(digest) if digest != token.signer.message_digest => {
			return Outcome::Failed("messageDigest does not match the TSTInfo");
		}
		Some(_) => {}
	}
	let mut signed = token.signer.signed_attributes.to_vec();
	signed[0] = tag::SET;
	let key = signer.public_key().raw;
	match cms_algorithm(
		token.signer.signature_algorithm,
		token.signer.digest_algorithm,
		key,
	) {
		Err(why) => Outcome::Failed(why),
		Ok(algorithm) if verify_with(algorithm, key, &signed, token.signer.signature) => {
			Outcome::Passed
		}
		Ok(_) => Outcome::Failed("bad signature"),
	}
}

fn find_signer<'b, 'a>(
	token: &Token<'a>,
	certificates: &'b [X509Certificate<'a>],
) -> Option<&'b X509Certificate<'a>> {
	certificates
		.iter()
		.find(|certificate| match token.signer.id {
			SignerId::IssuerSerial(issuer, serial) => {
				certificate.issuer().as_raw() == issuer && certificate.raw_serial() == serial
			}
			SignerId::KeyId(id) => key_identifier(certificate) == Some(id),
		})
}

fn key_identifier<'a>(certificate: &X509Certificate<'a>) -> Option<&'a [u8]> {
	use x509_parser::extensions::ParsedExtension;
	certificate
		.extensions()
		.iter()
		.find_map(|extension| match &extension.parsed_extension() {
			ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0),
			_ => None,
		})
}

/// (b): the only usage is timeStamping, and the extension is critical.
fn key_usage(signer: &X509Certificate<'_>) -> Outcome {
	let usage = match signer.extended_key_usage() {
		Err(_) => return Outcome::Failed("unreadable extended key usage"),
		Ok(None) => return Outcome::Failed("the signer has no extended key usage"),
		Ok(Some(usage)) => usage,
	};
	let value = usage.value;
	if !usage.critical || !value.time_stamping {
		return Outcome::Failed("the signer is not a critical timeStamping key");
	}
	let others = value.any
		|| value.server_auth
		|| value.client_auth
		|| value.code_signing
		|| value.email_protection
		|| value.ocsp_signing
		|| !value.other.is_empty();
	if others {
		return Outcome::Failed("the signer has usages besides timeStamping");
	}
	Outcome::Passed
}

/// (c): the signer and every certificate up to the anchor.
fn validity(
	signer: &X509Certificate<'_>,
	chain: &Option<ChainResult<'_, '_>>,
	when: i64,
) -> Outcome {
	let valid = |certificate: &X509Certificate<'_>| {
		let validity = certificate.validity();
		when >= validity.not_before.timestamp() && when <= validity.not_after.timestamp()
	};
	if !valid(signer) {
		return Outcome::Failed("the signer certificate was not valid at the stamped time");
	}
	match chain {
		Some(Ok((_, path))) if path.iter().all(|certificate| valid(certificate)) => Outcome::Passed,
		Some(Ok(_)) => Outcome::Failed("a chain certificate was not valid at the stamped time"),
		_ => Outcome::Failed("no chain to check"),
	}
}

type ChainResult<'b, 'a> = Result<([u8; 32], Vec<&'b X509Certificate<'a>>), &'static str>;

/// (a): walk issuers from `signer`, each verified as having signed the one
/// below, until a pinned key. Returns the anchor and the issuers walked.
fn chain_to_anchor<'b, 'a>(
	signer: &'b X509Certificate<'a>,
	certificates: &'b [X509Certificate<'a>],
	anchors: &[[u8; 32]],
) -> ChainResult<'b, 'a> {
	let mut current = signer;
	let mut path = Vec::new();
	for _ in 0..MAX_CHAIN {
		let key = sha256(current.public_key().raw);
		if anchors.contains(&key) {
			return Ok((key, path));
		}
		let Some(issuer) = certificates
			.iter()
			.filter(|candidate| candidate.subject().as_raw() == current.issuer().as_raw())
			.find(|candidate| signed_by(current, candidate))
		else {
			break;
		};
		if issuer.as_raw() == current.as_raw() {
			// Self-signed and not pinned: nothing further up.
			break;
		}
		path.push(issuer);
		current = issuer;
	}
	Err("the chain does not reach a pinned anchor")
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
