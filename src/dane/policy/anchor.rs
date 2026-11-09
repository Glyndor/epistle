//! Trust-anchor validation for the trust-anchor TLSA usages
//! (RFC 7672 section 3.1.2 and section 3.2.2).
//!
//! A DANE-TA (2) or PKIX-TA (0) record does not authenticate a peer by
//! itself: it names the trust anchor the peer's certificate chain has to end
//! at. The peer is authenticated only when the chain it presented validates
//! from the leaf up to that anchor, with that anchor as the only trust
//! anchor, and the leaf is valid for the name of the service.
//!
//! The anchor is the presented certificate the record matches, or, when the
//! peer did not present it, the certificate the record carries itself
//! (selector `0`, matching type `0`). A record that carries only a digest of
//! an anchor the peer did not present cannot be validated: a digest does not
//! rebuild the certificate, so such a record authenticates nothing.

use std::sync::Arc;

use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::ServerCertVerifier;

use crate::dane::cert::spki_of;
use crate::dane::tlsa::{MatchingType, Selector, TlsaRecord};

/// Whether the trust-anchor assertion of `record` authenticates the chain
/// the peer presented for `server_name` at `now`.
///
/// `leaf_der` is the server certificate and `chain_der` the rest of what the
/// peer presented, both as DER. The chain has to validate from the leaf up
/// to the anchor the record names, and the leaf has to be valid for
/// `server_name`.
pub fn authenticates(
	record: &TlsaRecord,
	leaf_der: &[u8],
	chain_der: &[&[u8]],
	server_name: &str,
	now: UnixTime,
) -> bool {
	let Some(anchor) = anchor_of(record, leaf_der, chain_der) else {
		return false;
	};
	// The anchor is the end of the path, not one of the issuers the peer
	// sent along the way.
	let intermediates: Vec<CertificateDer<'_>> = chain_der
		.iter()
		.map(|cert| CertificateDer::from(*cert))
		.filter(|cert| cert.as_ref() != anchor.as_slice())
		.collect();
	verifies_to_anchor(leaf_der, &intermediates, &anchor, server_name, now)
}

/// The trust anchor certificate the record names.
///
/// The anchor is the presented certificate the record matches. A record that
/// carries the whole certificate (selector `0`, matching type `0`) names an
/// anchor the peer need not have presented: the certificate in the record is
/// then the anchor. Any other record that matches nothing the peer presented
/// names an anchor that cannot be rebuilt, and authenticates nothing.
fn anchor_of(record: &TlsaRecord, leaf_der: &[u8], chain_der: &[&[u8]]) -> Option<Vec<u8>> {
	for cert in std::iter::once(leaf_der).chain(chain_der.iter().copied()) {
		if matches_cert(record, cert) {
			return Some(cert.to_vec());
		}
	}
	if record.selector == Selector::FullCert && record.matching_type == MatchingType::Full {
		return Some(record.association.clone());
	}
	None
}

/// Whether the record matches the certificate: the whole certificate for
/// selector `0`, its public key for selector `1`.
fn matches_cert(record: &TlsaRecord, cert_der: &[u8]) -> bool {
	let spki = match record.selector {
		Selector::FullCert => Vec::new(),
		Selector::Spki => spki_of(cert_der).unwrap_or_default(),
	};
	record.matches_cert(cert_der, &spki)
}

/// Whether `leaf_der` chains to `anchor_der` and is valid for `server_name`.
///
/// The anchor is the only trust anchor of the validation: the public PKIX
/// roots are not consulted. Signatures, validity periods and the name of the
/// leaf are checked; the name is matched against the DNS-IDs of the leaf
/// (RFC 7672 section 3.2.3).
fn verifies_to_anchor(
	leaf_der: &[u8],
	intermediates: &[CertificateDer<'_>],
	anchor_der: &[u8],
	server_name: &str,
	now: UnixTime,
) -> bool {
	let mut roots = RootCertStore::empty();
	if roots.add(CertificateDer::from(anchor_der)).is_err() {
		return false;
	}
	let Some(verifier) = verifier(roots) else {
		return false;
	};
	let Ok(name) = ServerName::try_from(server_name.to_string()) else {
		return false;
	};
	verifier
		.verify_server_cert(
			&CertificateDer::from(leaf_der),
			intermediates,
			&name,
			&[],
			now,
		)
		.is_ok()
}

/// The verifier that checks the chain against `roots`.
///
/// The provider is the one the process runs with, as the TLS stack does; the
/// ring provider is the fallback for a process that installed none.
fn verifier(roots: RootCertStore) -> Option<Arc<WebPkiServerVerifier>> {
	let provider = tokio_rustls::rustls::crypto::CryptoProvider::get_default()
		.cloned()
		.unwrap_or_else(|| Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()));
	WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
		.build()
		.ok()
}
