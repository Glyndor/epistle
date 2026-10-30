//! The placeholder an install carries before the authority answers.
//!
//! `init` used to write the self-signed pair at the ACME path so the
//! server had a certificate to serve. No authority issues such a
//! certificate: it is its own issuer, nobody vouches for it, and it
//! is valid until the year 4096. The renewal loop has to treat it as
//! due and replace it, or the first boot never places an order and the
//! host serves the placeholder forever.

use super::*;

/// A certificate that signed itself, the shape `init` used to write
/// at the ACME path.
fn self_issued_certificate() -> (rcgen::Certificate, rcgen::KeyPair) {
	let mut params = rcgen::CertificateParams::new(vec!["mail.example.org".into()])
		.expect("certificate parameters");
	params.distinguished_name.push(
		rcgen::DnType::CommonName,
		rcgen::DnValue::Utf8String("mail.example.org".to_string()),
	);
	let key = rcgen::KeyPair::generate().expect("key");
	(params.self_signed(&key).expect("certificate"), key)
}

/// A certificate nobody vouches for is due however far its expiry
/// is. Its expiry says nothing: the point of the certificate is that
/// it is not one an authority issued.
#[test]
fn a_self_issued_certificate_is_due_however_far_its_expiry_is() {
	let dir = tempfile::tempdir().expect("tempdir");
	fs::create_dir_all(dir.path().join("acme")).expect("ACME directory");
	let (certificate, key) = self_issued_certificate();
	fs::write(cert_path(dir.path()), certificate.pem()).expect("certificate file");
	fs::write(key_path(dir.path()), key.serialize_pem()).expect("key file");
	assert!(
		needs_renewal(dir.path(), 30, now_secs()),
		"a certificate that is its own issuer is a placeholder; the renewal loop must ask \
		 the authority for the real one instead of waiting for an expiry that never comes"
	);
}

/// The placeholder is due with no renewal window either: the operator
/// can set `renew_before_days = 0` and the first boot still has to
/// place the order.
#[test]
fn a_self_issued_certificate_is_due_without_a_renewal_window() {
	let dir = tempfile::tempdir().expect("tempdir");
	fs::create_dir_all(dir.path().join("acme")).expect("ACME directory");
	let (certificate, key) = self_issued_certificate();
	fs::write(cert_path(dir.path()), certificate.pem()).expect("certificate file");
	fs::write(key_path(dir.path()), key.serialize_pem()).expect("key file");
	assert!(
		needs_renewal(dir.path(), 0, now_secs()),
		"a placeholder is due even with no renewal window"
	);
}
