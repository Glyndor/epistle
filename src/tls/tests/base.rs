use super::*;
use std::path::PathBuf;

fn self_signed_pem(domain: &str) -> (String, String) {
	let c = rcgen::generate_simple_self_signed(vec![domain.to_string()]).expect("cert");
	(c.cert.pem(), c.signing_key.serialize_pem())
}

#[test]
fn acceptor_from_pem_builds_and_reloads() {
	let (cert1, key1) = self_signed_pem("a.example");
	let a1 = acceptor_from_pem(cert1.as_bytes(), key1.as_bytes()).expect("acceptor 1");
	let handle = ReloadableAcceptor::new(a1);
	let _ = handle.current(); // smoke: current acceptor available

	let (cert2, key2) = self_signed_pem("b.example");
	let a2 = acceptor_from_pem(cert2.as_bytes(), key2.as_bytes()).expect("acceptor 2");
	handle.reload(a2);
	let _ = handle.current(); // smoke: still available after reload
}

#[test]
fn acceptor_from_pem_rejects_missing_material() {
	assert!(acceptor_from_pem(b"", b"").is_err());
}

#[test]
fn identity_from_cert_reads_email_san() {
	let mut params = rcgen::CertificateParams::new(vec![]).expect("params");
	params.subject_alt_names.push(rcgen::SanType::Rfc822Name(
		"alice@example.org".try_into().expect("ia5"),
	));
	let key = rcgen::KeyPair::generate().expect("key");
	let cert = params.self_signed(&key).expect("self-signed");
	assert_eq!(
		identity_from_cert(cert.der().as_ref()),
		Some("alice@example.org".to_string())
	);
}

#[test]
fn identity_from_cert_none_without_email_san() {
	// A DNS-only certificate carries no rfc822Name SAN.
	let certified =
		rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()]).expect("cert");
	assert_eq!(identity_from_cert(certified.cert.der().as_ref()), None);
}

#[test]
fn identity_from_cert_rejects_garbage() {
	assert_eq!(identity_from_cert(b"not a certificate"), None);
}

/// Write a self-signed certificate + key pair into `dir`.
pub(crate) fn write_self_signed(dir: &Path) -> (PathBuf, PathBuf) {
	let certified = rcgen::generate_simple_self_signed(vec!["mail.example.org".to_string()])
		.expect("generate certificate");
	let cert_path = dir.join("cert.pem");
	let key_path = dir.join("key.pem");
	std::fs::write(&cert_path, certified.cert.pem()).expect("write cert");
	std::fs::write(&key_path, certified.signing_key.serialize_pem()).expect("write key");
	(cert_path, key_path)
}

fn tls_config(cert_file: PathBuf, key_file: PathBuf) -> Tls {
	let toml = format!(
		"cert_file = \"{}\"\nkey_file = \"{}\"\n",
		cert_file.display(),
		key_file.display()
	);
	toml::from_str(&toml).expect("tls config")
}

#[test]
fn builds_acceptor_from_valid_material() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (cert, key) = write_self_signed(dir.path());
	assert!(acceptor(&tls_config(cert, key)).is_ok());
}

#[test]
fn fails_on_missing_cert_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (_, key) = write_self_signed(dir.path());
	let result = acceptor(&tls_config(dir.path().join("missing.pem"), key));
	assert!(matches!(result, Err(TlsError::Read { .. })));
}

#[test]
fn fails_on_missing_key_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (cert, _) = write_self_signed(dir.path());
	let result = acceptor(&tls_config(cert, dir.path().join("missing.pem")));
	assert!(matches!(result, Err(TlsError::Read { .. })));
}

#[test]
fn fails_on_empty_cert_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (_, key) = write_self_signed(dir.path());
	let empty = dir.path().join("empty.pem");
	std::fs::write(&empty, b"").expect("write empty");
	let result = acceptor(&tls_config(empty, key));
	assert!(matches!(result, Err(TlsError::NoCertificates(_))));
}

#[test]
fn fails_on_key_without_key_material() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (cert, _) = write_self_signed(dir.path());
	let bogus = dir.path().join("bogus.pem");
	std::fs::write(&bogus, b"not a key").expect("write bogus");
	let result = acceptor(&tls_config(cert, bogus));
	assert!(matches!(result, Err(TlsError::NoPrivateKey(_))));
}

#[test]
fn fails_on_mismatched_cert_and_key() {
	let dir = tempfile::tempdir().expect("tempdir");
	let (cert, _) = write_self_signed(dir.path());
	let other = tempfile::tempdir().expect("tempdir");
	let (_, foreign_key) = write_self_signed(other.path());
	// A key from a different certificate must be rejected.
	let result = acceptor(&tls_config(cert, foreign_key));
	assert!(matches!(result, Err(TlsError::Invalid(_))));
}
