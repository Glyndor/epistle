//! Renewal depends on the usability of the complete ACME pair.

use super::*;

const NOW: u64 = 1_893_456_000; // 2030-01-01 UTC.

fn recent_pair(dir: &Path) {
	let (cert, key) = issued_certificate(2030, 10, 28);
	fs::create_dir_all(dir.join("acme")).expect("ACME directory");
	fs::write(cert_path(dir), cert.pem()).expect("certificate file");
	fs::write(key_path(dir), key.serialize_pem()).expect("key file");
}

#[test]
fn recent_issued_certificate_without_its_key_is_due() {
	let dir = tempfile::tempdir().expect("directory");
	recent_pair(dir.path());
	fs::remove_file(key_path(dir.path())).expect("remove key");
	assert!(needs_renewal(dir.path(), 30, NOW));
}

#[test]
fn recent_issued_certificate_with_another_certificates_key_is_due() {
	let dir = tempfile::tempdir().expect("directory");
	recent_pair(dir.path());
	let (_, other_key) = issued_certificate(2030, 10, 28);
	fs::write(key_path(dir.path()), other_key.serialize_pem()).expect("other key file");
	assert!(needs_renewal(dir.path(), 30, NOW));
}

#[test]
fn coherent_recent_pair_is_not_due() {
	let dir = tempfile::tempdir().expect("directory");
	recent_pair(dir.path());
	assert!(!needs_renewal(dir.path(), 30, NOW));
	assert!(!needs_renewal(dir.path(), 0, NOW));
}

#[test]
fn missing_certificate_with_a_key_is_due() {
	let dir = tempfile::tempdir().expect("directory");
	recent_pair(dir.path());
	fs::remove_file(cert_path(dir.path())).expect("remove certificate");
	assert!(needs_renewal(dir.path(), 30, NOW));
}

#[test]
fn unreadable_certificate_is_due_despite_a_recent_mtime() {
	let dir = tempfile::tempdir().expect("directory");
	recent_pair(dir.path());
	fs::remove_file(cert_path(dir.path())).expect("remove certificate");
	fs::create_dir(cert_path(dir.path())).expect("directory in place of certificate");
	assert!(needs_renewal(dir.path(), 30, NOW));
}

#[test]
fn malformed_certificate_is_due_without_waiting_for_mtime_expiry() {
	let dir = tempfile::tempdir().expect("directory");
	recent_pair(dir.path());
	fs::write(cert_path(dir.path()), b"invalid certificate").expect("certificate file");
	assert!(needs_renewal(dir.path(), 30, NOW));
}

#[test]
fn malformed_key_is_due() {
	let dir = tempfile::tempdir().expect("directory");
	recent_pair(dir.path());
	fs::write(key_path(dir.path()), b"invalid key").expect("key file");
	assert!(needs_renewal(dir.path(), 30, NOW));
}
