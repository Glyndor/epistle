use super::*;

const NOW: u64 = 1_893_456_000; // 2030-01-01 UTC.

fn certificate_at(dir: &Path, expiry_day: u8, modified: u64) {
	let mut params = rcgen::CertificateParams::new(vec!["mail.example.org".into()])
		.expect("certificate parameters");
	params.not_after = rcgen::date_time_ymd(2030, 1, expiry_day);
	let key = rcgen::KeyPair::generate().expect("key");
	let cert = params.self_signed(&key).expect("certificate");
	fs::create_dir_all(dir.join("acme")).expect("ACME directory");
	let path = cert_path(dir);
	fs::write(&path, cert.pem()).expect("certificate file");
	fs::File::options()
		.write(true)
		.open(path)
		.expect("open certificate")
		.set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(modified)))
		.expect("certificate mtime");
}

#[test]
fn fresh_mtime_with_five_days_until_not_after_is_due() {
	let dir = tempfile::tempdir().expect("directory");
	certificate_at(dir.path(), 6, NOW);
	assert!(
		needs_renewal(dir.path(), 30, NOW),
		"certificate expiring in five days must renew despite fresh mtime"
	);
}

#[test]
fn not_after_controls_the_exact_renewal_boundary() {
	let dir = tempfile::tempdir().expect("directory");
	certificate_at(dir.path(), 31, NOW);
	assert!(
		!needs_renewal(dir.path(), 30, NOW - 1),
		"certificate must remain current until its renewal window opens"
	);
	assert!(
		needs_renewal(dir.path(), 30, NOW),
		"certificate must renew at the exact notAfter renewal boundary"
	);
}

#[test]
fn old_mtime_does_not_renew_a_certificate_outside_its_window() {
	let dir = tempfile::tempdir().expect("directory");
	certificate_at(dir.path(), 31, NOW - 100 * 86_400);
	assert!(
		!needs_renewal(dir.path(), 5, NOW),
		"certificate outside its renewal window must ignore old mtime"
	);
}
