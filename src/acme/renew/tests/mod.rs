pub use super::*;

pub(super) mod base;
pub(super) mod expiry;
pub(super) mod placeholder;
pub(super) mod request;

/// The issuer the test certificates are signed by. A leaf has to be
/// signed by somebody other than itself: a self-issued certificate is
/// a placeholder nobody vouches for, and `needs_renewal` treats it as
/// due however far its expiry is.
pub(super) fn test_issuer() -> rcgen::Issuer<'static, rcgen::KeyPair> {
	let mut params = rcgen::CertificateParams::new(Vec::new()).expect("issuer parameters");
	params.distinguished_name.push(
		rcgen::DnType::CommonName,
		rcgen::DnValue::Utf8String("Epistle Test CA".to_string()),
	);
	let key = rcgen::KeyPair::generate().expect("issuer key");
	rcgen::Issuer::new(params, key)
}

/// A certificate an authority issued for `mail.example.org`, valid
/// until the given date.
pub(super) fn issued_certificate(year: i32, month: u8, day: u8) -> rcgen::Certificate {
	let mut params = rcgen::CertificateParams::new(vec!["mail.example.org".into()])
		.expect("certificate parameters");
	params.distinguished_name.push(
		rcgen::DnType::CommonName,
		rcgen::DnValue::Utf8String("mail.example.org".to_string()),
	);
	params.not_after = rcgen::date_time_ymd(year, month, day);
	let key = rcgen::KeyPair::generate().expect("key");
	params.signed_by(&key, &test_issuer()).expect("certificate")
}
