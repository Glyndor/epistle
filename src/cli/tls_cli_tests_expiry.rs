use super::*;

const EXPIRY: i64 = 1_798_761_599;
const NOW: u64 = (EXPIRY - 12 * 86_400) as u64;

fn certificate_view() -> TlsView {
	let dir = tempfile::tempdir().expect("dir");
	let mut params =
		rcgen::CertificateParams::new(vec!["mail.example.org".into()]).expect("params");
	params.not_after = x509_parser::time::ASN1Time::from_timestamp(EXPIRY)
		.expect("expiry")
		.to_datetime();
	let key = rcgen::KeyPair::generate().expect("key");
	let cert_path = dir.path().join("cert.pem");
	std::fs::write(&cert_path, params.self_signed(&key).expect("cert").pem()).expect("write cert");
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\n[tls]\ncert_file = {cert_path:?}\nkey_file = {:?}", dir.path(), dir.path().join("key.pem")
	)).expect("config");
	view(&config, NOW).expect("view")
}

#[test]
fn expiry_text_is_a_utc_date_with_days_left() {
	let view = certificate_view();
	let mut text = Vec::new();
	assert_eq!(render(&view, false, &mut text), ExitCode::SUCCESS);
	let text = String::from_utf8(text).expect("text");
	assert!(
		text.lines()
			.any(|line| line == "expires: 2026-12-31T23:59:59Z (12 days left)"),
		"tls show must print the expiry as an RFC 3339 UTC date"
	);
}

#[test]
fn expiry_json_adds_a_utc_date_and_preserves_epoch_and_days() {
	let view = certificate_view();
	let mut json = Vec::new();
	assert_eq!(render(&view, true, &mut json), ExitCode::SUCCESS);
	let json: serde_json::Value = serde_json::from_slice(&json).expect("json");
	assert_eq!(
		json["not_after_utc"], "2026-12-31T23:59:59Z",
		"tls show JSON must include the RFC 3339 UTC expiry"
	);
	assert_eq!(json["not_after"], EXPIRY);
	assert_eq!(json["days_left"], 12);
}
