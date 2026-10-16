//! Tests for `epistle tls show` and `epistle tls renew`.

use super::*;
use crate::acme::renew_request::{last_error, pending_request};

/// 2030-01-01 UTC.
const NOW: u64 = 1_893_456_000;

fn write_cert(cert: &std::path::Path, key: &std::path::Path, san: &str, expiry_day: u8) {
	let mut params = rcgen::CertificateParams::new(vec![san.into()]).expect("params");
	params.not_after = rcgen::date_time_ymd(2030, 1, expiry_day);
	let pair = rcgen::KeyPair::generate().expect("key");
	std::fs::write(cert, params.self_signed(&pair).expect("cert").pem()).expect("cert file");
	std::fs::write(key, pair.serialize_pem()).expect("key file");
}

fn config_in(dir: &std::path::Path, acme: bool) -> Config {
	write_cert(
		&dir.join("static.pem"),
		&dir.join("static.key"),
		"static.example.org",
		21,
	);
	let acme_section = if acme {
		"[acme]\ndirectory_url = 'https://acme.invalid/directory'\ndomains = ['mail.example.org']\n"
	} else {
		""
	};
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\n[tls]\ncert_file = {:?}\nkey_file = {:?}\n{acme_section}",
		dir.join("static.pem"),
		dir.join("static.key"),
	))
	.expect("config")
}

#[test]
fn show_reports_the_static_certificate() {
	let dir = tempfile::tempdir().expect("dir");
	let view = view(&config_in(dir.path(), false), NOW).expect("view");
	assert_eq!(view.source, "static");
	assert_eq!(view.sans, vec!["static.example.org"]);
	assert_eq!(view.days_left, 20);
	assert_eq!(view.cert_file, dir.path().join("static.pem"));
}

#[test]
fn show_reports_the_acme_certificate_the_server_presents() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_in(dir.path(), true);
	std::fs::create_dir(dir.path().join("acme")).expect("acme dir");
	write_cert(
		&dir.path().join("acme/cert.pem"),
		&dir.path().join("acme/key.pem"),
		"mail.example.org",
		31,
	);
	let view = view(&config, NOW).expect("view");
	assert_eq!(
		view.source, "acme",
		"must agree with what serve and probe use"
	);
	assert_eq!(view.sans, vec!["mail.example.org"]);
	assert_eq!(view.days_left, 30);
}

#[test]
fn show_prints_text_and_json() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_in(dir.path(), false);
	let mut text = Vec::new();
	assert_eq!(
		run(&config, TlsCli::Show { json: false }, false, &mut text),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(text).expect("utf8");
	assert!(
		text.contains("source: static") && text.contains("names: static.example.org"),
		"{text}"
	);
	let mut json = Vec::new();
	assert_eq!(
		run(&config, TlsCli::Show { json: true }, false, &mut json),
		ExitCode::SUCCESS
	);
	let json: serde_json::Value = serde_json::from_slice(&json).expect("json");
	assert_eq!(json["source"], "static");
	assert!(json["not_after"].as_i64().unwrap() > 0 && json["issuer"].is_string());
}

#[test]
fn renew_refuses_without_acme_or_without_tls() {
	let dir = tempfile::tempdir().expect("dir");
	let no_acme = config_in(dir.path(), false);
	let mut out = Vec::new();
	assert_eq!(
		renew(&no_acme, true, NOW, false, &mut out),
		ExitCode::FAILURE
	);
	assert!(pending_request(dir.path()).is_none());

	let mut no_tls = config_in(dir.path(), true);
	no_tls.tls = None;
	assert_eq!(
		renew(&no_tls, true, NOW, false, &mut out),
		ExitCode::FAILURE
	);
	assert!(
		pending_request(dir.path()).is_none(),
		"refusals must not queue anything"
	);
}

#[test]
fn renew_without_force_waits_for_the_window() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_in(dir.path(), true);
	std::fs::create_dir(dir.path().join("acme")).expect("acme dir");
	write_cert(
		&dir.path().join("acme/cert.pem"),
		&dir.path().join("acme/key.pem"),
		"mail.example.org",
		31,
	);
	// The certificate expires 30 days after NOW; a hundred days earlier it is far
	// outside the default 30 day renewal window.
	let mut out = Vec::new();
	let early = NOW - 100 * 86_400;
	assert_eq!(
		renew(&config, false, early, false, &mut out),
		ExitCode::SUCCESS
	);
	assert!(String::from_utf8(out).expect("utf8").starts_with("not due"));
	assert!(
		pending_request(dir.path()).is_none(),
		"nothing may be queued while not due"
	);
}

#[test]
fn renew_force_queues_a_forced_request() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_in(dir.path(), true);
	std::fs::create_dir(dir.path().join("acme")).expect("acme dir");
	write_cert(
		&dir.path().join("acme/cert.pem"),
		&dir.path().join("acme/key.pem"),
		"mail.example.org",
		31,
	);
	let mut out = Vec::new();
	assert_eq!(
		renew(&config, true, NOW, false, &mut out),
		ExitCode::SUCCESS
	);
	assert!(String::from_utf8(out).expect("utf8").contains("queued"));
	let request = pending_request(dir.path()).expect("request");
	assert!(request.force);
	assert_eq!(request.requested_at, NOW);
	assert!(last_error(dir.path()).is_none());
}

#[test]
fn renew_inside_the_window_queues_without_force() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_in(dir.path(), true);
	std::fs::create_dir(dir.path().join("acme")).expect("acme dir");
	write_cert(
		&dir.path().join("acme/cert.pem"),
		&dir.path().join("acme/key.pem"),
		"mail.example.org",
		10,
	);
	let mut out = Vec::new();
	assert_eq!(
		renew(&config, false, NOW, false, &mut out),
		ExitCode::SUCCESS
	);
	let request = pending_request(dir.path()).expect("request");
	assert!(!request.force, "a due certificate does not need force");
}

fn acme_dir_with_cert(expiry_day: u8) -> (tempfile::TempDir, Config) {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_in(dir.path(), true);
	std::fs::create_dir(dir.path().join("acme")).expect("acme dir");
	write_cert(
		&dir.path().join("acme/cert.pem"),
		&dir.path().join("acme/key.pem"),
		"mail.example.org",
		expiry_day,
	);
	(dir, config)
}

fn renew_json(config: &Config, force: bool, now: u64) -> (ExitCode, serde_json::Value) {
	let mut out = Vec::new();
	let code = renew(config, force, now, true, &mut out);
	let text = String::from_utf8(out).expect("utf8");
	assert_eq!(text.lines().count(), 1, "not one line of JSON: {text}");
	(code, serde_json::from_str(&text).expect("json"))
}

#[test]
fn renew_json_says_unchanged_while_the_certificate_is_not_due() {
	let (dir, config) = acme_dir_with_cert(31);
	assert_eq!(
		renew_json(&config, false, NOW - 100 * 86_400),
		(
			ExitCode::SUCCESS,
			serde_json::json!({
				"result": "unchanged", "action": "renew", "force": false, "renew_before_days": 30,
			})
		)
	);
	assert!(pending_request(dir.path()).is_none());
}

#[test]
fn renew_json_says_queued_when_it_wrote_the_request() {
	let (dir, config) = acme_dir_with_cert(31);
	assert_eq!(
		renew_json(&config, true, NOW),
		(
			ExitCode::SUCCESS,
			serde_json::json!({
				"result": "queued", "action": "renew", "force": true, "renew_before_days": 30,
			})
		)
	);
	assert!(pending_request(dir.path()).is_some_and(|request| request.force));
}
