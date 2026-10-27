//! Tests for `epistle dkim show`.

use super::*;
use crate::dkim::test_support::KeyDns;
use std::collections::HashMap;

const DAY: u64 = 86_400;

struct Fixture {
	dir: tempfile::TempDir,
	config: Config,
	value: String,
}

fn fixture(dns_section: bool) -> Fixture {
	let dir = tempfile::tempdir().expect("dir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let key = dir.path().join("original.key");
	std::fs::write(&key, pem).expect("key file");
	let value = Signer::load("original", &key)
		.expect("signer")
		.dns_record_value();
	let dns = if dns_section {
		"[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'x'\n"
	} else {
		""
	};
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org', 'example.net']\n[dkim]\nselector = 'original'\nkey_file = {key:?}\nrsa_selector = 'rsa1'\n{dns}",
		dir.path()
	))
	.expect("config");
	Fixture { dir, config, value }
}

fn view_with(f: &Fixture, records: &[(&str, &str)]) -> DkimView {
	let map: HashMap<String, Vec<String>> = records
		.iter()
		.map(|(name, value)| ((*name).to_string(), vec![(*value).to_string()]))
		.collect();
	let runtime = tokio::runtime::Runtime::new().expect("runtime");
	runtime
		.block_on(build(&f.config, Some(&KeyDns(map))))
		.expect("view")
}

fn status<'a>(view: &'a DkimView, name: &str) -> &'a str {
	view.records
		.iter()
		.find(|r| r.name == name)
		.unwrap_or_else(|| panic!("no record {name}"))
		.status
}

#[test]
fn published_records_are_compared_with_the_key_in_service() {
	let f = fixture(true);
	let other = {
		let (pem, _) = crate::dkim::generate_key().expect("key");
		let path = f.dir.path().join("other.key");
		std::fs::write(&path, pem).expect("key");
		Signer::load("original", &path)
			.expect("signer")
			.dns_record_value()
	};
	let split = f.value.replacen("p=", "p= ", 1); // resolvers may split the string
	let view = view_with(
		&f,
		&[
			("original._domainkey.example.org", &split),
			("original._domainkey.example.net", &other),
		],
	);
	assert_eq!(status(&view, "original._domainkey.example.org"), "ok");
	assert_eq!(status(&view, "original._domainkey.example.net"), "differs");
	assert_eq!(view.records.len(), 2, "one record per signing domain");
}

#[test]
fn an_unpublished_key_is_reported_missing() {
	let f = fixture(true);
	let view = view_with(&f, &[("original._domainkey.example.org", &f.value)]);
	assert_eq!(status(&view, "original._domainkey.example.org"), "ok");
	assert_eq!(status(&view, "original._domainkey.example.net"), "missing");
}

#[test]
fn rotation_state_drives_selector_previous_and_next_due() {
	let f = fixture(true);
	let state = crate::dkim::rotate::RotationState {
		selector: "ed7".into(),
		key_file: "original.key".into(),
		rotated_at: 7 * DAY,
		previous: Some(crate::dkim::rotate::Previous {
			selector: "ed1".into(),
			key_file: std::path::PathBuf::new(),
			retire_at: 21 * DAY,
			rsa: None,
		}),
		pending: None,
		rsa: None,
	};
	std::fs::write(
		f.dir.path().join("dkim-rotation.json"),
		serde_json::to_vec(&state).unwrap(),
	)
	.expect("state");
	crate::dkim::rotate::request_rotation(f.dir.path(), 9 * DAY).expect("request");

	let view = view_with(&f, &[]);

	assert_eq!(view.selector, "ed7");
	assert_eq!(view.source, "state");
	assert_eq!(view.key_file, f.dir.path().join("original.key"));
	assert_eq!(view.rotated_at, Some(7 * DAY));
	assert_eq!(view.next_rotation_due, Some(7 * DAY + 90 * DAY));
	assert_eq!(
		view.previous
			.as_ref()
			.map(|p| (p.selector.as_str(), p.retire_at)),
		Some(("ed1", 21 * DAY))
	);
	assert_eq!(view.rotation_requested_at, Some(9 * DAY));
	assert!(
		view.records
			.iter()
			.any(|r| r.name == "ed1._domainkey.example.org")
	);
}

#[test]
fn without_dns_section_there_is_no_scheduled_rotation() {
	let f = fixture(false);
	let key = f.dir.path().join("original.key");
	std::fs::write(
		f.dir.path().join("dkim-rotation.json"),
		format!(
			r#"{{"selector":"ed3","key_file":{key:?},"rotated_at":{},"previous":null}}"#,
			3 * DAY
		),
	)
	.expect("state");
	let view = view_with(&f, &[]);
	assert_eq!(view.source, "state");
	assert!(!view.automatic_rotation);
	assert_eq!(view.next_rotation_due, None);
	let mut out = Vec::new();
	render(&view, false, &mut out);
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		text.contains("next rotation: never ([dns] is not configured)"),
		"{text}"
	);
}

#[test]
fn invalid_state_is_an_error_not_a_guess() {
	let f = fixture(true);
	std::fs::write(f.dir.path().join("dkim-rotation.json"), "oops").expect("state");
	let runtime = tokio::runtime::Runtime::new().expect("runtime");
	let error = runtime
		.block_on(build(&f.config, None))
		.expect_err("must fail");
	assert!(error.contains("dkim-rotation.json"), "{error}");
}

#[test]
fn json_output_carries_the_documented_fields() {
	let f = fixture(true);
	let view = view_with(&f, &[]);
	let mut out = Vec::new();
	assert_eq!(render(&view, true, &mut out), ExitCode::SUCCESS);
	let json: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(json["selector"], "original");
	assert_eq!(json["algorithm"], "ed25519");
	assert!(
		json.get("rsa_selector").is_some(),
		"the field is present, null without dual signing"
	);
	assert!(json["records"].is_array());
	assert!(!String::from_utf8_lossy(&out).contains("PRIVATE"));
}

#[test]
fn a_rotation_in_progress_is_shown_beside_the_key_that_signs() {
	let f = fixture(true);
	let state = rotate::RotationState {
		selector: "original".into(),
		key_file: f.dir.path().join("original.key"),
		rotated_at: DAY,
		previous: None,
		pending: Some(rotate::Pending {
			selector: "ed100".into(),
			key_file: f.dir.path().join("dkim-ed100.key"),
			domains: vec!["example.org".into()],
			started_at: 100 * DAY,
			withdrawing: None,
			rsa: None,
		}),
		rsa: None,
	};
	let path = f.dir.path().join(rotate::STATE_FILE);
	std::fs::write(&path, serde_json::to_vec(&state).expect("json")).expect("state");
	let text = |view: &DkimView| {
		let mut out = Vec::new();
		render(view, false, &mut out);
		String::from_utf8(out).expect("utf-8")
	};
	let view = view_with(&f, &[]);
	assert_eq!(
		view.selector, "original",
		"the committed key is the one shown as signing"
	);
	assert!(
		text(&view).contains("rotation to ed100 in progress since 8640000; original signs"),
		"{}",
		text(&view)
	);

	let withdrawing = rotate::RotationState {
		pending: state.pending.clone().map(|p| rotate::Pending {
			withdrawing: Some("ed100._domainkey.example.org does not show the new key".into()),
			..p
		}),
		..state
	};
	std::fs::write(&path, serde_json::to_vec(&withdrawing).expect("json")).expect("state");
	assert!(
		text(&view_with(&f, &[]))
			.contains("rotation to ed100 is being withdrawn: ed100._domainkey"),
		"{}",
		text(&view_with(&f, &[]))
	);
}
