//! `epistle dkim show` with RSA dual signing: the RSA key in service, the
//! one retired with the previous selector and the one a rotation is
//! moving to, beside their ed25519 counterparts.

use super::*;
use crate::dkim::rotate::{Pending, Previous, RotationState, RsaKey, STATE_FILE};
use crate::dkim::test_support::KeyDns;
use std::collections::HashMap;

const DAY: u64 = 86_400;

/// A dual-signing configuration whose state names a rotated RSA key; the
/// RSA key is made in process at test time. `Err` says why it could not.
fn fixture() -> Result<(tempfile::TempDir, Config, String), String> {
	let (rsa_pem, rsa_value) =
		crate::dkim::generate_rsa_key(2048).map_err(|error| error.to_string())?;
	let dir = tempfile::tempdir().expect("dir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(dir.path().join("dkim-ed7.key"), pem).expect("key file");
	std::fs::write(dir.path().join("dkim-rsa7.key"), rsa_pem).expect("RSA key file");
	let state = RotationState {
		selector: "ed7".into(),
		key_file: "dkim-ed7.key".into(),
		rotated_at: 7 * DAY,
		previous: Some(Previous {
			selector: "ed1".into(),
			key_file: dir.path().join("dkim-ed1.key"),
			retire_at: 21 * DAY,
			rsa: Some(RsaKey {
				selector: "rsa1".into(),
				key_file: dir.path().join("dkim-rsa1.key"),
			}),
		}),
		pending: Some(Pending {
			selector: "ed100".into(),
			key_file: dir.path().join("dkim-ed100.key"),
			domains: vec!["example.org".into()],
			started_at: 100 * DAY,
			withdrawing: None,
			rsa: Some(RsaKey {
				selector: "rsa100".into(),
				key_file: dir.path().join("dkim-rsa100.key"),
			}),
		}),
		rsa: Some(RsaKey {
			selector: "rsa7".into(),
			key_file: "dkim-rsa7.key".into(),
		}),
	};
	std::fs::write(
		dir.path().join(STATE_FILE),
		serde_json::to_vec(&state).expect("json"),
	)
	.expect("state");
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n[dkim]\nselector = 'original'\nkey_file = '/nonexistent/original.key'\nrsa_selector = 'rsa-configured'\nrsa_key_file = '/nonexistent/rsa.key'\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'x'\n",
		dir.path()
	))
	.expect("config");
	Ok((dir, config, rsa_value))
}

#[test]
fn the_rotated_rsa_key_is_shown_with_its_previous_and_pending_ones() {
	let (dir, config, rsa_value) = match fixture() {
		Ok(fixture) => fixture,
		Err(reason) => {
			eprintln!(
				"skip: no RSA key could be generated ({reason}); dkim show was not exercised"
			);
			return;
		}
	};
	let records: HashMap<String, Vec<String>> =
		[("rsa7._domainkey.example.org".to_string(), vec![rsa_value])].into();
	let runtime = tokio::runtime::Runtime::new().expect("runtime");
	let view = runtime
		.block_on(build(&config, Some(&KeyDns(records))))
		.unwrap_or_else(|_| panic!("the view builds"));
	assert_eq!(view.rsa_selector.as_deref(), Some("rsa7"));
	assert_eq!(view.rsa_key_file, Some(dir.path().join("dkim-rsa7.key")));
	assert_eq!(view.rsa_source, Some("state"));
	let status = |name: &str| {
		view.records
			.iter()
			.find(|r| r.name == name)
			.map(|r| r.status)
			.unwrap_or_else(|| panic!("no record {name}"))
	};
	assert_eq!(status("rsa7._domainkey.example.org"), "ok");
	assert_eq!(status("rsa1._domainkey.example.org"), "missing");
	assert!(
		view.records.iter().all(|r| r.selector != "rsa-configured"),
		"the configured RSA selector is not the one in service"
	);

	let mut out = Vec::new();
	render(&view, false, &mut out);
	let text = String::from_utf8(out).expect("utf-8");
	for line in [
		"rsa selector: rsa7 (from state)",
		"previous: ed1 and rsa1 (retires at 1970-01-22T00:00:00Z)",
		"rotation to ed100 and rsa100 in progress since 1970-04-11T00:00:00Z; ed7 and rsa7 sign until DNS shows the new keys",
	] {
		assert!(text.contains(line), "dkim show prints {line:?}");
	}
	let mut out = Vec::new();
	render(&view, true, &mut out);
	let json: serde_json::Value = serde_json::from_slice(&out).expect("json");
	assert_eq!(json["rsa_selector"], "rsa7");
	assert_eq!(json["previous"]["rsa_selector"], "rsa1");
	assert_eq!(json["in_progress"]["rsa_selector"], "rsa100");
	assert!(!String::from_utf8_lossy(&out).contains("PRIVATE"));
}

#[test]
fn without_a_rotated_rsa_key_the_configured_one_is_shown() {
	let dir = tempfile::tempdir().expect("dir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let key = dir.path().join("original.key");
	std::fs::write(&key, pem).expect("key file");
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n[dkim]\nselector = 'original'\nkey_file = {key:?}\nrsa_selector = 'rsa-configured'\nrsa_key_file = '/nonexistent/rsa.key'\n",
		dir.path()
	))
	.expect("config");
	let runtime = tokio::runtime::Runtime::new().expect("runtime");
	let view = runtime
		.block_on(build(&config, None))
		.unwrap_or_else(|_| panic!("the view builds"));
	assert_eq!(view.rsa_selector.as_deref(), Some("rsa-configured"));
	assert_eq!(view.rsa_source, Some("config"));
}
