//! Tests for `epistle dkim rotate`: it refuses what the server refuses and
//! otherwise only queues a request for the server.

use super::*;
use crate::dkim::rotate::{REQUEST_FILE, STATE_FILE, pending_request};

const DAY: u64 = 86_400;

fn write_key(dir: &std::path::Path) -> std::path::PathBuf {
	let (pem, _) = crate::dkim::generate_key().expect("key");
	let path = dir.join("original.key");
	std::fs::write(&path, pem).expect("key file");
	path
}

fn config_with(dir: &std::path::Path, domains: &str, dns: &str) -> Config {
	let key = write_key(dir);
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = {domains}\n[dkim]\nselector = 'original'\nkey_file = {key:?}\n{dns}",
		dir
	))
	.expect("config")
}

const DNS: &str = "[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = 'secret'\n";

fn refusal(config: &Config, now: u64) -> String {
	preflight(config, now).err().expect("must be refused")
}

#[test]
fn refuses_without_dns_exactly_as_the_server_stays_off() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_with(dir.path(), "['example.org']", "");
	assert_eq!(decide_dkim_rotation(&config), DkimRotationPlan::Off);
	assert!(refusal(&config, 5 * DAY).contains("[dns] is not configured"));
	let mut out = Vec::new();
	assert_eq!(
		rotate_now(&config, false, 5 * DAY, &mut out),
		ExitCode::FAILURE
	);
	assert!(
		!dir.path().join(REQUEST_FILE).exists(),
		"a refusal must not queue anything"
	);
}

#[test]
fn refuses_an_out_of_zone_signing_domain_like_the_server() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_with(dir.path(), "['example.org', 'other.net']", DNS);
	match decide_dkim_rotation(&config) {
		DkimRotationPlan::Run { out_of_zone, .. } => assert_eq!(out_of_zone, vec!["other.net"]),
		other => panic!("unexpected plan {other:?}"),
	}
	let reason = refusal(&config, 5 * DAY);
	assert!(
		reason.contains("other.net") && reason.contains("outside the [dns] zone"),
		"{reason}"
	);
	let mut out = Vec::new();
	assert_eq!(
		rotate_now(&config, false, 5 * DAY, &mut out),
		ExitCode::FAILURE
	);
	assert!(!dir.path().join(REQUEST_FILE).exists());
}

#[test]
fn refuses_a_provider_that_cannot_be_built() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_with(
		dir.path(),
		"['example.org']",
		"[dns]\nprovider = 'manual'\nzone = 'example.org'\n",
	);
	assert!(refusal(&config, 5 * DAY).contains("cannot be built"));
}

#[test]
fn refuses_an_invalid_state_file_and_a_same_day_repeat() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_with(dir.path(), "['example.org']", DNS);
	std::fs::write(dir.path().join(STATE_FILE), "not json").expect("state");
	assert!(refusal(&config, 5 * DAY).contains(STATE_FILE));

	let key = dir.path().join("original.key");
	std::fs::write(
		dir.path().join(STATE_FILE),
		format!(
			r#"{{"selector":"ed5","key_file":{key:?},"rotated_at":{},"previous":null}}"#,
			5 * DAY
		),
	)
	.expect("state");
	assert!(refusal(&config, 5 * DAY + 3600).contains("ed5 is already active"));
}

#[test]
fn dry_run_describes_the_rotation_and_writes_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_with(dir.path(), "['example.org']", DNS);
	let mut out = Vec::new();
	assert_eq!(
		rotate_now(&config, true, 5 * DAY, &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("rotate original -> ed5"), "{text}");
	assert!(
		text.contains("publish TXT ed5._domainkey.example.org"),
		"{text}"
	);
	assert!(text.contains("dry run: nothing changed"), "{text}");
	assert!(!dir.path().join(REQUEST_FILE).exists());
}

#[test]
fn rotate_queues_one_request_for_the_server() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config_with(dir.path(), "['example.org']", DNS);
	let mut out = Vec::new();
	assert_eq!(
		rotate_now(&config, false, 5 * DAY, &mut out),
		ExitCode::SUCCESS
	);
	assert!(String::from_utf8(out).expect("utf8").contains("queued"));
	assert_eq!(
		pending_request(dir.path()).expect("request").requested_at,
		5 * DAY
	);
	assert!(
		!dir.path().join(STATE_FILE).exists(),
		"the CLI must not write the state itself"
	);
	assert!(
		!dir.path().join("dkim-ed5.key").exists(),
		"the CLI must not write keys itself"
	);
}

#[test]
fn dry_run_with_dual_signing_names_both_keys() {
	let dir = tempfile::tempdir().expect("dir");
	let dual =
		format!("rsa_selector = 'rsa-configured'\nrsa_key_file = '/nonexistent/rsa.key'\n{DNS}");
	let config = config_with(dir.path(), "['example.org', 'sub.example.org']", &dual);
	let state = format!(
		r#"{{"selector":"ed3","key_file":"original.key","rotated_at":{},"previous":{{"selector":"ed1","key_file":"","retire_at":{},"rsa":{{"selector":"rsa1","key_file":""}}}},"rsa":{{"selector":"rsa3","key_file":"dkim-rsa3.key"}}}}"#,
		3 * DAY,
		4 * DAY
	);
	std::fs::write(dir.path().join(STATE_FILE), state).expect("state");
	let mut out = Vec::new();
	assert_eq!(
		rotate_now(&config, true, 5 * DAY, &mut out),
		ExitCode::SUCCESS
	);
	let text = String::from_utf8(out).expect("utf8");
	for line in [
		"rotate ed3 -> ed5",
		"rotate rsa3 -> rsa5",
		"publish TXT ed5._domainkey.example.org",
		"publish TXT rsa5._domainkey.example.org",
		"publish TXT rsa5._domainkey.sub.example.org",
		"retire ed1 and rsa1 now",
	] {
		assert!(text.contains(line), "the dry run prints {line:?}");
	}
}
