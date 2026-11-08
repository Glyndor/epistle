//! `dkim rotate --domain`: it refuses what the server's rotation of that
//! domain would refuse, and otherwise only queues a request in the domain's
//! key directory.

use super::*;
use crate::dkim::domain_rotate::{REQUEST_FILE, pending_request, state_dir};

const DAY: u64 = 86_400;

/// A configuration hosting `example.org` (a key of its own) and `other.net`
/// (a key of its own outside the `[dns]` zone), with `dns` as the `[dns]`
/// table.
fn config(dir: &std::path::Path, dns: &str) -> Config {
	let mut keys = Vec::new();
	for name in ["default", "org", "net"] {
		let (pem, _) = crate::dkim::generate_key().expect("key");
		let path = dir.join(format!("{name}.pem"));
		std::fs::write(&path, pem).expect("key file");
		keys.push(path);
	}
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {dir:?}\ndomains = ['example.org', 'other.net', 'shared.example.org']\n\
		 [dkim]\nselector = 's1'\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = 'example.org'\nselector = 'own1'\nkey_file = {:?}\n\
		 [[dkim.domain]]\nname = 'other.net'\nselector = 'own1'\nkey_file = {:?}\n{dns}",
		keys[0], keys[1], keys[2]
	))
	.expect("config")
}

/// A `[dns]` table for the `example.org` zone, with a token made at run time.
fn dns() -> String {
	format!(
		"[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken = '{}'\n",
		uuid::Uuid::new_v4().simple()
	)
}

fn run(config: &Config, name: &str, dry_run: bool, now: u64) -> (ExitCode, String, String) {
	let (mut out, mut err) = (Vec::new(), Vec::new());
	let code = rotate_domain(config, name, dry_run, now, false, &mut err, &mut out);
	(
		code,
		String::from_utf8(out).expect("utf-8"),
		String::from_utf8(err).expect("utf-8"),
	)
}

fn request_file(config: &Config, name: &str) -> std::path::PathBuf {
	state_dir(&config.data_dir, name)
		.expect("dir")
		.join(REQUEST_FILE)
}

#[test]
fn a_domain_with_its_own_key_in_the_zone_is_queued() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path(), &dns());
	let now = 20_000 * DAY;
	let (code, out, err) = run(&config, "Example.ORG", false, now);
	assert_eq!(code, ExitCode::SUCCESS, "{err}");
	for line in [
		"rotate own1 -> own20000",
		"publish TXT own20000._domainkey.example.org",
		"queued:",
	] {
		assert!(out.contains(line), "{line:?} in {out}");
	}
	assert!(pending_request(&config.data_dir, "example.org").is_some());
	assert!(
		!request_file(&config, "other.net").exists(),
		"only the named domain is asked to rotate"
	);
	assert!(
		!config
			.data_dir
			.join(crate::dkim::rotate::REQUEST_FILE)
			.exists(),
		"the [dkim] key is not asked to rotate"
	);
}

#[test]
fn a_dry_run_prints_the_plan_and_queues_nothing() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path(), &dns());
	let (code, out, _) = run(&config, "example.org", true, 20_000 * DAY);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(out.contains("dry run: nothing changed"), "{out}");
	assert!(!request_file(&config, "example.org").exists());
}

#[test]
fn a_domain_no_dns_entry_publishes_for_is_refused() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path(), &dns());
	let (code, out, err) = run(&config, "other.net", false, 20_000 * DAY);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(out.is_empty());
	assert!(
		err.contains("no [dns] entry can publish records at other.net"),
		"{err}"
	);
	assert!(!request_file(&config, "other.net").exists());
}

#[test]
fn without_dns_every_domain_is_refused() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path(), "");
	let (code, _, err) = run(&config, "example.org", false, 20_000 * DAY);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(err.contains("no [dns] entry can publish"), "{err}");
}

#[test]
fn a_domain_on_the_default_key_is_pointed_at_the_default_rotation() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path(), &dns());
	let (code, _, err) = run(&config, "shared.example.org", false, 20_000 * DAY);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(err.contains("signs with the [dkim] default"), "{err}");
}

#[test]
fn a_replaced_selector_inside_its_overlap_is_refused_with_its_date() {
	let dir = tempfile::tempdir().expect("dir");
	let config = config(dir.path(), &dns());
	let now = 20_000 * DAY;
	let key_dir = state_dir(&config.data_dir, "example.org").expect("dir");
	std::fs::create_dir_all(&key_dir).expect("mkdir");
	let (pem, _) = crate::dkim::generate_key().expect("key");
	std::fs::write(key_dir.join("own19990.pem"), pem).expect("key");
	let state = crate::dkim::rotate::RotationState {
		selector: "own19990".into(),
		key_file: key_dir.join("own19990.pem"),
		rotated_at: now - 10 * DAY,
		previous: Some(crate::dkim::rotate::Previous {
			selector: "own19900".into(),
			key_file: key_dir.join("own19900.pem"),
			retire_at: now + DAY,
			rsa: None,
		}),
		pending: None,
		rsa: None,
	};
	std::fs::write(
		key_dir.join(crate::dkim::domain_rotate::STATE_FILE),
		serde_json::to_vec(&state).expect("json"),
	)
	.expect("state");
	let (code, _, err) = run(&config, "example.org", false, now);
	assert_eq!(code, ExitCode::FAILURE);
	assert!(err.contains("own19900 is still published until"), "{err}");
	assert!(!request_file(&config, "example.org").exists());
	// Past its retirement the plan retires it first and rotates past both.
	let (code, out, err) = run(&config, "example.org", true, now + 2 * DAY);
	assert_eq!(code, ExitCode::SUCCESS, "{err}");
	assert!(out.contains("retire own19900 first"), "{out}");
	assert!(out.contains("rotate own19990 -> own20002"), "{out}");
}
