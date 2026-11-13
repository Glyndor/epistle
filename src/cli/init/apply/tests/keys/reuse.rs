//! Apply unit tests: the self-signed certificate pair.
//!
//! Lives in a sibling because the original `src/cli/init/apply/tests/helpers/answers.rs` was at
//! the per-file line limit. These tests pin the "never regenerated"
//! rule for `cert.pem`/`key.pem` and confirm the pair is named in the
//! plan the operator sees before confirming.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use super::*;
use crate::cli::init::answers::Services;

#[cfg(unix)]
fn sha256_of(path: &std::path::Path) -> Option<Vec<u8>> {
	let bytes = std::fs::read(path).ok()?;
	Some(
		ring::digest::digest(&ring::digest::SHA256, &bytes)
			.as_ref()
			.to_vec(),
	)
}

#[cfg(not(unix))]
fn sha256_of(_path: &std::path::Path) -> Option<Vec<u8>> {
	None
}

pub(super) fn answers_minimal() -> Answers {
	Answers {
		mode: crate::cli::init::answers::Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: Some(Ipv4Addr::new(8, 8, 8, 8)),
		public_ipv6: Some(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
		image: Some("localhost/epistle:dev".to_string()),
		acme: None,
		first_account: None,
		resources: Default::default(),
	}
}

#[test]
fn plan_lists_the_self_signed_cert_step() {
	let answers = answers_minimal();
	let plan = plan(&answers).expect("plan");
	let cert_step = plan
		.steps
		.iter()
		.find(|s| matches!(s, PlanStep::SelfSignedCert { .. }))
		.expect("plan must list the self-signed cert step");
	let mut rendered = String::new();
	use std::fmt::Write;
	write!(&mut rendered, "{cert_step}").expect("render");
	assert!(
		rendered.contains("cert.pem") && rendered.contains("key.pem"),
		"plan step must name both halves of the pair"
	);
}

#[test]
fn apply_does_not_regenerate_the_self_signed_cert_pair() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(outcome.error.is_none());
	let cert = data_dir.join("keys/cert.pem");
	let key = data_dir.join("keys/key.pem");
	let cert_hash_before = sha256_of(&cert).expect("cert hash");
	let key_hash_before = sha256_of(&key).expect("key hash");
	assert!(
		outcome
			.report
			.steps
			.iter()
			.any(|s| matches!(s, ReportStep::Wrote(p) if p == &cert)),
		"first apply must write the cert: {:?}",
		outcome.report.steps
	);
	// Change every answer the operator can change and apply again.
	answers.hostname = "mail2.example.org".to_string();
	answers.domains = vec!["example.org".to_string(), "example.com".to_string()];
	answers.services = Services {
		antivirus: None,
		panel: None,
		panel_image: None,
		imap: false,
		submission: true,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
		database: false,
		certs: false,
	};
	answers.mode = crate::cli::init::answers::Mode::Manual;
	let outcome = apply(&answers);
	assert!(outcome.error.is_none());
	let cert_hash_after = sha256_of(&cert).expect("cert hash");
	let key_hash_after = sha256_of(&key).expect("key hash");
	assert_eq!(
		cert_hash_before, cert_hash_after,
		"self-signed cert must not be regenerated when answers change"
	);
	assert_eq!(
		key_hash_before, key_hash_after,
		"self-signed key must not be regenerated when answers change"
	);
	assert!(
		outcome
			.report
			.steps
			.iter()
			.all(|s| !matches!(s, ReportStep::Wrote(p) if p == &cert || p == &key)),
		"second apply must not rewrite the cert/key pair: {:?}",
		outcome.report.steps
	);
	assert!(
		outcome
			.report
			.steps
			.iter()
			.any(|s| matches!(s, ReportStep::Reused(p) if p == &cert))
			&& outcome
				.report
				.steps
				.iter()
				.any(|s| matches!(s, ReportStep::Reused(p) if p == &key)),
		"second apply must report the cert/key as reused: {:?}",
		outcome.report.steps
	);
}

#[test]
fn second_run_plan_says_reuse_and_config_identical() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"first apply failed: {:?}",
		outcome.error
	);
	drop(outcome);
	// The second-run plan must say reuse for every key/cert and
	// "identical, not touched" for the config.
	let plan = plan(&answers).expect("plan");
	let mut rendered = String::new();
	plan.write_to(&mut rendered).expect("render");
	assert!(
		rendered.contains("dkim ed25519 key: reuse"),
		"plan must say reuse for ed25519; rendered: {rendered}"
	);
	assert!(
		rendered.contains("dkim rsa key: reuse"),
		"plan must say reuse for rsa; rendered: {rendered}"
	);
	assert!(
		rendered.contains("storage key: reuse"),
		"plan must say reuse for storage; rendered: {rendered}"
	);
	assert!(
		rendered.contains("oauth private key: reuse"),
		"plan must say reuse for oauth private; rendered: {rendered}"
	);
	assert!(
		rendered.contains("oauth public key: reuse"),
		"plan must say reuse for oauth public; rendered: {rendered}"
	);
	assert!(
		rendered.contains("self-signed cert: reuse"),
		"plan must say reuse for the cert pair; rendered: {rendered}"
	);
	assert!(
		rendered.contains("config: identical, not touched"),
		"plan must say identical for the config; rendered: {rendered}"
	);
	assert!(
		!rendered.contains("generate "),
		"second-run plan must not mention generate for any key or cert; rendered: {rendered}"
	);
	assert!(
		!rendered.contains("data dir: create"),
		"second-run plan must not list the data dir as a create step; rendered: {rendered}"
	);
	assert!(
		!rendered.contains("config dir: create"),
		"second-run plan must not list the config dir as a create step; rendered: {rendered}"
	);
}
