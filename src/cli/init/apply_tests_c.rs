//! Apply unit tests: report rendering, ApplyError Display, and the
//! no-parent error. Lives in a sibling because the original
//! `apply_tests.rs` and `apply_tests_b.rs` are at the per-file line
//! limit. These tests pin the operator-visible strings that drive
//! the stderr output during a failed or partial run.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::apply_config;
use super::*;
use crate::cli::init::answers::{DnsAnswers, Mode, Services};

fn answers_minimal() -> Answers {
	Answers {
		mode: Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: Some(Ipv4Addr::new(8, 8, 8, 8)),
		public_ipv6: Some(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
	}
}

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

#[test]
fn sha256_of_is_stable() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("f.txt");
	std::fs::write(&path, b"hello").expect("write");
	let a = sha256_of(&path).expect("hash");
	let b = sha256_of(&path).expect("hash");
	assert_eq!(a, b);
}

#[test]
fn report_renders_every_step_kind_with_a_distinct_label() {
	// The operator reads the report top-to-bottom. Each variant must
	// show up with a label that says what kind of step it was, so a
	// change that drops or merges two labels would leave the operator
	// guessing which line is which.
	let mut report = Report::default();
	let s1 = std::path::PathBuf::from("/var/lib/epistle/keys/s1.pem");
	let storage = std::path::PathBuf::from("/var/lib/epistle/keys/storage.key");
	let config_path = std::path::PathBuf::from("/etc/epistle/mail.toml");
	let data_dir = std::path::PathBuf::from("/var/lib/epistle");
	report.steps.push(ReportStep::Reused(s1.clone()));
	report.steps.push(ReportStep::Wrote(storage.clone()));
	report.steps.push(ReportStep::Updated(config_path.clone()));
	report
		.steps
		.push(ReportStep::ConfigIdentical(config_path.clone()));
	report.steps.push(ReportStep::CreatedDir(data_dir.clone()));
	report.steps.push(ReportStep::Skipped {
		name: "dkim rsa key".to_string(),
		reason: "openssl not on PATH".to_string(),
	});
	let mut buf = Vec::new();
	report.write_to(&mut buf).expect("render");
	let rendered = String::from_utf8_lossy(&buf).into_owned();
	assert!(
		rendered.contains("reused:"),
		"reused label missing: {rendered}"
	);
	assert!(
		rendered.contains("wrote:"),
		"wrote label missing: {rendered}"
	);
	assert!(
		rendered.contains("updated:"),
		"updated label missing: {rendered}"
	);
	assert!(
		rendered.contains("config identical:"),
		"config identical label missing: {rendered}"
	);
	assert!(
		rendered.contains("created dir:"),
		"created dir label missing: {rendered}"
	);
	assert!(
		rendered.contains("skipped:") && rendered.contains("dkim rsa key"),
		"skipped label missing: {rendered}"
	);
}

#[test]
fn apply_error_messages_name_the_path_and_the_failure() {
	// Every ApplyError variant renders a message an operator can act
	// on. A change that drops the file path or the operation name
	// would leave the operator guessing which file to look at.
	let keys_dir = ApplyError::KeysDir(
		std::path::PathBuf::from("/var/lib/epistle/keys"),
		std::io::Error::other("permission denied"),
	);
	let keys_msg = format!("{keys_dir}");
	assert!(
		keys_msg.contains("/var/lib/epistle/keys"),
		"KeysDir display must name the path: {keys_msg}"
	);
	assert!(
		keys_msg.contains("permission denied"),
		"KeysDir display must surface the underlying error: {keys_msg}"
	);

	let encode = ApplyError::ConfigEncode("invalid TOML".to_string());
	assert!(
		format!("{encode}").contains("encode"),
		"ConfigEncode display must name the failure"
	);

	let invalid = ApplyError::ConfigInvalid("missing listener".to_string());
	assert!(
		format!("{invalid}").contains("invalid"),
		"ConfigInvalid display must name the failure"
	);

	let read = ApplyError::ConfigRead(
		std::path::PathBuf::from("/etc/epistle/mail.toml"),
		std::io::Error::other("not a file"),
	);
	let read_msg = format!("{read}");
	assert!(
		read_msg.contains("read"),
		"ConfigRead display must name the operation: {read_msg}"
	);

	let write = ApplyError::ConfigWrite(
		std::path::PathBuf::from("/etc/epistle/mail.toml"),
		std::io::Error::other("disk full"),
	);
	let write_msg = format!("{write}");
	assert!(
		write_msg.contains("write"),
		"ConfigWrite display must name the operation: {write_msg}"
	);

	let dir_err = ApplyError::ConfigDir(
		std::path::PathBuf::from("/etc/epistle"),
		std::io::Error::other("mkdir failed"),
	);
	let dir_msg = format!("{dir_err}");
	assert!(
		dir_msg.contains("/etc/epistle"),
		"ConfigDir display must name the path: {dir_msg}"
	);
}

#[test]
fn apply_fails_when_config_path_has_no_parent() {
	// A config_path like \"/\" has no parent directory; the apply
	// phase must reject it with a message that names the path so the
	// operator sees why the run bailed. The variant is ConfigInvalid
	// because no IO happened yet, so the message is the only signal.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	std::fs::create_dir(&data_dir).expect("mkdir data");
	let answers = Answers {
		mode: Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: Some(Ipv4Addr::new(8, 8, 8, 8)),
		public_ipv6: None,
		data_dir: data_dir.clone(),
		config_path: std::path::PathBuf::from("/"),
		dns: None,
		services: Services::default(),
	};
	let outcome = apply(&answers);
	let err = outcome
		.error
		.expect("apply must fail when config_path has no parent");
	assert!(
		matches!(err, ApplyError::ConfigInvalid(_)),
		"expected ConfigInvalid, got {err:?}"
	);
	let rendered = format!("{err}");
	assert!(
		rendered.contains("parent") || rendered.contains("config_path"),
		"ConfigInvalid display must explain why: {rendered}"
	);
}

fn answers_with_dns_and_extra_services() -> Answers {
	Answers {
		mode: Mode::Automatic,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: None,
		public_ipv6: None,
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: Some(DnsAnswers {
			provider: "cloudflare".to_string(),
			zone: "example.org".to_string(),
			token: None,
			token_file: Some(PathBuf::from("/run/secrets/cf")),
			token_env: None,
		}),
		services: Services {
			imap: false,
			submission: false,
			pop3: true,
			managesieve: true,
			webdav: true,
			api: false,
		},
	}
}

#[test]
fn apply_writes_a_config_with_every_service_kind() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_with_dns_and_extra_services();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	drop(outcome);
	let rendered = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		rendered.contains("\"pop3s\""),
		"POP3 listener must be wired through to the config: {rendered}"
	);
	assert!(
		rendered.contains("\"manage-sieve\""),
		"ManageSieve listener must be wired through: {rendered}"
	);
	assert!(
		rendered.contains("\"web-dav\""),
		"WebDAV listener must be wired through: {rendered}"
	);
	// management API is intentionally off here: enabling it requires
	// an [api] section that init does not generate, and the candidate
	// config would not validate. The api branch of build_config is
	// exercised in apply.rs unit tests that drive build_config
	// directly.
}

#[test]
fn apply_writes_a_config_with_a_dns_section() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_with_dns_and_extra_services();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	drop(outcome);
	let rendered = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		rendered.contains("[dns]"),
		"DNS section must be written into the config: {rendered}"
	);
	assert!(
		rendered.contains("cloudflare"),
		"DNS provider must be in the config: {rendered}"
	);
	assert!(
		rendered.contains("token_file"),
		"DNS token source must be in the config: {rendered}"
	);
	assert!(
		rendered.contains("/run/secrets/cf"),
		"DNS token_file path must be in the config: {rendered}"
	);
}

#[test]
fn apply_rejects_an_existing_config_that_is_unparseable() {
	// A config file already exists at the destination, but the TOML
	// parser cannot make sense of it. The apply phase must surface
	// the read failure rather than silently overwriting the file
	// with bytes the operator did not intend to keep.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	std::fs::create_dir(&data_dir).expect("mkdir data");
	std::fs::write(&config_path, "this is not = valid TOML\tbroken\n").expect("write");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod");
	}
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	let err = outcome.error.expect("apply must surface the parse failure");
	assert!(
		matches!(err, ApplyError::ConfigRead(_, _)),
		"expected ConfigRead, got {err:?}"
	);
	// The unparseable file must still be on disk; the apply phase
	// must not have replaced it with a candidate that never
	// validated.
	let still_there = std::fs::read_to_string(&config_path).expect("read");
	assert!(
		still_there.contains("broken"),
		"unparseable config must survive a failed apply; got: {still_there}"
	);
}

#[test]
fn build_config_includes_the_api_listener_when_services_request_it() {
	// build_config is the only caller that can drive the api branch:
	// enabling api through `apply` requires an [api] section that
	// init does not generate, so the candidate would never validate.
	// Pin the listener shape here so a future change cannot silently
	// drop the api branch.
	let mut answers = answers_minimal();
	answers.services = Services {
		imap: false,
		submission: false,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: true,
	};
	let cert = std::path::PathBuf::from("/var/lib/epistle/keys/cert.pem");
	let key = std::path::PathBuf::from("/var/lib/epistle/keys/key.pem");
	let ed = std::path::PathBuf::from("/var/lib/epistle/keys/s1.pem");
	let desired = apply_config::build_config(&answers, Some(&ed), None, &cert, &key)
		.expect("build_config with api");
	assert!(
		desired.listeners.iter().any(|l| l.kind == "api"),
		"api listener must be wired through: {:?}",
		desired.listeners
	);
}

#[cfg(unix)]
#[test]
fn apply_refuses_an_orphan_oauth_public_key() {
	// When oauth_private was deleted but oauth_public was left on
	// disk, the apply phase must NOT mint a fresh unrelated
	// oauth_private: tokens already issued against the surviving
	// oauth_public would silently break. The apply phase surfaces
	// an `OAuthPairIncomplete` error instead, names the missing
	// private key path, and leaves the surviving public key bytes
	// untouched.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome1 = apply(&answers);
	assert!(
		outcome1.error.is_none(),
		"first apply must succeed: {:?}",
		outcome1.error
	);
	drop(outcome1);
	// Delete only the private half so the public half is left over.
	let oauth_private = data_dir.join("keys").join("oauth_signing.key");
	let oauth_public = data_dir.join("keys").join("oauth_public.key");
	let public_before = std::fs::read(&oauth_public).expect("read public");
	assert!(
		oauth_private.exists(),
		"first apply must write oauth_private"
	);
	assert!(oauth_public.exists(), "first apply must write oauth_public");
	std::fs::remove_file(&oauth_private).expect("delete oauth_private");

	let outcome2 = apply(&answers);
	let err = outcome2
		.error
		.expect("second apply with orphan oauth_public must refuse");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!("expected OAuthPairIncomplete, got {err:?}");
	};
	assert!(
		message.contains("oauth_signing.key"),
		"the diagnostic must name the missing private key: {message}"
	);
	assert!(
		!oauth_private.exists(),
		"a fresh private key must NOT have been written"
	);
	let public_after = std::fs::read(&oauth_public).expect("read public");
	assert_eq!(
		public_before, public_after,
		"public key bytes must be untouched"
	);
}

#[cfg(unix)]
#[test]
fn apply_fails_when_existing_data_dir_blocks_keys_dir_creation() {
	// data_dir already exists with mode 0500. ensure_data_dir
	// succeeds (it sees the directory), then ensure_keys_dir tries
	// to create data_dir/keys and the mode blocks the write. The
	// apply phase must surface the failure as KeysDir rather than
	// silently creating the keys elsewhere.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	std::fs::create_dir(&data_dir).expect("mkdir data");
	std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o500))
		.expect("chmod 0500 on data");
	// Canary write: confirms the chmod actually blocks writes
	// (running as root would defeat the test).
	let canary = data_dir.join("canary");
	if std::fs::write(&canary, b"x").is_ok() {
		std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755))
			.expect("restore");
		let _ = std::fs::remove_file(&canary);
		eprintln!(
			"skipping: data_dir mode 0500 did not block writes (running as root or fs ignores mode)"
		);
		return;
	}
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	// Restore permissions so the tempdir can be cleaned up.
	let _ = std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755));
	let err = outcome
		.error
		.expect("apply must fail when keys dir cannot be created");
	assert!(
		matches!(err, ApplyError::KeysDir(_, _)),
		"expected KeysDir, got {err:?}"
	);
	assert!(
		format!("{err}").contains("keys"),
		"KeysDir display must name the path"
	);
}
