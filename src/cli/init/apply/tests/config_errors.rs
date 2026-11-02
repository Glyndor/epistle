//! Apply unit tests: report rendering, ApplyError Display, and the
//! no-parent error. Lives in a sibling because the original
//! `src/cli/init/apply/tests/base.rs` and `src/cli/init/apply/tests/reuse.rs` are at the per-file line
//! limit. These tests pin the operator-visible strings that drive
//! the stderr output during a failed or partial run.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::apply_config;
use super::failures::apply_error_name;
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
		image: Some("localhost/epistle:dev".to_string()),
		acme: None,
		first_account: None,
		resources: Default::default(),
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
		name: "account alice@example.org".to_string(),
		reason: "it already exists".to_string(),
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
		rendered.contains("skipped:") && rendered.contains("alice@example.org"),
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
		image: Some("localhost/epistle:dev".to_string()),
		acme: None,
		first_account: None,
		resources: Default::default(),
	};
	let outcome = apply(&answers);
	let err = outcome
		.error
		.expect("apply must fail when config_path has no parent");
	assert!(
		matches!(err, ApplyError::ConfigInvalid(_)),
		"expected ConfigInvalid, got {}",
		apply_error_name(&err)
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
			antivirus: None,
			imap: false,
			submission: false,
			pop3: true,
			managesieve: true,
			webdav: true,
			api: false,
			database: false,
		},
		image: Some("localhost/epistle:dev".to_string()),
		acme: None,
		first_account: None,
		resources: Default::default(),
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
	// API setup is exercised separately below.
}

#[path = "config_errors_extra.rs"]
mod extra;
