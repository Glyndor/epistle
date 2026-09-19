//! Answers unit tests for the empty/whitespace-only DNS token sources.
//!
//! Lifted out of `answers_tests.rs` to keep it under the per-file
//! line limit. The assistant already trims before storing an empty
//! prompt answer as `None`; the file path used to keep the literal
//! `Some("")` and treat it as a present source. The shared validator
//! now treats an empty or whitespace-only value in any of the three
//! sources (`token`, `token_file`, `token_env`) as absent, so the
//! assistant and the file path reject the same input with the same
//! sentence.

use std::path::PathBuf;

use super::*;
use Mode::*;

fn minimal(mode: Mode) -> Answers {
	Answers {
		mode,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: None,
		public_ipv6: None,
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
	}
}

/// Empty `dns.token` in the answers file must NOT count as a present
/// token source: the assistant already trims before storing, so an
/// empty line on the prompt stays empty in the file, and the file
/// must reject it with the same `DnsTokenMissing` the assistant would
/// have produced.
#[test]
fn empty_dns_token_field_is_treated_as_absent() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: Some(String::new()),
		token_file: None,
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("empty token must count as absent");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsTokenMissing)),
		"empty token must surface as DnsTokenMissing, got {errors:?}"
	);
}

/// Whitespace-only `dns.token` (a stray space the operator hit on the
/// keyboard by accident) must NOT count as a present source either.
#[test]
fn whitespace_only_dns_token_field_is_treated_as_absent() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: Some("   ".to_string()),
		token_file: None,
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("whitespace token must count as absent");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsTokenMissing)),
		"whitespace token must surface as DnsTokenMissing, got {errors:?}"
	);
}

/// Empty `dns.token_file` in the answers file must NOT count as a
/// present source: the file path preserves the literal string the
/// operator wrote, and `token_file = ""` is the same shape an empty
/// prompt would produce.
#[test]
fn empty_dns_token_file_field_is_treated_as_absent() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: Some(PathBuf::new()),
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("empty token_file must count as absent");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsTokenMissing)),
		"empty token_file must surface as DnsTokenMissing, got {errors:?}"
	);
}

/// Whitespace-only `dns.token_file` (a stray path with spaces) must
/// NOT count as a present source either.
#[test]
fn whitespace_only_dns_token_file_field_is_treated_as_absent() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: Some(PathBuf::from("   ")),
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("whitespace token_file must count as absent");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsTokenMissing)),
		"whitespace token_file must surface as DnsTokenMissing, got {errors:?}"
	);
}

/// Empty `dns.token_env` in the answers file must NOT count as a
/// present source.
#[test]
fn empty_dns_token_env_field_is_treated_as_absent() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: None,
		token_env: Some(String::new()),
	});
	let errors = answers
		.validate()
		.expect_err("empty token_env must count as absent");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsTokenMissing)),
		"empty token_env must surface as DnsTokenMissing, got {errors:?}"
	);
}

/// Whitespace-only `dns.token_env` must NOT count as a present source.
#[test]
fn whitespace_only_dns_token_env_field_is_treated_as_absent() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: None,
		token_env: Some("   ".to_string()),
	});
	let errors = answers
		.validate()
		.expect_err("whitespace token_env must count as absent");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsTokenMissing)),
		"whitespace token_env must surface as DnsTokenMissing, got {errors:?}"
	);
}

/// The assistant and the file path must reject the same empty value
/// with the same `Invalid` variant: `token_file = ""` from the file
/// and the assistant (which never stores an empty value as Some) both
/// surface as `DnsTokenMissing` after a non-empty provider/zone have
/// been supplied.
#[test]
fn empty_token_file_in_file_and_assistant_produce_the_same_invalid() {
	let from_file = {
		let mut answers = minimal(Automatic);
		answers.dns = Some(DnsAnswers {
			provider: "cloudflare".to_string(),
			zone: "example.org".to_string(),
			token: None,
			token_file: Some(PathBuf::new()),
			token_env: None,
		});
		answers.validate().expect_err("file: empty token_file")
	};
	// The assistant never stores an empty value as Some: it calls
	// `(!token.is_empty()).then_some(...)`. So the assistant shape
	// is `None`, not `Some("")`. The validator must reject the
	// assistant shape with the same variant.
	let from_assistant = {
		let mut answers = minimal(Automatic);
		answers.dns = Some(DnsAnswers {
			provider: "cloudflare".to_string(),
			zone: "example.org".to_string(),
			token: None,
			token_file: None,
			token_env: None,
		});
		answers.validate().expect_err("assistant: empty token_file")
	};
	let file_has_missing = from_file
		.iter()
		.any(|e| matches!(e, Invalid::DnsTokenMissing));
	let assistant_has_missing = from_assistant
		.iter()
		.any(|e| matches!(e, Invalid::DnsTokenMissing));
	assert!(
		file_has_missing && assistant_has_missing,
		"both paths must surface DnsTokenMissing: file={from_file:?}, assistant={from_assistant:?}"
	);
}
