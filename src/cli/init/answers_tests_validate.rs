//! Per-field rules of `Answers::validate`. Every test here drives
//! `validate()` with one deliberate mistake and asserts that the
//! corresponding `Invalid` variant surfaces; the next sibling
//! (`answers_tests_deserialise`) exercises the answers TOML path and
//! `answers_tests_messages` pins the Display strings.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use super::Mode::*;
use super::tests::minimal;
use super::*;

#[test]
fn minimal_manual_answers_validate_with_no_warnings() {
	let answers = minimal(Manual);
	let result = answers.validate();
	assert!(
		matches!(result, Ok(ref w) if w.is_empty()),
		"got {result:?}"
	);
}

#[test]
fn manual_mode_rejects_dns_section() {
	let mut answers = minimal(Manual);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: Some(PathBuf::from("/run/secrets/cf")),
		token_env: None,
	});
	let result = answers.validate();
	let errors = result.expect_err("manual with dns must error");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsForbidden)),
		"got {errors:?}"
	);
}

#[test]
fn automatic_mode_requires_dns_section() {
	let mut answers = minimal(Automatic);
	answers.dns = None;
	let errors = answers
		.validate()
		.expect_err("automatic without dns must error");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsRequired)),
		"got {errors:?}"
	);
}

#[test]
fn hostname_equal_to_a_domain_is_an_error() {
	let mut answers = minimal(Manual);
	answers.hostname = "example.org".to_string();
	let errors = answers
		.validate()
		.expect_err("hostname == domain must error");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::Hostname(_))),
		"got {errors:?}"
	);
}

#[test]
fn duplicate_domains_are_an_error() {
	let mut answers = minimal(Manual);
	answers.domains = vec!["example.org".to_string(), "EXAMPLE.org".to_string()];
	let errors = answers
		.validate()
		.expect_err("duplicate domains must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::DomainsDuplicate { .. })),
		"got {errors:?}"
	);
}

#[test]
fn empty_domains_is_an_error() {
	let mut answers = minimal(Manual);
	answers.domains.clear();
	let errors = answers.validate().expect_err("empty domains must error");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DomainsEmpty)),
		"got {errors:?}"
	);
}

#[test]
fn invalid_domain_is_an_error() {
	let mut answers = minimal(Manual);
	answers.domains = vec!["not a domain".to_string()];
	let errors = answers.validate().expect_err("invalid domain must error");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::Domain { .. })),
		"got {errors:?}"
	);
}

#[test]
fn private_ipv4_is_an_error() {
	let mut answers = minimal(Manual);
	answers.public_ipv4 = Some(Ipv4Addr::new(192, 168, 0, 1));
	let errors = answers.validate().expect_err("private IPv4 must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::PublicIpv4 { .. })),
		"got {errors:?}"
	);
}

#[test]
fn loopback_ipv6_is_an_error() {
	let mut answers = minimal(Manual);
	answers.public_ipv6 = Some(Ipv6Addr::LOCALHOST);
	let errors = answers.validate().expect_err("loopback IPv6 must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::PublicIpv6 { .. })),
		"got {errors:?}"
	);
}

#[test]
fn inline_dns_token_warns_but_does_not_error() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: Some("inline-secret".to_string()),
		token_file: None,
		token_env: None,
	});
	let warnings = answers
		.validate()
		.expect("inline token should warn, not error");
	assert!(
		warnings.iter().any(|w| w.field == "dns.token"),
		"got {warnings:?}"
	);
}

#[test]
fn multiple_dns_token_sources_is_an_error() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: Some(PathBuf::from("/run/secrets/cf")),
		token_env: Some("CF_TOKEN".to_string()),
	});
	let errors = answers
		.validate()
		.expect_err("two token sources must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::DnsTokenAmbiguous)),
		"got {errors:?}"
	);
}

// Empty `dns.token` and the other token sources counting as absent
// are covered in `answers_tests_dns.rs`.

#[test]
fn automatic_dns_outside_zone_is_an_error() {
	let mut answers = minimal(Automatic);
	answers.domains = vec!["example.com".to_string()];
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: Some(PathBuf::from("/run/secrets/cf")),
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("domain outside zone must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::DnsZoneScope { .. })),
		"got {errors:?}"
	);
}

#[test]
fn disabling_both_imap_and_submission_warns() {
	let mut answers = minimal(Manual);
	answers.services = Services {
		imap: false,
		submission: false,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
		database: false,
	};
	let warnings = answers.validate().expect("must warn, not error");
	assert!(
		warnings.iter().any(|w| w.field == "services"),
		"got {warnings:?}"
	);
}

#[test]
fn non_absolute_data_dir_is_an_error() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("relative/path");
	let errors = answers
		.validate()
		.expect_err("relative data_dir must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::DataDirNotAbsolute)),
		"got {errors:?}"
	);
}

#[test]
fn non_absolute_config_path_is_an_error() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from("relative/path");
	let errors = answers
		.validate()
		.expect_err("relative config_path must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathNotAbsolute)),
		"got {errors:?}"
	);
}

#[test]
fn three_independent_mistakes_report_three_errors() {
	let answers = Answers {
		mode: Manual,
		hostname: "example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
		public_ipv6: None,
		data_dir: PathBuf::from("relative/data"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
		image: None,
		acme: None,
	};
	let errors = answers.validate().expect_err("three mistakes must error");
	let count = errors.len();
	assert!(
		count >= 3,
		"expected at least 3 errors, got {count}: {errors:?}"
	);
}
