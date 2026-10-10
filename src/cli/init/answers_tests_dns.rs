//! Answers unit tests for the DNS provider section: empty and
//! whitespace-only token sources, and the four zone shapes that
//! used to bypass the validator (Unicode match, malformed,
//! confusable look-alike).
//!
//! The shared validator now treats an empty or whitespace-only value
//! in any of the three sources (`token`, `token_file`, `token_env`)
//! as absent, so the assistant and the file path reject the same
//! input with the same sentence.

use std::path::PathBuf;

use super::Mode::*;
use super::tests::minimal;
use super::*;

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

/// A Unicode zone with its Unicode domain must validate: the
/// previous shape compared the raw U-label zone against an A-label
/// domain and rejected a perfectly aligned pair. The shared
/// validator now normalises the zone before the scope check, so the
/// two spellings of one domain produce the same outcome.
#[test]
fn unicode_dns_zone_with_its_unicode_domain_validates() {
	let mut answers = minimal(Automatic);
	answers.domains = vec!["bücher.example.org".to_string()];
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "bücher.example.org".to_string(),
		token: None,
		token_file: Some(PathBuf::from("/run/secrets/cf")),
		token_env: None,
	});
	let result = answers.validate();
	assert!(
		result.is_ok(),
		"unicode zone with matching unicode domain must validate, got {result:?}"
	);
}

/// A zone that is not a valid domain name (`zone = "invalid"`) must
/// surface as `Invalid::DnsZoneMalformed` from the file path. The
/// shared validator runs `crate::domain::normalize` on the zone
/// before the scope check; the same shape would be rejected by the
/// assistant because `ask_domain` runs the same normaliser on
/// every prompt line.
#[test]
fn invalid_dns_zone_in_answers_file_fails_validation() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "invalid".to_string(),
		token: None,
		token_file: Some(PathBuf::from("/run/secrets/cf")),
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("invalid zone must surface as DnsZoneMalformed");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::DnsZoneMalformed { .. })),
		"invalid zone must surface as DnsZoneMalformed, got {errors:?}"
	);
}

/// A zone with a confusable look-alike (Cyrillic that looks like
/// `paypal.com`) must surface as `DnsZoneMalformed`. The same shape
/// in the assistant is rejected by `ask_domain` because the prompt
/// helper runs the same normaliser.
#[test]
fn confusable_dns_zone_in_answers_file_fails_validation() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "\u{0440}\u{0430}\u{04cf}pal.com".to_string(),
		token: None,
		token_file: Some(PathBuf::from("/run/secrets/cf")),
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("confusable zone must surface as DnsZoneMalformed");
	let has_zone_invalid = errors
		.iter()
		.any(|e| matches!(e, Invalid::DnsZoneMalformed { .. }));
	let has_zone_scope = errors.iter().any(|e| {
		matches!(
			e,
			Invalid::DnsZoneMalformed {
				reason,
				..
			} if reason.contains("confusable")
		)
	});
	assert!(
		has_zone_invalid && has_zone_scope,
		"confusable zone must surface as DnsZoneMalformed with the confusable reason: {errors:?}"
	);
}

/// `provider = "cloudfare"` (typo, missing the second `l`) is not in
/// the supported list. Without the validation, the build falls through
/// `Dns::build` to the manual-mode arm and the operator's automation
/// silently never runs. The answers validator must surface the bad
/// value up front with the supported names so the operator sees what
/// to fix without reading the validator's source.
#[test]
fn unknown_dns_provider_is_rejected_with_the_list_in_the_message() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudfare".to_string(),
		zone: "example.org".to_string(),
		token: Some("x".to_string()),
		token_file: None,
		token_env: None,
	});
	let errors = answers.validate().expect_err("unknown provider must error");
	let bad = errors
		.iter()
		.find_map(|e| match e {
			Invalid::DnsProviderUnsupported { value, supported } => {
				Some((value.clone(), supported.clone()))
			}
			_ => None,
		})
		.expect("expected DnsProviderUnsupported");
	assert_eq!(bad.0, "cloudfare");
	// Every supported name appears in the error message so the operator
	// can see the list at a glance.
	let supported = bad.1.clone();
	for name in [
		"cloudflare",
		"desec",
		"digitalocean",
		"porkbun",
		"rfc2136",
		"godaddy",
		"manual",
	] {
		assert!(
			supported.contains(name),
			"supported list must name {name}: {supported}"
		);
	}
	// The display rendering carries the same fields.
	let rendered = errors
		.iter()
		.map(|e| format!("{e}"))
		.collect::<Vec<_>>()
		.join("; ");
	assert!(rendered.contains("cloudfare"), "{rendered}");
	assert!(rendered.contains("cloudflare"), "{rendered}");
}

/// The supported list is matched case-insensitively: an operator who
/// types `Cloudflare` (capitalised) must not be told it is unsupported.
#[test]
fn capitalised_dns_provider_name_is_accepted() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "Cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: Some("x".to_string()),
		token_file: None,
		token_env: None,
	});
	let result = answers.validate();
	assert!(
		result.is_ok(),
		"capitalised provider must validate, got {result:?}"
	);
}
