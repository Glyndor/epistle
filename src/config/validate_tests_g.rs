//! Validation tests for the `postmaster@<domain>` warning.
//!
//! Split out of `validate_tests.rs` to stay under the line limit, matching the
//! precedent set by the alert tests in `validate_tests_c.rs`, the tenant tests
//! in `validate_tests_d.rs`, the SRS tests in `validate_tests_e.rs` and the
//! database TLS tests in `validate_tests_f.rs`.

use super::tests::config_from;

#[test]
fn warns_when_domain_lacks_postmaster_and_catch_all() {
	// RFC 5321 §4.5.1: the server MUST accept mail to `postmaster` at every
	// domain it serves. Without an explicit `postmaster@<domain>` address or
	// a per-domain catch-all, RCPT TO for that address would resolve to
	// `UnknownUser` and the server would 5.1.1 the message. The validator
	// surfaces that as a warning — not a rejection — so an upgrade does not
	// refuse to start a server that was already running fine.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
"#,
	);
	assert!(
		result.is_ok(),
		"missing postmaster must warn, not fail: {:?}",
		result.err()
	);

	let events = crate::cli::tracing_capture::run_with_capture(|| {
		let _ = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
"#,
		);
	});
	let warning = events
		.iter()
		.find(|e| e.level == tracing::Level::WARN)
		.expect("expected a warning naming the missing postmaster address");
	let msg = warning
		.fields
		.get("message")
		.expect("message field")
		.as_str();
	assert!(
		msg.contains("postmaster"),
		"warning must mention postmaster: {msg}"
	);
	assert!(
		msg.contains("example.org"),
		"warning must name the domain: {msg}"
	);
	// Both fixes must be listed so the operator knows what to do.
	assert!(
		msg.contains("`postmaster@<domain>`"),
		"warning must list the explicit-address fix: {msg}"
	);
	assert!(
		msg.contains("catch_all"),
		"warning must list the catch-all fix: {msg}"
	);
	assert_eq!(
		warning.fields.get("domain").map(String::as_str),
		Some("example.org"),
		"warning carries the offending domain as a structured field"
	);
}

#[test]
fn accepts_explicit_postmaster_address() {
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org", "postmaster@example.org"]
"#,
	);
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn accepts_catch_all_in_place_of_postmaster() {
	// A domain-wide catch-all funnels `postmaster` (and every other unknown
	// user) to the configured account, so the RFC 5321 §4.5.1 acceptance
	// requirement is satisfied without an explicit `postmaster@<domain>`
	// address.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org"]
catch_all = ["example.org"]
"#,
	);
	assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn postmaster_warning_is_emitted_per_offending_domain() {
	// `example.org` has a configured `postmaster@` address, so it stays
	// silent; `second.example` has neither, so it produces a warning. One
	// bad domain does not stop the validator from also checking the rest —
	// every offending domain is reported, the way the old per-domain
	// rejection surfaced each one.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org", "second.example"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org", "postmaster@example.org"]
"#,
	);
	assert!(
		result.is_ok(),
		"missing postmaster must warn, not fail: {:?}",
		result.err()
	);

	let events = crate::cli::tracing_capture::run_with_capture(|| {
		let _ = config_from(
			r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org", "second.example"]

[[accounts]]
name = "alice"
addresses = ["alice@example.org", "postmaster@example.org"]
"#,
		);
	});
	let warnings: Vec<_> = events
		.iter()
		.filter(|e| e.level == tracing::Level::WARN)
		.collect();
	let warned_domains: Vec<&str> = warnings
		.iter()
		.filter_map(|w| w.fields.get("domain").map(String::as_str))
		.collect();
	assert!(
		warned_domains.contains(&"second.example"),
		"warning must name the offending domain: {warnings:?}"
	);
	assert!(
		!warned_domains.contains(&"example.org"),
		"warning must NOT name domains that have postmaster: {warnings:?}"
	);
}

#[test]
fn postmaster_requirement_is_skipped_without_accounts() {
	// Without accounts there is nowhere to deliver `postmaster@<domain>` to
	// anyway, so the validator does not insist on its address. The server
	// does not accept any mail in this configuration; the requirement
	// exists to prevent an *operational* server from rejecting postmaster.
	let result = config_from(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org"]
"#,
	);
	assert!(result.is_ok(), "{:?}", result.err());
}
