//! The address questions of the assistant against an injected detector:
//! a detected address is the default, typing replaces it, and the
//! non-global rule still rejects a typed private address.

use super::super::super::detect::tests::base::{Scripted, v4, v6};
use super::*;

/// Manual-mode answers with `ip_lines` (one line per answer, retries
/// included) in place of the two address questions.
fn input(ip_lines: &[&str]) -> String {
	let mut text = String::from("manual\nmail.example.org\nexample.org\n\n\n");
	for line in ip_lines {
		text.push_str(line);
		text.push('\n');
	}
	text.push_str("/var/lib/epistle\n/etc/epistle/mail.toml\n");
	// Seven service questions and the image, all left at their default.
	text.push_str(&"\n".repeat(8));
	text
}

fn drive(ip_lines: &[&str], detector: &dyn Detector) -> (String, Answers) {
	let text = input(ip_lines);
	let mut reader = std::io::BufReader::new(text.as_bytes());
	let mut out = Vec::new();
	let result = run(&mut reader, &mut out, detector);
	let printed = String::from_utf8(out).expect("utf-8");
	match result {
		Ok(filled) => (printed, filled.answers),
		Err(()) => panic!("the assistant gave up; it printed: {printed}"),
	}
}

#[test]
fn empty_input_accepts_the_detected_addresses() {
	let detector = Scripted::found(Some(v4()), Some(v6()));
	let (printed, answers) = drive(&["", ""], &detector);
	assert_eq!(answers.public_ipv4, Some(v4()));
	assert_eq!(answers.public_ipv6, Some(v6()));
	assert!(
		printed.contains("public IPv4 [8.8.8.8] (empty to accept, \"none\" to skip)> "),
		"the IPv4 prompt must offer the detected address: {printed}"
	);
	assert!(
		printed.contains("public IPv6 [2606:4700::1111] (empty to accept, \"none\" to skip)> "),
		"the IPv6 prompt must offer the detected address: {printed}"
	);
	assert_eq!(detector.calls.get(), 1, "one interface walk per run");
}

#[test]
fn a_typed_address_replaces_the_detected_one() {
	let detector = Scripted::found(Some(v4()), Some(v6()));
	let (_, answers) = drive(&["1.1.1.1", "none"], &detector);
	assert_eq!(answers.public_ipv4, Some("1.1.1.1".parse().expect("v4")));
	assert_eq!(
		answers.public_ipv6, None,
		"\"none\" skips a detected default"
	);
}

#[test]
fn a_typed_private_address_is_still_rejected_with_a_default_on_offer() {
	let detector = Scripted::found(Some(v4()), None);
	let (printed, answers) = drive(&["192.168.1.10", "", ""], &detector);
	assert!(
		printed.contains(
			"a private address (RFC 1918: 10/8, 172.16/12, 192.168/16); public address required"
		),
		"the non-global rule must reject the typed address: {printed}"
	);
	assert_eq!(
		answers.public_ipv4,
		Some(v4()),
		"the retry accepted the default"
	);
	assert_eq!(answers.public_ipv6, None);
}

#[test]
fn nothing_detected_keeps_the_plain_prompt_and_hints_at_nat() {
	let detector = Scripted::found(None, None);
	let (printed, answers) = drive(&["", ""], &detector);
	assert_eq!((answers.public_ipv4, answers.public_ipv6), (None, None));
	assert!(
		printed.contains("  no global IPv4 or IPv6 address on this host's interfaces"),
		"the NAT hint must be shown once: {printed}"
	);
	assert!(
		printed.contains("public IPv4 (empty to skip)> "),
		"{printed}"
	);
	assert!(
		!printed.contains("(empty to accept"),
		"no default may be offered: {printed}"
	);
}

#[test]
fn a_failing_detector_falls_back_to_the_plain_prompt() {
	let detector = Scripted::failing();
	let (printed, answers) = drive(&["1.1.1.1", ""], &detector);
	assert_eq!(answers.public_ipv4, Some("1.1.1.1".parse().expect("v4")));
	assert!(
		printed.contains("public IPv4 (empty to skip)> "),
		"{printed}"
	);
	assert!(
		printed.contains("public IPv6 (empty to skip)> "),
		"{printed}"
	);
	assert!(
		!printed.contains("(empty to accept"),
		"no default may be offered: {printed}"
	);
}

#[test]
fn a_non_global_detection_is_never_offered() {
	let private: std::net::Ipv4Addr = "10.0.0.5".parse().expect("v4");
	let detector = Scripted::found(Some(private), None);
	let (printed, answers) = drive(&["", ""], &detector);
	assert_eq!(answers.public_ipv4, None);
	assert!(!printed.contains("10.0.0.5"), "{printed}");
}
