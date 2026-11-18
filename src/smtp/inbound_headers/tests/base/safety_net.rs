//! Inbound header tests: the safety net, reserved remainders and compaction cost.

use super::*;

/// The safety net re-parses with mail-parser and reports any reserved
/// field strip missed. It exists so a future mail-parser change that
/// folds a byte strip does not anticipate does not turn into a forged
/// header delivered.
#[test]
fn safety_net_flags_a_reserved_field_strip_would_leave() {
	for (name, value, expected) in [
		(
			"Authentication-Results",
			"mail.example.org; dkim=pass\r\n",
			"Authentication-Results",
		),
		("Received-SPF", "forged\r\n", "Received-SPF"),
		("Delivered-To", "alice@example.org\r\n", "Delivered-To"),
		("Return-Path", "<forged@example.org>\r\n", "Return-Path"),
		("Epistle-Class", "marketing\r\n", "Epistle-Class"),
		("X-Epistle", "forged\r\n", "X-Epistle"),
		("X-Spam-Status", "Yes\r\n", "X-Spam-Status"),
		("X-Spam-Score", "0.97\r\n", "X-Spam-Status"),
		(
			"X-Epistle-Attachment-Warning",
			"executable\r\n",
			"X-Epistle-Attachment-Warning",
		),
	] {
		let data = format!("{name}: {value}Subject: kept\r\n\r\nbody").into_bytes();
		assert_eq!(
			reserved_remaining(&data, HOST).unwrap_or(""),
			expected,
			"{name}"
		);
	}
}

/// The safety net must NOT flag a foreign, parseable `Authentication-Results`
/// (the stripper keeps it as untrusted information, by design) nor any
/// non-reserved field.
#[test]
fn safety_net_does_not_flag_foreign_or_unrelated_fields() {
	for data in [
		&b"Authentication-Results: other.example; spf=pass\r\nSubject: kept\r\n\r\nbody"[..],
		&b"From: eve@sender.example\r\nTo: alice@example.org\r\nSubject: hi\r\n\r\nbody"[..],
		&b"DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed; d=sender.example; s=external; h=from:to; bh=; b=\r\nSubject: kept\r\n\r\nbody"[..],
		&b"Authentication-Results: prior.example; spf=pass\r\nSubject: kept\r\n\r\nbody"[..],
		&b":Authentication-Results: prior.example; spf=pass\r\nSubject: kept\r\n\r\nbody"[..],
		&b"X-Epistlefoo: client\r\nSubject: kept\r\n\r\nbody"[..],
		&b":X-Epistlefoo: client\r\nSubject: kept\r\n\r\nbody"[..],
		&b"Subject: kept\r\n\r\n:X-Epistle: body"[..],
	] {
		assert!(reserved_remaining(data, HOST).is_none(), "{data:?}");
	}
}

/// The safety net compares names without regard to case: mail-parser keeps
/// the case of the names it does not know, so a lower-case spelling that
/// strip missed must still be refused.
#[test]
fn safety_net_ignores_the_case_of_the_name() {
	for (name, expected) in [
		("authentication-results", "Authentication-Results"),
		("AUTHENTICATION-RESULTS", "Authentication-Results"),
		("received-spf", "Received-SPF"),
		("delivered-to", "Delivered-To"),
		("return-path", "Return-Path"),
		("epistle-class", "Epistle-Class"),
		("x-epistle", "X-Epistle"),
		("x-spam-status", "X-Spam-Status"),
		("X-SPAM-Score", "X-Spam-Status"),
		(
			"x-epistle-attachment-warning",
			"X-Epistle-Attachment-Warning",
		),
	] {
		let data = format!("{name}: {HOST}; none\r\nSubject: kept\r\n\r\nbody").into_bytes();
		assert_eq!(
			reserved_remaining(&data, HOST).unwrap_or(""),
			expected,
			"{name}"
		);
	}
}

/// End-to-end through the strip-with-hole helper: a hole in the leader
/// fold lets `:Authentication-Results: x` survive strip; the safety net
/// must still flag it. This is what the SMTP path will hand the server
/// when run.rs calls `reserved_remaining` after `strip`.
#[test]
fn safety_net_catches_a_hypothetical_hole_in_strip() {
	for (name, expected) in [
		("Authentication-Results", "Authentication-Results"),
		("Received-SPF", "Received-SPF"),
		("Delivered-To", "Delivered-To"),
		("Return-Path", "Return-Path"),
		("Epistle-Class", "Epistle-Class"),
		("X-Epistle", "X-Epistle"),
		("X-Spam-Status", "X-Spam-Status"),
		("X-Spam-Score", "X-Spam-Status"),
		(
			"X-Epistle-Attachment-Warning",
			"X-Epistle-Attachment-Warning",
		),
	] {
		let mut data = format!(":{name}: forged\r\nSubject: kept\r\n\r\nbody").into_bytes();
		strip_buggy(&mut data, HOST);
		assert_eq!(
			reserved_remaining(&data, HOST).unwrap_or(""),
			expected,
			"{name}"
		);
		// And `strip` (with the leader fold) clears it, so the safety net
		// is the second pass, not the first.
		let mut fixed = format!(":{name}: forged\r\nSubject: kept\r\n\r\nbody").into_bytes();
		strip(&mut fixed, HOST);
		assert!(reserved_remaining(&fixed, HOST).is_none(), "{name}");
	}
}

/// Empty Authentication-Results values remain reserved. 1.0 represents
/// them as Text("") instead of Empty, so the authserv-id parser rejects
/// the empty text. Both representations must keep the same policy.
#[test]
fn reserved_remaining_flags_an_empty_authentication_results_value() {
	let original = b"Authentication-Results:\r\nSubject: kept\r\n\r\nbody";
	assert_eq!(
		reserved_remaining(original, HOST),
		Some("Authentication-Results"),
	);
}

#[test]
fn reserved_remaining_flags_an_empty_authentication_results_value_in_lowercase() {
	let original = b"authentication-results:\r\nSubject: kept\r\n\r\nbody";
	assert_eq!(
		reserved_remaining(original, HOST),
		Some("Authentication-Results"),
	);
}

/// Body amplification exposes repeated suffix shifts without move instrumentation.
#[test]
fn repeated_fields_compaction_cost_does_not_multiply_the_body() {
	fn elapsed(body_len: usize) -> std::time::Duration {
		let mut original = b"X-Spam-Status: forged\r\n".repeat(8_192);
		original.extend_from_slice(b"Subject: kept\r\n\r\n");
		original.resize(original.len() + body_len, 0xff);
		(0..3)
			.map(|_| {
				let mut data = original.clone();
				let start = std::time::Instant::now();
				strip(std::hint::black_box(&mut data), HOST);
				let elapsed = start.elapsed();
				assert_eq!(data.len(), b"Subject: kept\r\n\r\n".len() + body_len);
				std::hint::black_box(data);
				elapsed
			})
			.min()
			.unwrap()
	}
	let small = elapsed(64 * 1024);
	let large = elapsed(8 * 1024 * 1024);
	// Parsing is identical; one body copy permits a generous fixed margin.
	assert!(
		large < small * 12 + std::time::Duration::from_millis(50),
		"body amplification suggests repeated suffix moves: small={small:?}, large={large:?}"
	);
}
