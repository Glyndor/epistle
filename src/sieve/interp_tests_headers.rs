//! A sender can put as many headers in a message as the message may hold.
//! Looking them up, and visiting what a lookup finds, is work a run pays
//! for, and does not cost a pass over every header each time.

use std::time::{Duration, Instant};

use super::interp::{Message, Outcome, evaluate};
use super::lexer::tokenize;
use super::parser::parse;

/// A message with `count` headers named `x` (and a Subject).
fn crowded(count: usize) -> Vec<u8> {
	let mut raw = b"Subject: hi\r\n".to_vec();
	for _ in 0..count {
		raw.extend_from_slice(b"x: y\r\n");
	}
	raw.extend_from_slice(b"\r\nbody\r\n");
	raw
}

fn run(script: &str, raw: &[u8]) -> (Outcome, Duration) {
	let tokens = tokenize(script).expect("lex");
	let commands = parse(&tokens).expect("parse");
	let message = Message::parse(raw);
	let started = Instant::now();
	let outcome = evaluate(&commands, &message);
	(outcome, started.elapsed())
}

#[test]
fn looking_up_a_header_that_is_not_there_does_not_read_every_header() {
	// 3000 tests over 300 000 headers: nine hundred million header
	// comparisons if each test reads them all.
	let script = "if exists \"x-nothere\" { discard; }\n".repeat(3000);
	let (outcome, took) = run(&script, &crowded(300_000));
	assert!(!outcome.aborted && !outcome.discarded);
	assert!(took < Duration::from_secs(3), "{took:?}");
}

#[test]
fn a_long_list_of_names_is_a_lookup_each() {
	// One test (one step) with 60 000 names over 200 000 headers.
	let names: Vec<String> = (0..60_000).map(|n| format!("\"x-{n:05}\"")).collect();
	let script = format!(
		"if header :contains [{}] \"zzz\" {{ discard; }}\n",
		names.join(",")
	);
	let (outcome, took) = run(&script, &crowded(200_000));
	assert!(!outcome.discarded);
	assert!(took < Duration::from_secs(3), "{took:?}");
}

#[test]
fn visiting_the_values_of_a_header_is_paid_for() {
	// A million values of `x`. A lookup visits the first thousand of them, and
	// a test that does so again and again stops the run when it has spent what
	// it may.
	let script = "if header :contains \"x\" \"zzz\" { discard; }\n".repeat(5000);
	let (outcome, took) = run(&script, &crowded(1_000_000));
	assert!(outcome.aborted, "the run was not stopped");
	assert!(took < Duration::from_secs(20), "{took:?}");
}

#[test]
fn counting_headers_is_a_lookup_not_a_pass() {
	let script = "require \"relational\";\nif header :count \"ge\" :comparator \"i;ascii-numeric\" \"x\" \"1000000\" { discard; }\n".repeat(3000);
	let (outcome, took) = run(&script, &crowded(300_000));
	assert!(!outcome.aborted && !outcome.discarded);
	assert!(took < Duration::from_secs(3), "{took:?}");
}

#[test]
fn the_headers_are_still_found_whatever_their_case() {
	let raw = b"X-Foo: one\r\nx-foo: two\r\nSubject: s\r\n\r\nb\r\n";
	let (outcome, _) = run("if header :is \"X-FOO\" \"two\" { discard; }", raw);
	assert!(outcome.discarded);
	let (outcome, _) = run(
		"require \"relational\";\nif header :count \"eq\" :comparator \"i;ascii-numeric\" \"x-foo\" \"2\" { discard; }",
		raw,
	);
	assert!(outcome.discarded);
}

#[test]
fn a_name_visits_its_first_thousand_values() {
	let mut raw = Vec::new();
	for n in 0..3000 {
		let value = if n == 2500 { "needle" } else { "y" };
		raw.extend_from_slice(format!("x: {value}\r\n").as_bytes());
	}
	raw.extend_from_slice(b"\r\nb\r\n");
	let script = "if header :contains \"x\" \"needle\" { discard; }";
	assert!(
		!run(script, &raw).0.discarded,
		"the 2501st value is past the quota"
	);
	let mut early = raw.clone();
	early.splice(0..0, b"x: needle\r\n".iter().copied());
	assert!(
		run(script, &early).0.discarded,
		"the first thousand are read"
	);
	// A value is read up to 64 KiB.
	let long = format!("Subject: {}needle\r\n\r\nb\r\n", "y".repeat(70_000));
	assert!(
		!run(
			"if header :contains \"subject\" \"needle\" { discard; }",
			long.as_bytes()
		)
		.0
		.discarded
	);
	let near = format!("Subject: {}needle\r\n\r\nb\r\n", "y".repeat(60_000));
	assert!(
		run(
			"if header :contains \"subject\" \"needle\" { discard; }",
			near.as_bytes()
		)
		.0
		.discarded
	);
}

#[test]
fn only_the_first_ten_thousand_headers_are_read_and_a_lookup_says_so() {
	// Subject plus 20 000 `x`: the interpreter reads the first 10 000 of all.
	let raw = crowded(20_000);
	let (outcome, _) = run(
		"require \"relational\";\nif header :count \"ge\" :comparator \"i;ascii-numeric\" \"x\" \"10000\" { discard; }\n",
		&raw,
	);
	assert!(!outcome.discarded, "9 999 `x` were read: {outcome:?}");
	assert!(outcome.inspection_truncated);
	let (outcome, _) = run(
		"if header :contains \"subject\" \"hi\" { discard; }\n",
		&raw,
	);
	assert!(
		outcome.discarded,
		"the headers before the cut are all there"
	);
	let (outcome, _) = run("if exists \"subject\" { discard; }\n", &crowded(10));
	assert!(outcome.discarded && !outcome.inspection_truncated);
}

/// 12 000 filler headers and then the ones a filter would look at.
fn padded() -> Vec<u8> {
	let mut raw = Vec::new();
	for n in 0..12_000 {
		raw.extend_from_slice(format!("x{n}: y\r\n").as_bytes());
	}
	raw.extend_from_slice(b"From: evil@x.example\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nSubject: cheap\r\n\r\nbody\r\n");
	raw
}

#[test]
fn every_test_that_looks_at_headers_says_when_some_were_not_read() {
	// SMTP refuses such a message, but a message can reach the filter by
	// other ways (the cut is the safety net), and no test may answer "not
	// there" about a header past the cut without a trace.
	for script in [
		"if header :contains \"subject\" \"cheap\" { discard; }",
		"if address :is \"from\" \"evil@x.example\" { discard; }",
		"if exists \"from\" { discard; }",
		"if not exists \"from\" { keep; }",
		"require \"date\";\nif date :is \"date\" \"year\" \"2024\" { discard; }",
	] {
		let (outcome, _) = run(script, &padded());
		assert!(outcome.inspection_truncated, "{script}: {outcome:?}");
	}
}

fn discarded(script: &str, raw: &[u8]) -> bool {
	let (outcome, _) = run(script, raw);
	outcome.discarded
}

#[test]
fn padding_with_blanks_does_not_push_the_text_out_of_the_window() {
	let script = "if header :contains \"subject\" \"viagra\" { discard; }";
	let spaces = " ".repeat(70_000);
	// In the first line, in a folded line, after text, and as many folded lines.
	let first = format!("Subject:{spaces}viagra\r\n\r\nb\r\n");
	let folded = format!("Subject: cheap\r\n{spaces}viagra\r\n\r\nb\r\n");
	let inside = format!("Subject: cheap{spaces}viagra\r\n\r\nb\r\n");
	let lines = format!("Subject:{} viagra\r\n\r\nb\r\n", "\r\n ".repeat(70_000));
	for raw in [first, folded, inside, lines] {
		assert!(discarded(script, raw.as_bytes()), "{}", &raw[..40]);
	}
}

#[test]
fn a_value_keeps_its_words_whatever_the_blanks_between_them() {
	let raw = b"Subject:  two\t words   and\r\n more \r\n\r\nb\r\n";
	assert!(discarded(
		"if header :is \"subject\" \"two words and more\" { discard; }",
		raw
	));
}

#[test]
fn a_message_at_the_smtp_limit_with_the_servers_own_fields_is_read_whole() {
	// SMTP lets MAX_HEADER_FIELDS through and the server adds about a dozen
	// (a hundred is the margin): the last field must still be under the cut.
	let mut raw = Vec::new();
	for n in 0..crate::smtp::trace::MAX_HEADER_FIELDS - 1 {
		raw.extend_from_slice(format!("x{n}: y\r\n").as_bytes());
	}
	raw.extend_from_slice(b"From: evil@x.example\r\n");
	let mut stamped = Vec::new();
	for n in 0..100 {
		stamped.extend_from_slice(format!("Received: hop {n}\r\n").as_bytes());
	}
	stamped.extend_from_slice(&raw);
	stamped.extend_from_slice(b"\r\nbody\r\n");
	let (outcome, _) = run(
		"if address :is \"from\" \"evil@x.example\" { discard; }",
		&stamped,
	);
	assert!(
		outcome.discarded && !outcome.inspection_truncated,
		"{outcome:?}"
	);
}

#[test]
fn octets_that_are_not_utf8_do_not_hide_the_text_after_them() {
	// 23 folded lines of 990 octets of 0xff: converted to the three-octet
	// replacement character they pushed the word out of the window, and
	// nothing said so. Each octet is one character now.
	let mut raw = b"Subject:".to_vec();
	for _ in 0..23 {
		raw.extend_from_slice(b"\r\n ");
		raw.extend(std::iter::repeat_n(0xffu8, 990));
	}
	raw.extend_from_slice(b"\r\n viagra\r\n\r\nb\r\n");
	assert!(discarded(
		"if header :contains \"subject\" \"viagra\" { discard; }",
		&raw
	));
}

#[test]
fn the_ends_of_a_value_lose_every_blank_that_trim_loses() {
	let script = "if header :is \"subject\" \"viagra\" { discard; }";
	for (name, blank) in [
		("NBSP", "\u{a0}"),
		("ideographic", "\u{3000}"),
		("NEL", "\u{85}"),
		("VT", "\u{b}"),
		("FF", "\u{c}"),
		("CR", "\r"),
		("tab", "\t"),
	] {
		for raw in [
			format!("Subject: {blank}viagra\r\n\r\nb\r\n"),
			format!("Subject: viagra{blank}\r\n\r\nb\r\n"),
			format!("Subject:\r\n {blank}viagra{blank}\r\n\r\nb\r\n"),
		] {
			assert!(discarded(script, raw.as_bytes()), "{name}: {raw:?}");
		}
	}
}

#[test]
fn a_header_name_of_endless_bad_octets_is_not_a_header() {
	let mut raw = vec![0xffu8; 65_000];
	raw.extend_from_slice(b": value\r\nSubject: viagra\r\n\r\nb\r\n");
	let (outcome, _) = run(
		"if header :contains \"subject\" \"viagra\" { discard; }",
		&raw,
	);
	assert!(outcome.discarded, "the line after it is read");
	assert!(
		outcome.inspection_truncated,
		"and the name left out is said"
	);
}

#[test]
fn a_message_with_lf_line_ends_has_its_headers_and_not_its_body_as_headers() {
	let mut raw = b"Subject: viagra\n\n".to_vec();
	for n in 0..20_000 {
		raw.extend_from_slice(format!("not-a-header-{n}: y\n").as_bytes());
	}
	let (outcome, _) = run(
		"if exists \"not-a-header-5\" { keep; } else { discard; }",
		&raw,
	);
	assert!(
		outcome.discarded && !outcome.inspection_truncated,
		"{outcome:?}"
	);
}
