//! No reservation in proportion to the input before the budget has been
//! looked at: a script's variable or a message's header of tens of mebibytes
//! must not make the interpreter hold tens of mebibytes more.

use super::alloc_probe::peak_bytes;
use super::ast::Argument;
use super::compare::match_spec;
use super::env::{Env, MAX_VAR_BYTES};

const MIB: usize = 1 << 20;

fn spec(tag: &str) -> super::compare::MatchSpec {
	match_spec(&[Argument::Tag(tag.to_string())])
}

#[test]
fn an_expansion_is_never_built_past_its_limit() {
	let mut env = Env::default();
	env.set("a", &"y".repeat(MAX_VAR_BYTES));
	// 16384 references of 4096 octets would be 64 MiB; the template is 64 KiB.
	let template = "${a}".repeat(16 * 1024);
	let (out, peak) = peak_bytes(|| env.expand(&template));
	assert_eq!(out.len(), template.len());
	assert!(
		peak < MIB,
		"{peak} octets held for a result of {}",
		out.len()
	);
}

#[test]
fn matching_a_long_text_copies_none_of_it() {
	let text = "a".repeat(32 * MIB);
	let mut env = Env::default();
	let (matched, peak) = peak_bytes(|| spec("matches").test(&text, "*a*", &mut env));
	assert!(matched);
	assert!(peak < MIB, "{peak} octets held to match 32 MiB");
	assert_eq!(env.get("1").map(str::len), Some(0));
	let (matched, peak) = peak_bytes(|| spec("matches").test(&text, "a*", &mut Env::default()));
	assert!(matched);
	assert!(peak < MIB, "{peak} octets held for the capture of 32 MiB");
}

#[test]
fn a_text_past_the_budget_is_refused_before_it_is_touched() {
	let text = "a".repeat(64 * MIB);
	let mut env = Env::default();
	// A run that has all but spent its work.
	assert!(env.charge(super::env::MAX_WORK - 1000));
	let (matched, peak) = peak_bytes(|| spec("matches").test(&text, "*a*", &mut env));
	assert!(!matched);
	assert!(env.exhausted(), "the run is abandoned, not told 'no match'");
	assert!(
		peak < 64 * 1024,
		"{peak} octets held for a text it would not read"
	);
}

#[test]
fn the_other_comparisons_copy_none_of_the_text_either() {
	let text = "A".repeat(32 * MIB);
	for (tag, key) in [("contains", "needle"), ("is", "other")] {
		let (_, peak) = peak_bytes(|| spec(tag).test_simple(&text, key));
		assert!(peak < MIB, ":{tag} held {peak} octets for 32 MiB");
	}
	let digits = "1".repeat(32 * MIB);
	let numeric = match_spec(&[
		Argument::Tag("value".to_string()),
		Argument::Str("gt".to_string()),
		Argument::Tag("comparator".to_string()),
		Argument::Str("i;ascii-numeric".to_string()),
	]);
	let (_, peak) = peak_bytes(|| numeric.test_simple(&digits, "5"));
	assert!(
		peak < MIB,
		"a numeric key held {peak} octets for 32 MiB of digits"
	);
}

/// A message of about `mib` mebibytes that is nothing but headers.
fn headers_only(mib: usize) -> Vec<u8> {
	let mut raw = Vec::with_capacity(mib * MIB + 64);
	let mut n = 0u64;
	while raw.len() < mib * MIB {
		raw.extend_from_slice(format!("h{n}: b\r\n").as_bytes());
		n += 1;
	}
	raw.extend_from_slice(b"\r\nbody\r\n");
	raw
}

#[test]
fn reading_a_message_of_millions_of_headers_holds_a_little_of_it() {
	// 24 MiB of one-letter header values is about two million headers. Each
	// one copied and indexed took 620 MiB of the server per recipient with a
	// filter; the interpreter looks at the first few thousand.
	let raw = headers_only(24);
	let (message, peak) = peak_bytes(|| super::interp::Message::parse(&raw));
	assert!(peak < 8 * MIB, "{peak} octets held for 24 MiB of headers");
	assert!(message.has_header("h0"));
	assert!(!message.has_header("h1999999"));
	let seen = message.visible_headers(&["h0"]);
	assert!(seen.truncated, "a lookup says the headers were cut");
}

#[test]
fn reading_a_message_with_a_huge_body_keeps_only_the_window_of_it() {
	let mut raw = b"Subject: hi\r\n\r\n".to_vec();
	raw.extend(std::iter::repeat_n(b'x', 24 * MIB));
	let (message, peak) = peak_bytes(|| super::interp::Message::parse(&raw));
	assert!(peak < 3 * MIB, "{peak} octets held for a 24 MiB body");
	let (shown, truncated) = message.body_window();
	assert_eq!(shown.len(), super::env::BODY_WINDOW);
	assert!(truncated);
}

#[test]
fn a_few_headers_are_all_visible_and_not_truncated() {
	let message = super::interp::Message::parse(b"A: 1\r\nB: 2\r\n\r\nbody");
	let seen = message.visible_headers(&["a", "b"]);
	assert_eq!(seen.values, vec!["1", "2"]);
	assert!(!seen.truncated);
}

#[test]
fn headers_that_are_not_utf8_cost_no_more_than_headers_that_are() {
	// One octet that is not UTF-8 used to make the whole header block be
	// copied (and each such octet three times as long) before any cut.
	let mut raw = Vec::new();
	while raw.len() < 24 * MIB {
		raw.extend_from_slice(b"h: \xff\xfe\r\n");
	}
	raw.extend_from_slice(b"\r\nbody\r\n");
	let (_, peak) = peak_bytes(|| super::interp::Message::parse(&raw));
	assert!(peak < 8 * MIB, "{peak} octets held for 24 MiB of headers");
}

#[test]
fn a_message_of_one_endless_line_of_bad_octets_is_cut_before_it_is_converted() {
	let raw = vec![0xffu8; 24 * MIB];
	let (message, peak) = peak_bytes(|| super::interp::Message::parse(&raw));
	assert!(
		peak < 4 * MIB,
		"{peak} octets held for 24 MiB without a break"
	);
	assert!(!message.has_header("h"));
}
