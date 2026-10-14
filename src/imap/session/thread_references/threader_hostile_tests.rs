//! THREAD=REFERENCES on mailboxes shaped to exhaust it: reply chains as
//! long as the mailbox, references that force the loop check over deep
//! trees, and References headers with far more ids than a real one.

use std::fmt::Write;
use std::time::{Duration, Instant};

use super::*;

/// Message texts, numbered from 1 in order and all sent at once.
fn thread_texts(texts: &[String]) -> (String, usize) {
	let mut threader = Threader::new();
	for (seqno, text) in (1..).zip(texts) {
		threader.add(seqno, seqno, 0, text);
	}
	let containers = threader.builder.containers();
	let mut out = String::new();
	threader.render(false, &mut out);
	(out, containers)
}

/// `n` messages, each replying to the one before.
fn chain(n: usize) -> Vec<String> {
	(0..n)
		.map(|i| match i {
			0 => "Message-ID: <m0@x>\r\n\r\n".to_string(),
			_ => format!("Message-ID: <m{i}@x>\r\nReferences: <m{}@x>\r\n\r\n", i - 1),
		})
		.collect()
}

/// A chain of `n / 2` messages, then `n / 2` messages whose References
/// ask to hang the head of the chain under its tail: every one of those
/// links would loop, and finding that out by walking up from the tail
/// costs the whole chain each time.
fn loop_probes(n: usize) -> Vec<String> {
	let half = n / 2;
	let mut texts = chain(half);
	texts.extend((0..half).map(|j| {
		format!(
			"Message-ID: <p{j}@x>\r\nReferences: <m{}@x> <m0@x>\r\n\r\n",
			half - 1
		)
	}));
	texts
}

/// One message, then one whose References lists `n` other ids before it.
fn long_references(n: usize) -> Vec<String> {
	let mut references = String::with_capacity(n * 12);
	for i in 0..n {
		let _ = write!(references, " <r{i}@x>");
	}
	vec![
		"Message-ID: <p@x>\r\n\r\n".to_string(),
		format!("Message-ID: <c@x>\r\nReferences:{references} <p@x>\r\n\r\n"),
	]
}

/// One message with `n - 1` direct replies.
fn star(n: usize) -> Vec<String> {
	(0..n)
		.map(|i| match i {
			0 => "Message-ID: <s@x>\r\n\r\n".to_string(),
			_ => format!("Message-ID: <s{i}@x>\r\nIn-Reply-To: <s@x>\r\n\r\n"),
		})
		.collect()
}

/// A reply chain where every message also has a reply of its own, so
/// each level nests one list deeper: `(1 (2)(3 (4)(5 ...)))`.
fn comb(n: usize) -> Vec<String> {
	(0..n)
		.map(|i| match i {
			0 => "Message-ID: <k0@x>\r\n\r\n".to_string(),
			_ => format!(
				"Message-ID: <k{i}@x>\r\nReferences: <k{}@x>\r\n\r\n",
				(i - 1) / 2 * 2
			),
		})
		.collect()
}

/// Pairs of messages without references that share a base subject, one
/// an original and one a reply, under as many subjects as half the count.
fn subjects(n: usize) -> Vec<String> {
	(0..n)
		.map(|i| {
			let reply = if i % 2 == 1 { "Re: " } else { "" };
			format!("Subject: {reply}topic {}\r\n\r\n", i / 2)
		})
		.collect()
}

#[test]
fn a_hundred_thousand_message_chain_renders_as_one_list() {
	let n = 100_000;
	let (out, _) = thread_texts(&chain(n));
	let mut expected = String::from("(1");
	for seqno in 2..=n {
		let _ = write!(expected, " {seqno}");
	}
	expected.push(')');
	assert!(out == expected, "the chain did not render as (1 2 ... {n})");
}

#[test]
fn a_hundred_thousand_replies_to_one_message_render_flat() {
	let n = 100_000;
	let (out, _) = thread_texts(&star(n));
	let mut expected = String::from("(1 ");
	for seqno in 2..=n {
		let _ = write!(expected, "({seqno})");
	}
	expected.push(')');
	assert!(
		out == expected,
		"the replies did not render as (1 (2)...({n}))"
	);
}

#[test]
fn a_comb_fifty_thousand_lists_deep_renders_nested() {
	let levels = 50_000;
	let (out, _) = thread_texts(&comb(2 * levels + 1));
	let mut expected = String::from("(1");
	for level in 1..=levels {
		let _ = write!(expected, " ({})({}", 2 * level, 2 * level + 1);
	}
	expected.push_str(&")".repeat(levels + 1));
	assert!(out == expected, "the comb did not nest one list per level");
}

#[test]
fn originals_take_their_replies_by_subject() {
	let (out, _) = thread_texts(&subjects(6));
	assert_eq!(out, "(1 2)(3 4)(5 6)");
}

#[test]
fn loop_probes_against_a_long_chain_change_nothing() {
	let n = 20_000;
	let (out, _) = thread_texts(&loop_probes(n));
	// The probes' last reference is the head, so they reply to it next to
	// the rest of the chain, which stays as it was.
	let mut expected = String::from("(1 (2");
	for seqno in 3..=n / 2 {
		let _ = write!(expected, " {seqno}");
	}
	expected.push(')');
	for seqno in n / 2 + 1..=n {
		let _ = write!(expected, "({seqno})");
	}
	expected.push(')');
	assert!(out == expected, "the probes moved the head of the chain");
}

#[test]
fn an_enormous_references_list_keeps_the_parent_and_a_bounded_tail() {
	let (out, containers) = thread_texts(&long_references(200_000));
	assert_eq!(out, "(1 2)");
	// The parent's container, the reply's own, and the ids it keeps.
	assert!(
		containers <= msgid::MAX_REFERENCES + 1,
		"{containers} containers for one header"
	);
}

/// A mailbox of about `n` messages.
type Shape = fn(usize) -> Vec<String>;

/// The fastest of three runs, so a busy machine adds as little noise as it
/// can to a timing comparison.
fn fastest(texts: &[String]) -> Duration {
	(0..3)
		.map(|_| {
			let started = Instant::now();
			thread_texts(texts);
			started.elapsed()
		})
		.min()
		.unwrap_or_default()
}

/// Growth, not wall clock: four times the input must cost about four times
/// the work (a little more for the sorts and the amortized splay steps).
/// A quadratic path costs about sixteen times. The short run is floored at
/// 5 ms so scheduler noise on a busy machine cannot make the ratio look
/// quadratic.
#[test]
fn hostile_mailboxes_take_near_linear_time() {
	let small = 12_500;
	let shapes: [(&str, Shape); 6] = [
		("chain", chain),
		("comb", comb),
		("subjects", subjects),
		("loop probes", loop_probes),
		("long references", long_references),
		("star", star),
	];
	for (name, shape) in shapes {
		let (short, long) = (shape(small), shape(small * 4));
		let base = fastest(&short).max(Duration::from_millis(5));
		let grown = fastest(&long);
		assert!(
			grown < base * 10,
			"{name} went from {base:?} to {grown:?} for four times the input"
		);
	}
}
