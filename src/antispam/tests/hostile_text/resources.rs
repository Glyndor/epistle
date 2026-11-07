//! Input construction is outside the probe; all three analysis passes run
//! on the measured thread, so Sieve's thread-local allocator sees their work.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::antispam::{bayes, scoring_text, urls};

const DEADLINE: Duration = Duration::from_secs(2);
// Initial debug measurements peaked at 2,000,513 bytes; allow four times
// that amount for allocator and platform variation, with a 2-second deadline.
const MAX_PEAK: usize = 8 * 1024 * 1024;

struct Analysis {
	reduced: scoring_text::ScoringText,
	tokens: Vec<String>,
	hosts: Vec<String>,
}

fn analyze(raw: Vec<u8>) -> Analysis {
	let (send, receive) = mpsc::sync_channel(1);
	let started = Instant::now();
	let worker = std::thread::spawn(move || {
		let measured = crate::sieve::test_peak_bytes(|| {
			let reduced = scoring_text::scoring_text(&raw);
			let tokens = bayes::tokenize_bounded(&reduced.text, 5000);
			let hosts = urls::extract_hosts(&raw, urls::DEFAULT_HOST_CAP);
			Analysis {
				reduced,
				tokens,
				hosts,
			}
		});
		// A timeout has already failed the test; do not panic on the sender too.
		let _ = send.send(measured);
	});
	let (analysis, peak) = match receive.recv_timeout(DEADLINE) {
		Ok(measured) => measured,
		Err(RecvTimeoutError::Timeout) => panic!("text analysis exceeded 2 seconds"),
		Err(RecvTimeoutError::Disconnected) => {
			worker.join().expect("analysis worker panicked");
			panic!("analysis worker returned no measurement");
		}
	};
	worker.join().expect("analysis worker panicked");
	let elapsed = started.elapsed();
	eprintln!("hostile text: elapsed={elapsed:?}, peak={peak} bytes");
	assert!(elapsed < DEADLINE, "text analysis took {elapsed:?}");
	assert!(
		peak > 0,
		"allocation probe recorded no analysis allocations"
	);
	assert!(
		peak < MAX_PEAK,
		"text analysis held {peak} bytes (limit {MAX_PEAK})"
	);
	assert!(
		!analysis.reduced.unread,
		"analysis panicked and used its unread fallback"
	);
	assert!(
		analysis
			.reduced
			.text
			.split_whitespace()
			.any(|token| token == "tailmarker"),
		"lost text after hostile input"
	);
	analysis
}

fn message(kind: &str, body: &str) -> Vec<u8> {
	format!("Content-Type: text/{kind}; charset=utf-8\r\n\r\n{body}").into_bytes()
}

#[test]
fn a_hundred_thousand_links_are_bounded_and_marked_incomplete() {
	// Unique hosts stop URL extraction at its host cap; duplicates force it
	// to scan all 256 KiB. Both bodies must stay within the measured budget.
	for unique in [true, false] {
		let mut body = String::new();
		for n in 0..100_000 {
			use std::fmt::Write;
			let host = if unique { n } else { 0 };
			writeln!(body, "https://host{host}.test/path").unwrap();
		}
		body.push_str("tailmarker");
		let analysis = analyze(message("plain", &body));
		// Both decoded-byte and token-window limits are exceeded. This is
		// the signal score_message passes to score_text's 0.5 floor.
		assert!(
			analysis.reduced.clipped,
			"exhausted text budget was reported complete"
		);
		assert!(analysis.reduced.text.len() <= crate::antispam::training_queue::MAX_TRAINING_BYTES);
		assert_eq!(
			analysis.hosts.len(),
			if unique { urls::DEFAULT_HOST_CAP } else { 1 }
		);
		assert_eq!(
			analysis.hosts.first().map(String::as_str),
			Some("host0.test")
		);
		assert_eq!(
			analysis.hosts.last().map(String::as_str),
			Some(if unique { "host49.test" } else { "host0.test" })
		);
	}
}

#[test]
fn a_million_character_token_does_not_hide_the_next_word() {
	// ASCII takes the split fast path; Unicode takes push_chars, whose
	// temporary token must stop growing at 30 bytes. Each input has 1M chars.
	for character in ['a', 'é'] {
		let body = format!("{} tailmarker", character.to_string().repeat(1_000_000));
		let analysis = analyze(message("plain", &body));
		// Oversize tokens are deliberately ignored, not an exhausted window.
		assert!(
			!analysis.reduced.clipped,
			"one discarded token consumed the window"
		);
		assert!(
			!analysis
				.reduced
				.text
				.contains(&character.to_string().repeat(31)),
			"oversize token was retained"
		);
		assert!(analysis.hosts.is_empty());
	}
}

#[test]
fn eight_thousand_html_levels_keep_the_visible_text_without_recursion() {
	let body = format!(
		"{}innermarker{} tailmarker",
		"<div>".repeat(8192),
		"</div>".repeat(8192)
	);
	let analysis = analyze(message("html", &body));
	// The scorer reads HTML bytes as text; MIME depth is a different limit.
	assert!(
		!analysis.reduced.clipped,
		"small HTML was not read completely"
	);
	assert!(
		analysis.tokens.iter().any(|token| token == "innermarker"),
		"deep HTML lost its innermost text"
	);
	assert!(analysis.hosts.is_empty());
}
