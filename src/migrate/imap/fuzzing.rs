//! Entry point for the fuzz target of the responses a source server sends to
//! `migrate imap` (see `crate::fuzzing`).
//!
//! The old server is untrusted: it may be compromised, or a man in the middle
//! may speak for it when the run allows an unverified certificate. The bytes
//! go through the same reader the client uses, with small bounds so a fuzzer
//! reaches every limit, and each response is handed to every parser the
//! client calls on a response.

use std::sync::OnceLock;
use std::time::Duration;

use super::parse;
use super::token::{MAX_TOKENS, tokenize};
use super::wire::{Limits, MAX_LITERALS, Response, read_response};

/// The bounds the fuzz target reads with: small enough that a short input
/// reaches the line and literal limits, which the defaults (64 KiB lines,
/// literals as large as a message) would put out of reach.
const LIMITS: Limits = Limits {
	line: 256,
	literal: 32,
	idle: Duration::from_secs(5),
	response: Duration::from_secs(5),
};

/// The most responses read from one input. Every response consumes at least
/// one line ending, so the input length bounds the loop already; this keeps
/// one input from turning into a long run when it is mostly line endings.
const MAX_RESPONSES: usize = 64;

/// Read `raw` as the stream a source server sends and parse every response
/// in it, checking the bounds the reader promises.
///
/// # Panics
///
/// When a response breaks a bound the reader or the parsers promise. That is
/// what the fuzz target looks for.
pub(crate) fn responses_for_fuzzing(raw: &[u8]) {
	static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
	let runtime = RUNTIME.get_or_init(|| {
		tokio::runtime::Builder::new_current_thread()
			.enable_time()
			.build()
			.expect("a current-thread runtime builds")
	});
	runtime.block_on(async {
		let mut reader = raw;
		for _ in 0..MAX_RESPONSES {
			let Ok(response) = read_response(&mut reader, &LIMITS).await else {
				return;
			};
			check_bounds(&response);
			parse_all(response);
		}
	});
}

/// The bounds of the reader and the tokenizer.
fn check_bounds(response: &Response) {
	let literals = response
		.segments
		.iter()
		.filter(|segment| segment.literal.is_some())
		.count();
	assert!(
		literals <= MAX_LITERALS,
		"{literals} literals in one response"
	);
	for segment in &response.segments {
		assert!(segment.text.len() <= LIMITS.line, "line over the limit");
		if let Some(literal) = &segment.literal {
			assert!(literal.len() <= LIMITS.literal, "literal over the limit");
		}
	}
	if let Ok(tokens) = tokenize(response) {
		assert!(tokens.len() <= MAX_TOKENS, "{} tokens", tokens.len());
	}
}

/// Every parser the client runs on a response.
fn parse_all(response: Response) {
	let largest = LIMITS.line.max(LIMITS.literal);
	if let parse::Kind::Tagged { text, .. } | parse::Kind::UntaggedStatus { text, .. } =
		parse::kind(&response)
	{
		let code = parse::response_code(&text);
		std::hint::black_box(parse::capabilities(code.iter().map(String::as_str)));
	}
	let words = parse::data_words(&response);
	assert!(words.len() <= 512, "{} data words", words.len());
	std::hint::black_box(parse::capabilities(words.iter().map(String::as_str)));
	if let Ok(Some(entry)) = parse::list_entry(&response) {
		assert!(entry.name.len() <= largest, "mailbox name over the limit");
	}
	if let Some(prefix) = parse::personal_namespace(&response) {
		assert!(prefix.len() <= largest, "namespace prefix over the limit");
	}
	if let Ok(Some(listed)) = parse::listed(response.clone()) {
		assert_ne!(listed.uid, 0, "a listed message without a UID");
	}
	if let Ok(Some(fetched)) = parse::fetch(response) {
		let body = fetched.body.as_ref().map_or(0, Vec::len);
		assert!(body <= largest, "message body over the limit");
		assert!(
			fetched.flags.len() <= MAX_TOKENS,
			"{} flags",
			fetched.flags.len()
		);
	}
}
