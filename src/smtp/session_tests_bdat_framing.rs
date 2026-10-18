//! BDAT message octets get the framing DATA gets from the line decoder: no
//! bare CR or LF, no NUL, no line past the SMTP limit, however the octets
//! are cut into chunks. The same message must reach the same verdict over
//! DATA and over BDAT, for an anonymous sender and for an authenticated one.

use super::*;
use crate::smtp::line::{LineCheck, LineDecoder, MAX_LINE_LENGTH};
use crate::smtp::session::tests_mods::tests_auth::reply_text;
use crate::smtp::trace::line_error_reply;

/// How a message ended.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
	/// Handed to delivery, with the body as stored.
	Delivered(Vec<u8>),
	/// The connection was closed with this reply.
	Closed(String),
	/// Refused with this reply, the connection kept.
	Refused(String),
}

/// A session ready for message data: anonymous to a local recipient, or
/// alice (authenticated) to a remote one.
fn ready(authenticated: bool) -> Session {
	if !authenticated {
		let mut session = tests_basic::greeted();
		session.command_line("MAIL FROM:<carol@remote.example>");
		session.command_line("RCPT TO:<bob@example.org>");
		return session;
	}
	let directory = Arc::new(Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	));
	let mut session = Session::new("mail.example.org")
		.with_directory(directory)
		.with_tls_active();
	session.command_line("EHLO client.example.org");
	session.mark_authenticated_for_test("alice");
	assert_eq!(session.authenticated(), Some("alice"));
	session.command_line("MAIL FROM:<alice@example.org>");
	session.command_line("RCPT TO:<dave@remote.example>");
	session
}

fn outcome(action: Action) -> Option<Outcome> {
	match action {
		Action::Deliver(_, message) => Some(Outcome::Delivered(message.data)),
		Action::Close(_) => Some(Outcome::Closed(reply_text(&action))),
		Action::Continue(ref reply) if reply.code() >= 400 => {
			Some(Outcome::Refused(reply_text(&action)))
		}
		_ => None,
	}
}

/// `body` over DATA: through the line decoder, as the connection loop does.
fn via_data(body: &[u8], authenticated: bool) -> Outcome {
	let mut session = ready(authenticated);
	assert!(matches!(
		session.command_line("DATA"),
		Action::CollectData(_)
	));
	let mut decoder = LineDecoder::new();
	decoder.feed(body);
	decoder.feed(b".\r\n");
	loop {
		match decoder.next_line() {
			Err(error) => return Outcome::Closed(line_error_reply(&error).to_string()),
			Ok(None) => panic!("DATA never finished"),
			Ok(Some(line)) => {
				if let Some(action) = session.data_line(&line) {
					return outcome(action).expect("final action");
				}
			}
		}
	}
}

/// `body` over BDAT, cut at `cuts` (offsets into `body`, ascending).
fn via_bdat(body: &[u8], cuts: &[usize], authenticated: bool) -> Outcome {
	let mut session = ready(authenticated);
	let mut edges = vec![0];
	edges.extend_from_slice(cuts);
	edges.push(body.len());
	for (index, pair) in edges.windows(2).enumerate() {
		let chunk = &body[pair[0]..pair[1]];
		let last = index == edges.len() - 2;
		let command = format!("BDAT {}{}", chunk.len(), if last { " LAST" } else { "" });
		let Action::CollectChunk { .. } = session.command_line(&command) else {
			panic!("BDAT not accepted");
		};
		if let Some(done) = outcome(session.bdat_chunk(chunk, last)) {
			return done;
		}
	}
	panic!("BDAT never finished");
}

/// Cuttings of `body`: every single cut and single octets for a short body;
/// for a long one (a session costs a password check) the cuts at both ends
/// and around the middle.
fn cuttings(body: &[u8]) -> Vec<Vec<usize>> {
	let len = body.len();
	let mut cuts: Vec<usize> = (0..=len).collect();
	if len > 64 {
		cuts = [
			0,
			1,
			2,
			30,
			31,
			len / 2,
			len - 6,
			len - 5,
			len - 2,
			len - 1,
			len,
		]
		.to_vec();
	}
	let mut all: Vec<Vec<usize>> = cuts.into_iter().map(|at| vec![at]).collect();
	if len <= 64 {
		all.push((1..len).collect());
	}
	all.push(Vec::new());
	all
}

#[track_caller]
fn assert_same_verdict(body: &[u8], authenticated: bool) -> Outcome {
	let expected = via_data(body, authenticated);
	for cuts in cuttings(body) {
		assert_eq!(
			via_bdat(body, &cuts, authenticated),
			expected,
			"body {body:?} cut at {cuts:?}, authenticated: {authenticated}"
		);
	}
	expected
}

const GOOD: &[u8] = b"From: alice@example.org\r\nSubject: hi\r\n\r\nhello\r\n";

#[test]
fn a_well_formed_message_is_the_same_over_data_and_bdat() {
	for authenticated in [false, true] {
		assert_eq!(
			assert_same_verdict(GOOD, authenticated),
			Outcome::Delivered(GOOD.to_vec())
		);
	}
}

#[track_caller]
fn assert_closed_over_both(body: &[u8], text: &str) {
	for authenticated in [false, true] {
		let verdict = assert_same_verdict(body, authenticated);
		assert_eq!(verdict, Outcome::Closed(text.to_string()), "{body:?}");
	}
}

const BARE: &str = "554 5.5.2 bare CR or LF is not allowed, closing connection\r\n";
const NUL: &str = "554 5.5.2 NUL byte received, closing connection\r\n";
const LONG: &str = "500 5.5.2 line too long, closing connection\r\n";

#[test]
fn a_bare_lf_is_refused_over_both() {
	assert_closed_over_both(b"From: alice@example.org\nSubject: hi\r\n\r\nx\r\n", BARE);
	assert_closed_over_both(b"From: alice@example.org\r\n\r\nx\ny\r\n", BARE);
}

#[test]
fn a_bare_cr_is_refused_over_both() {
	assert_closed_over_both(b"From: alice@example.org\r\n\r\nx\ry\r\n", BARE);
	assert_closed_over_both(b"From: alice@example.org\r\n\r\nx\r\r\n", BARE);
}

#[test]
fn a_cr_ending_the_message_is_refused() {
	// Nothing follows the CR: over DATA the dot line after it makes it a
	// bare CR, and over BDAT the end of the message does.
	assert_closed_over_both(b"From: alice@example.org\r\n\r\nx\r", BARE);
}

#[test]
fn a_nul_is_refused_over_both() {
	assert_closed_over_both(b"From: alice@example.org\r\n\r\nx\0y\r\n", NUL);
}

#[test]
fn a_line_past_the_smtp_limit_is_refused_over_both() {
	let mut body = b"From: alice@example.org\r\nX: ".to_vec();
	body.extend(std::iter::repeat_n(b'a', MAX_LINE_LENGTH));
	body.extend_from_slice(b"\r\n\r\nx\r\n");
	assert_closed_over_both(&body, LONG);
	// One octet under the limit is a line like any other.
	let mut fits = b"From: alice@example.org\r\nX: ".to_vec();
	fits.extend(std::iter::repeat_n(b'a', MAX_LINE_LENGTH - 3));
	fits.extend_from_slice(b"\r\n\r\nx\r\n");
	assert_eq!(
		assert_same_verdict(&fits, false),
		Outcome::Delivered(fits.clone())
	);
}

#[test]
fn a_bare_lf_cannot_hide_a_second_from_in_a_submission() {
	// The From check reads one field; a bare LF would let a second one ride
	// behind it. Refused before the check is reached.
	let body = b"From: alice@example.org\nFrom: ceo@victim.example\r\n\r\nx\r\n";
	assert_eq!(
		assert_same_verdict(body, true),
		Outcome::Closed(BARE.into())
	);
}

#[test]
fn an_end_of_data_marker_behind_a_bare_lf_is_refused() {
	let body = b"From: alice@example.org\r\n\r\nx\n.\r\nQUIT\r\n";
	for authenticated in [false, true] {
		assert_eq!(
			assert_same_verdict(body, authenticated),
			Outcome::Closed(BARE.into())
		);
	}
}

#[test]
fn a_refused_message_leaves_no_transaction_behind() {
	let mut session = ready(false);
	session.command_line("BDAT 3");
	let action = session.bdat_chunk(b"a\nb", false);
	assert!(matches!(action, Action::Close(_)));
	assert!(!session.in_transaction());
}

#[test]
fn a_zero_octet_chunk_does_not_reopen_data() {
	// An empty chunk starts chunking: DATA is no way round the checks.
	let mut session = ready(false);
	assert!(matches!(
		session.command_line("BDAT 0"),
		Action::CollectChunk { .. }
	));
	assert_eq!(
		tests_basic::reply_code(&session.bdat_chunk(b"", false)),
		250
	);
	assert_eq!(tests_basic::reply_code(&session.command_line("DATA")), 503);
	// The framing state survives the empty chunks: a CR before and an LF
	// after them are one CRLF, and an LF alone after them is not.
	session.command_line("BDAT 2");
	session.bdat_chunk(b"x\r", false);
	session.command_line("BDAT 0");
	assert_eq!(
		tests_basic::reply_code(&session.bdat_chunk(b"", false)),
		250
	);
	session.command_line("BDAT 2 LAST");
	assert!(matches!(
		session.bdat_chunk(b"\ny", true),
		Action::Deliver(..)
	));
	let mut session = ready(false);
	session.command_line("BDAT 1");
	session.bdat_chunk(b"x", false);
	session.command_line("BDAT 0");
	session.bdat_chunk(b"", false);
	session.command_line("BDAT 1 LAST");
	assert!(matches!(session.bdat_chunk(b"\n", true), Action::Close(_)));
}

#[test]
fn an_unterminated_last_line_is_kept_as_sent() {
	// DATA cannot send one; BDAT may, and nothing about it is smuggling.
	let mut session = ready(false);
	session.command_line("BDAT 5 LAST");
	let Action::Deliver(_, message) = session.bdat_chunk(b"hello", true) else {
		panic!("expected delivery");
	};
	assert_eq!(message.data, b"hello");
}

/// Every string over a four-letter alphabet, up to `len` letters.
fn strings(len: usize) -> Vec<Vec<u8>> {
	let mut all = vec![Vec::new()];
	let mut layer = vec![Vec::new()];
	for _ in 0..len {
		layer = layer
			.iter()
			.flat_map(|prefix| {
				b"a\r\n\0".iter().map(move |&byte| {
					let mut next = prefix.clone();
					next.push(byte);
					next
				})
			})
			.collect();
		all.extend(layer.iter().cloned());
	}
	all
}

#[test]
fn the_line_decoder_and_the_bdat_check_agree_on_every_short_stream() {
	// A small cap so the length rule is exercised too.
	const CAP: usize = 3;
	for body in strings(7) {
		let mut wire = body.clone();
		wire.extend_from_slice(b"\r\n");
		let mut decoder = LineDecoder::with_limit(CAP);
		decoder.feed(&wire);
		let mut data_ok = true;
		loop {
			match decoder.next_line() {
				Err(_) => {
					data_ok = false;
					break;
				}
				Ok(None) => break,
				Ok(Some(_)) => {}
			}
		}
		for cut in 0..=wire.len() {
			let mut check = LineCheck::new();
			let verdict = check
				.feed(&wire[..cut], CAP)
				.and_then(|()| check.feed(&wire[cut..], CAP))
				.and_then(|()| check.finish());
			assert_eq!(verdict.is_ok(), data_ok, "{wire:?} cut at {cut}");
		}
	}
}
