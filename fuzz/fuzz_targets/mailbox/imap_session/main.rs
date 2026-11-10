#![no_main]

//! A whole IMAP session driven by a command sequence the fuzzer chooses. The
//! session runs against a data directory of its own and a directory of two
//! accounts built in memory; no server, socket or database is involved. The
//! parser target sees one line at a time; this one sees what a line does to
//! the state the earlier ones built, and checks after every step:
//!
//! - the framing holds: lines end in CRLF and hold no other CR or LF, every
//!   literal is as long as it says, and a tagged command ends in its own
//!   tagged OK, NO or BAD;
//! - nothing past sign-in works before it: a mailbox command is refused and
//!   the data directory does not change;
//! - only a matching password signs in, and the right one does;
//! - one account never reaches the other: the neighbour's files never
//!   change, nothing outside the signed-in account changes, and no reply
//!   carries a string only the neighbour's mail holds, unless the client
//!   typed it itself.

#[path = "../../shared/accounts.rs"]
mod accounts;
mod client;
mod fixture;
mod reply;

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;

use accounts::{Account, which};
use client::{Kind, Step};
use epistle::imap::session::{Output, Session};
use fixture::{DataDir, Picture};

const MAX_STEPS: usize = 120;
/// APPENDLIMIT for the run: a literal the client announces is read from the
/// input, so it stays small.
const APPEND_LIMIT: usize = 4096;

/// What the model knows about the connection.
struct Model {
	/// The account the session signed in as.
	account: Option<usize>,
	/// Every byte the client sent: a marker found here may come back.
	sent: Vec<u8>,
	/// The half of a SASL LOGIN exchange already sent (the user name).
	sasl_user: Option<String>,
	/// The data directory before sign-in, which nothing may change.
	before: Picture,
}

fn contains(haystack: &[u8], needle: &str) -> bool {
	haystack
		.windows(needle.len())
		.any(|w| w == needle.as_bytes())
}

/// The tagged completion of a command and the framing of everything around it.
fn check_reply(step: &Step, output: &Output) {
	let lines = reply::lines(&output.bytes);
	let Some(tag) = step.tag.as_deref() else {
		return;
	};
	let waits = output.collect_literal.is_some() || output.collect_auth || output.idle;
	let last = lines.last().map(String::as_str).unwrap_or("");
	if waits {
		assert!(
			last.starts_with('+') || output.collect_literal.is_some(),
			"the session waits for the client without a continuation: {last:?}"
		);
		return;
	}
	// A line with a control character is refused before its tag is read, so
	// nothing can carry the tag back.
	if step.line.chars().any(|c| c.is_ascii_control()) {
		assert_eq!(
			lines,
			["* BAD malformed command"],
			"a line with a control character ran"
		);
		return;
	}
	let tagged: Vec<&String> = lines
		.iter()
		.filter(|l| reply::status(l, tag).is_some())
		.collect();
	assert_eq!(
		tagged.len(),
		1,
		"one tagged completion per command: {lines:?}"
	);
	assert!(
		reply::status(last, tag).is_some(),
		"the tagged completion is not the last line: {lines:?}"
	);
}

/// Before sign-in: a mailbox command is refused, and nothing is stored.
fn check_signed_out(step: &Step, output: &Output, model: &Model, dir: &DataDir) {
	if step.kind == Kind::Mailbox
		&& let Some(tag) = step.tag.as_deref()
	{
		let lines = reply::lines(&output.bytes);
		let ok = lines.iter().any(|l| reply::status(l, tag) == Some("OK"));
		assert!(!ok, "a mailbox command ran before sign-in");
		assert!(
			output.collect_literal.is_none(),
			"an APPEND before sign-in was read"
		);
	}
	let now = fixture::picture(&dir.0, &[]);
	assert!(
		now == model.before,
		"the data directory changed before sign-in: {:?}",
		fixture::changed(&model.before, &now)
	);
}

/// After sign-in as `me`: the neighbour is out of reach.
fn check_signed_in(output: &Output, me: usize, accounts: &[Account], model: &Model, dir: &DataDir) {
	let other = &accounts[1 - me];
	if !contains(&model.sent, &other.marker) {
		assert!(
			!contains(&output.bytes, &other.marker),
			"a reply carries the other account's mail"
		);
	}
	// Everything outside the signed-in account stays as it was. The
	// server-level annotations (SETMETADATA on the empty mailbox name) live
	// in the account's own directory, so they are inside it too.
	let mine = dir.account(accounts[me].name);
	let outside = fixture::picture(&dir.0, &[mine.clone()]);
	let was: Picture = model
		.before
		.iter()
		.filter(|(path, _)| !dir.0.join(path).starts_with(&mine))
		.map(|(p, v)| (p.clone(), v.clone()))
		.collect();
	assert!(
		outside == was,
		"a write landed outside the signed-in account: {:?}",
		fixture::changed(&was, &outside)
	);
}

fn run(data: &[u8]) {
	let mut u = Unstructured::new(data);
	let accounts = accounts::accounts();
	let directory = accounts::directory(&accounts);
	let dir = DataDir::new();
	fixture::seed(&mut u, &dir.0, &accounts);
	let quota = match u.int_in_range(0..=3).unwrap_or(0) {
		0 => 2048,
		_ => epistle::imap::session::DEFAULT_QUOTA_BYTES,
	};
	let mut session = Session::new("mail.example.org", dir.0.clone(), directory)
		.with_append_limit(APPEND_LIMIT)
		.with_quota_limit(quota);
	reply::lines(&session.greeting().bytes);
	let mut model = Model {
		account: None,
		sent: Vec::new(),
		sasl_user: None,
		before: fixture::picture(&dir.0, &[]),
	};
	let mut sasl = false;
	let mut idle = false;
	let mut prelude = client::prelude(&mut u, &accounts).into_iter();
	for counter in 0..MAX_STEPS {
		let first = prelude.next();
		if first.is_none() && u.is_empty() {
			break;
		}
		let (step, output) = if idle {
			let step = Step {
				line: "DONE".into(),
				tag: None,
				kind: Kind::Raw,
				login: None,
				literal: None,
			};
			let output = session.idle_done();
			(step, output)
		} else if sasl {
			let (line, login, half) = client::sasl_reply(&mut u, &accounts);
			let login = login.or_else(|| match (model.sasl_user.take(), half.clone()) {
				(Some(user), Some(pass)) => Some((user, pass)),
				(None, half) => {
					model.sasl_user = half;
					None
				}
				_ => None,
			});
			let output = session.auth_response(&line);
			let step = Step {
				line,
				tag: None,
				kind: Kind::SignIn,
				login,
				literal: None,
			};
			(step, output)
		} else {
			let step = first.unwrap_or_else(|| client::next(&mut u, &accounts, counter));
			let output = session.command_line(&step.line);
			(step, output)
		};
		model.sent.extend_from_slice(step.line.as_bytes());
		if let Some(literal) = &step.literal {
			model.sent.extend_from_slice(literal);
		}
		let mut output = output;
		check_reply(&step, &output);
		// The literal an APPEND announced, or whatever bytes the session
		// asks for when the line announced one the generator did not plan.
		if let Some(size) = output.collect_literal {
			assert!(
				size <= APPEND_LIMIT,
				"a literal over APPENDLIMIT was accepted"
			);
			let mut bytes = step.literal.clone().unwrap_or_default();
			bytes.resize(size, b'x');
			model.sent.extend_from_slice(&bytes);
			output = if u.int_in_range(0..=7).unwrap_or(0) == 0 {
				session.literal_bad_trailer()
			} else {
				session.literal_done(&bytes)
			};
			let finished = Step {
				line: String::new(),
				tag: step.tag.clone(),
				kind: step.kind,
				login: None,
				literal: None,
			};
			check_reply(&finished, &output);
		}
		sasl = output.collect_auth;
		idle = output.idle;
		if !sasl {
			model.sasl_user = None;
		}

		let now = session.is_authenticated();
		match model.account {
			Some(me) => {
				assert!(now, "the session signed itself out");
				check_signed_in(&output, me, &accounts, &model, &dir);
			}
			None if now => {
				let me = step.login.as_ref().and_then(|l| which(&accounts, l));
				assert!(me.is_some(), "signed in without a matching password");
				model.account = me;
				check_signed_in(&output, me.unwrap_or(0), &accounts, &model, &dir);
			}
			None => {
				// The right password on a LOGIN line has to work.
				let verb = step.line.split(' ').nth(1);
				let matching = step.login.as_ref().and_then(|l| which(&accounts, l));
				assert!(
					!(verb == Some("LOGIN") && matching.is_some()),
					"a matching LOGIN was refused"
				);
				check_signed_out(&step, &output, &model, &dir);
			}
		}
		if output.close {
			break;
		}
	}
}

fuzz_target!(|data: &[u8]| run(data));
