#![no_main]

//! A whole SMTP session driven by a command sequence the fuzzer chooses,
//! against a directory of two accounts built in memory. The session is
//! sans-IO and hands accepted mail to its caller, so no store, socket or
//! database is involved. The parser targets see one line at a time; this one
//! sees what a line does to the transaction the earlier ones built, and
//! checks after every step:
//!
//! - every reply is well framed: one code, continuation lines marked, CRLF
//!   at the end of each line and no CR or LF inside one;
//! - only a matching password signs in, as the account it belongs to;
//! - a signed-in account sends only from its own addresses;
//! - without signing in, a recipient is accepted only when it is a local
//!   account, so the server never relays for a stranger;
//! - a message is handed over only at the end of DATA or the last BDAT
//!   chunk, with the sender and recipients the transaction accepted and the
//!   body the client sent, dot-unstuffed, byte for byte.

#[path = "../../shared/accounts.rs"]
mod accounts;
mod client;
mod model;

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;

use epistle::smtp::session::{Action, Reply, Session};
use model::Model;

const MAX_STEPS: usize = 150;
/// The message size limit of the run: small, so the oversize path is
/// reachable from short inputs.
const MAX_SIZE: usize = 256;

/// One status code per reply, `-` on every line but the last, and CRLF only
/// at the end of each line.
fn check_reply(reply: &Reply) -> u16 {
	let wire = reply.to_string();
	let code = reply.code();
	assert!((200..600).contains(&code), "reply code out of range");
	let lines: Vec<&str> = wire.split_inclusive("\r\n").collect();
	assert!(wire.ends_with("\r\n"), "reply without CRLF");
	for (i, line) in lines.iter().enumerate() {
		let body = &line[..line.len() - 2];
		assert!(!body.contains(['\r', '\n']), "CR or LF inside a reply line");
		let separator = if i + 1 == lines.len() { ' ' } else { '-' };
		assert!(
			body.starts_with(&format!("{code}{separator}")),
			"reply line out of form"
		);
	}
	code
}

/// The reply an action carries, framed and checked.
fn reply_of(action: &Action) {
	match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::Deliver(r, _)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r)
		| Action::DiscardChunk { reply: r, .. } => {
			check_reply(r);
		}
		Action::CollectChunk { .. } => {}
	}
}

fn run(data: &[u8]) {
	let mut u = Unstructured::new(data);
	let accounts = accounts::accounts();
	let directory = accounts::directory(&accounts);
	let starttls = u.int_in_range(0..=3).unwrap_or(1) == 0;
	let mut session = Session::new("mx.example.org")
		.with_directory(directory)
		.with_max_message_size(MAX_SIZE)
		.with_max_recipients(4);
	session = if starttls {
		session.with_tls_available()
	} else {
		session.with_tls_active()
	};
	check_reply(&session.greeting());
	let mut model = Model::new(&accounts);
	let mut pending: Option<Action> = None;
	let mut prelude = client::prelude(&mut u, &accounts).into_iter();
	for _ in 0..MAX_STEPS {
		let first = match pending {
			None => prelude.next(),
			Some(_) => None,
		};
		if first.is_none() && u.is_empty() {
			break;
		}
		let action = match pending.take() {
			Some(Action::CollectData(_)) => model.data(&mut u, &mut session),
			Some(Action::CollectChunk { size, last }) => {
				let bytes = client::chunk(&mut u, size);
				let action = session.bdat_chunk(&bytes, last);
				model.chunk(&bytes, last, &action);
				action
			}
			Some(Action::CollectAuthResponse(_)) => model.auth_reply(&mut u, &mut session),
			_ => {
				let step = first.unwrap_or_else(|| client::command(&mut u, &accounts));
				let action = session.command_line(&step.line);
				model.command(&step, &action);
				action
			}
		};
		reply_of(&action);
		model.signed_in(&session);
		match action {
			Action::Close(_) => break,
			Action::UpgradeTls(_) => {
				session.tls_started();
				model.tls_started();
			}
			Action::CollectData(_)
			| Action::CollectChunk { .. }
			| Action::CollectAuthResponse(_) => {
				pending = Some(action);
			}
			_ => {}
		}
	}
}

fuzz_target!(|data: &[u8]| run(data));
