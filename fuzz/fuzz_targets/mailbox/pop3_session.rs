#![no_main]

//! A whole POP3 session driven by a command sequence the fuzzer chooses,
//! against an in-memory backend holding two accounts. The parser targets see
//! one line at a time; this one sees what a line does to the state the lines
//! before it built, and checks four things after every step:
//!
//! - nothing past sign-in works before it: no mailbox is listed, read or
//!   deleted until the password of the account matched;
//! - one account never reads another: every message the session asks the
//!   store for belongs to the account that signed in, and every body it
//!   returns is that account's message, byte for byte;
//! - deletion is a promise kept at QUIT and only there: the store is asked
//!   to remove exactly the messages the client deleted and did not restore;
//! - a reply never breaks the framing: one status line per reply, and a
//!   dot-terminated body that nothing inside it can end early.
//!
//! The passwords come from the input, so no secret is written in this file.

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use std::rc::Rc;

use epistle::pop3::command::{Command, parse};
use epistle::pop3::session::{Backend, Response, Session};

const ACCOUNTS: [&str; 2] = ["acct-a", "acct-b"];
const MAX_STEPS: usize = 200;

struct Account {
	name: &'static str,
	secret: String,
	inbox: Vec<(String, Vec<u8>)>,
}

/// What the session asked of the store, in order.
#[derive(Default)]
struct Log {
	verified: Vec<String>,
	listed: Vec<String>,
	fetched: Vec<(String, String)>,
	removed: Vec<(String, Vec<String>)>,
}

struct Store {
	accounts: Rc<Vec<Account>>,
	log: Rc<RefCell<Log>>,
}

impl Backend for Store {
	fn verify(&self, user: &str, pass: &str, _peer: Option<std::net::IpAddr>) -> Option<String> {
		let found = self
			.accounts
			.iter()
			.find(|a| a.name == user && a.secret == pass)?;
		self.log.borrow_mut().verified.push(found.name.to_string());
		Some(found.name.to_string())
	}

	fn list(&self, account: &str) -> Vec<(String, usize)> {
		self.log.borrow_mut().listed.push(account.to_string());
		let found = self.accounts.iter().find(|a| a.name == account);
		found.map_or_else(Vec::new, |a| {
			a.inbox.iter().map(|(u, d)| (u.clone(), d.len())).collect()
		})
	}

	// Looks the id up in every account, not just the one asked about: a
	// session that passes the wrong account still gets bytes back, and the
	// comparison afterwards is what catches it.
	fn fetch(&self, account: &str, uid: &str) -> Option<Vec<u8>> {
		self.log
			.borrow_mut()
			.fetched
			.push((account.to_string(), uid.to_string()));
		self.accounts
			.iter()
			.flat_map(|a| a.inbox.iter())
			.find(|(u, _)| u == uid)
			.map(|(_, d)| d.clone())
	}

	fn remove(&self, account: &str, uids: &[String]) {
		self.log
			.borrow_mut()
			.removed
			.push((account.to_string(), uids.to_vec()));
	}
}

/// Where the sign-in of this connection stands, as far as the model knows.
enum Pending {
	/// No `USER` is waiting for its `PASS`.
	No,
	/// `USER name` was accepted and `PASS` has not come.
	User(String),
	/// Something the model does not follow (a SASL exchange) touched it.
	Unknown,
}

struct Model {
	signed_in: Option<usize>,
	pending: Pending,
	awaiting_sasl: bool,
	deleted: Vec<bool>,
	logged_before: usize,
}

fn text(u: &mut Unstructured, max: usize) -> String {
	let len = u.int_in_range(0..=max).unwrap_or(0);
	let bytes = u.bytes(len).unwrap_or(&[]);
	String::from_utf8_lossy(bytes).into_owned()
}

fn secret(u: &mut Unstructured) -> String {
	let bytes = u.bytes(8).unwrap_or(&[0; 8]).to_vec();
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn base64(input: &[u8]) -> String {
	const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let mut out = String::new();
	for chunk in input.chunks(3) {
		let n = chunk
			.iter()
			.enumerate()
			.fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
		for i in 0..4 {
			if i <= chunk.len() {
				out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
			} else {
				out.push('=');
			}
		}
	}
	out
}

fn build_accounts(u: &mut Unstructured) -> Vec<Account> {
	ACCOUNTS
		.iter()
		.map(|name| {
			let count = u.int_in_range(0..=4).unwrap_or(0);
			let inbox = (0..count)
				.map(|i| {
					let mut body = format!("X-Owner: {name}\r\n\r\n").into_bytes();
					let extra = u.int_in_range(0..=48).unwrap_or(0);
					body.extend_from_slice(u.bytes(extra).unwrap_or(&[]));
					(format!("{name}-{i}"), body)
				})
				.collect();
			Account {
				name,
				secret: secret(u),
				inbox,
			}
		})
		.collect()
}

/// A name, a password or a number the fuzzer picks, biased to the real ones.
fn pick_name(u: &mut Unstructured) -> String {
	match u.int_in_range(0..=3).unwrap_or(0) {
		0 | 1 => ACCOUNTS[u.int_in_range(0..=1).unwrap_or(0)].to_string(),
		2 => text(u, 8),
		_ => String::new(),
	}
}

fn pick_secret(u: &mut Unstructured, accounts: &[Account]) -> String {
	match u.int_in_range(0..=3).unwrap_or(0) {
		0 => accounts[0].secret.clone(),
		1 => accounts[1].secret.clone(),
		2 => text(u, 16),
		_ => secret(u),
	}
}

fn number(u: &mut Unstructured) -> u32 {
	u.int_in_range(0..=6).unwrap_or(0)
}

/// The next line the client sends: a well-formed command most of the time, raw
/// bytes the rest.
fn next_line(u: &mut Unstructured, accounts: &[Account]) -> String {
	match u.int_in_range(0..=21).unwrap_or(5) {
		0 => format!("USER {}", pick_name(u)),
		1 => format!("PASS {}", pick_secret(u, accounts)),
		2 => {
			let authz = if u.arbitrary::<bool>().unwrap_or(false) {
				pick_name(u)
			} else {
				String::new()
			};
			let name = pick_name(u);
			let pass = pick_secret(u, accounts);
			format!(
				"AUTH PLAIN {}",
				base64(format!("{authz}\0{name}\0{pass}").as_bytes())
			)
		}
		3 => "AUTH PLAIN".to_string(),
		4 => "AUTH".to_string(),
		5 => text(u, 40),
		6 => "STAT".to_string(),
		7 => "LIST".to_string(),
		8 => format!("LIST {}", number(u)),
		9 => "UIDL".to_string(),
		10 => format!("UIDL {}", number(u)),
		11 | 12 => format!("RETR {}", number(u)),
		13 => format!("TOP {} {}", number(u), number(u)),
		14 | 15 => format!("DELE {}", number(u)),
		16 => "RSET".to_string(),
		17 => "NOOP".to_string(),
		18 => "CAPA".to_string(),
		19 => {
			let name = pick_name(u);
			let pass = pick_secret(u, accounts);
			base64(format!("\0{name}\0{pass}").as_bytes())
		}
		20 => "*".to_string(),
		_ => "QUIT".to_string(),
	}
}

/// One status line per reply, and a body that only its own terminator ends.
fn check_framing(response: &Response) {
	let wire = response.encode();
	assert!(wire.ends_with(b"\r\n"), "reply does not end in CRLF");
	assert_eq!(response.is_final(), matches!(response, Response::Bye(_)));
	match response {
		Response::Multiline { .. } => {
			assert!(wire.starts_with(b"+OK "), "multiline reply without +OK");
			let first = wire.windows(2).position(|w| w == b"\r\n").unwrap();
			let body = &wire[first + 2..];
			assert!(body.ends_with(b".\r\n"), "body not dot-terminated");
			let lines: Vec<&[u8]> = body.split(|b| *b == b'\n').collect();
			// Split on LF: the last piece is empty, the one before is the
			// terminator, and none of the earlier ones may be a lone dot.
			for line in &lines[..lines.len().saturating_sub(2)] {
				assert!(*line != b".\r", "a body line ends the reply early");
			}
			for (i, byte) in wire.iter().enumerate() {
				assert!(*byte != b'\n' || wire[i - 1] == b'\r', "bare LF in a reply");
			}
		}
		_ => {
			let first = wire.windows(2).position(|w| w == b"\r\n").unwrap();
			assert_eq!(first + 2, wire.len(), "a status reply spans two lines");
			assert!(!wire[..first].iter().any(|b| *b == b'\r' || *b == b'\n'));
		}
	}
}

fn expect_err(response: &Response, what: &str) {
	assert!(matches!(response, Response::Err(_)), "{what}: {response:?}");
}

fn line_for(index: usize, size: usize) -> String {
	format!("{} {}\r\n", index + 1, size)
}

/// The transaction state: every reply against the model of the mailbox.
fn check_transaction(
	command: &Command,
	response: &Response,
	account: &Account,
	deleted: &mut [bool],
) {
	let live = |n: u32| {
		let i = (n as usize).checked_sub(1)?;
		(i < deleted.len() && !deleted[i]).then_some(i)
	};
	let sizes = |deleted: &[bool]| -> (usize, usize) {
		let kept = account
			.inbox
			.iter()
			.zip(deleted)
			.filter(|(_, gone)| !**gone);
		kept.fold((0, 0), |(c, o), ((_, data), _)| (c + 1, o + data.len()))
	};
	match command {
		Command::Stat => {
			let (count, octets) = sizes(deleted);
			assert_eq!(response, &Response::Ok(format!("{count} {octets}")));
		}
		Command::List(None) | Command::Uidl(None) => {
			let by_size = matches!(command, Command::List(None));
			let mut want = Vec::new();
			for (i, (uid, data)) in account.inbox.iter().enumerate() {
				if !deleted[i] {
					let line = if by_size {
						line_for(i, data.len())
					} else {
						format!("{} {uid}\r\n", i + 1)
					};
					want.extend_from_slice(line.as_bytes());
				}
			}
			let Response::Multiline { body, .. } = response else {
				panic!("a listing did not answer with a body: {response:?}");
			};
			assert_eq!(
				body, &want,
				"listing shows other messages than the account's"
			);
		}
		Command::List(Some(n)) | Command::Uidl(Some(n)) => match live(*n) {
			Some(i) => {
				let (uid, data) = &account.inbox[i];
				let want = if matches!(command, Command::List(_)) {
					format!("{} {}", i + 1, data.len())
				} else {
					format!("{} {uid}", i + 1)
				};
				assert_eq!(response, &Response::Ok(want));
			}
			None => expect_err(response, "listing a message that is not there"),
		},
		Command::Retr(n) => match live(*n) {
			Some(i) => {
				let Response::Multiline { body, .. } = response else {
					panic!("RETR of a live message failed: {response:?}");
				};
				assert_eq!(body, &account.inbox[i].1, "RETR returned foreign bytes");
			}
			None => expect_err(response, "RETR of a message that is not there"),
		},
		Command::Top(n, _) => match live(*n) {
			Some(i) => {
				let Response::Multiline { body, .. } = response else {
					panic!("TOP of a live message failed: {response:?}");
				};
				assert!(account.inbox[i].1.starts_with(body), "TOP is not a prefix");
			}
			None => expect_err(response, "TOP of a message that is not there"),
		},
		Command::Dele(n) => match live(*n) {
			Some(i) => {
				assert!(
					matches!(response, Response::Ok(_)),
					"DELE refused: {response:?}"
				);
				deleted[i] = true;
			}
			None => expect_err(response, "DELE of a message that is not there"),
		},
		Command::Rset => {
			deleted.fill(false);
			let count = account.inbox.len();
			assert_eq!(response, &Response::Ok(format!("{count} messages")));
		}
		Command::Noop => assert_eq!(response, &Response::Ok(String::new())),
		Command::Capa => assert!(matches!(response, Response::Multiline { .. })),
		Command::Quit => assert!(matches!(response, Response::Bye(_))),
		Command::User(_) | Command::Pass(_) | Command::Auth { .. } => {
			expect_err(response, "a second sign-in");
		}
	}
}

/// Before sign-in: `USER` and `PASS` are the only way in, and the password
/// decides.
fn check_authorization(
	command: &Command,
	response: &Response,
	model: &mut Model,
	accounts: &[Account],
) {
	match command {
		Command::User(name) => {
			assert_eq!(response, &Response::Ok("send PASS".to_string()));
			model.pending = Pending::User(name.clone());
		}
		Command::Pass(pass) => {
			let expected = match &model.pending {
				Pending::No => Some(false),
				Pending::User(name) => {
					Some(accounts.iter().any(|a| a.name == name && a.secret == *pass))
				}
				Pending::Unknown => None,
			};
			match expected {
				Some(true) => assert!(
					matches!(response, Response::Ok(_)),
					"right password refused"
				),
				Some(false) => expect_err(response, "a wrong password was accepted"),
				None => {}
			}
			if !matches!(response, Response::Ok(_)) {
				model.pending = Pending::No;
			}
		}
		Command::Auth { .. } => model.pending = Pending::Unknown,
		Command::Capa => assert!(matches!(response, Response::Multiline { .. })),
		Command::Quit => assert!(matches!(response, Response::Bye(_))),
		_ => expect_err(response, "a mailbox command before sign-in"),
	}
}

fn run(data: &[u8]) {
	let mut u = Unstructured::new(data);
	let accounts = Rc::new(build_accounts(&mut u));
	let log = Rc::new(RefCell::new(Log::default()));
	let mut session = Session::new(Store {
		accounts: Rc::clone(&accounts),
		log: Rc::clone(&log),
	});
	let mut model = Model {
		signed_in: None,
		pending: Pending::No,
		awaiting_sasl: false,
		deleted: Vec::new(),
		logged_before: 0,
	};
	let mut quit = false;
	for _ in 0..MAX_STEPS {
		if u.is_empty() || quit {
			break;
		}
		let line = next_line(&mut u, &accounts);
		let was_sasl = std::mem::take(&mut model.awaiting_sasl);
		let command = if was_sasl { None } else { parse(&line).ok() };
		let response = session.handle_line(&line);
		check_framing(&response);
		model.awaiting_sasl = matches!(response, Response::Continuation);

		if command.is_none() && !was_sasl {
			assert_eq!(response, Response::Err("invalid command".to_string()));
		}
		if was_sasl {
			model.pending = Pending::Unknown;
		}
		match (model.signed_in, command.as_ref()) {
			(Some(i), Some(command)) => {
				check_transaction(command, &response, &accounts[i], &mut model.deleted);
				quit = matches!(command, Command::Quit);
			}
			(None, Some(command)) => {
				check_authorization(command, &response, &mut model, &accounts);
				quit = matches!(command, Command::Quit);
			}
			(_, None) => {}
		}

		// Signing in is the one transition, and only a matching password
		// makes it.
		let now = session.is_authenticated();
		assert!(
			model.signed_in.is_none() || now,
			"the session signed itself out"
		);
		if now && model.signed_in.is_none() {
			let log = log.borrow();
			assert!(
				log.verified.len() > model.logged_before,
				"signed in without a match"
			);
			let name = log.verified.last().unwrap();
			let index = accounts.iter().position(|a| a.name == name).unwrap();
			model.signed_in = Some(index);
			model.deleted = vec![false; accounts[index].inbox.len()];
		}
		model.logged_before = log.borrow().verified.len();

		let log = log.borrow();
		match model.signed_in {
			None => assert!(
				log.listed.is_empty() && log.fetched.is_empty() && log.removed.is_empty(),
				"the store was read or changed before sign-in"
			),
			Some(i) => {
				let name = accounts[i].name;
				assert!(
					log.listed.iter().all(|a| a == name),
					"another mailbox was listed"
				);
				for (account, uid) in &log.fetched {
					assert!(account == name && uid.starts_with(name), "foreign fetch");
				}
				assert!(log.removed.is_empty() || quit, "removal before QUIT");
			}
		}
	}
	if quit {
		let log = log.borrow();
		let want: Vec<String> = match model.signed_in {
			Some(i) => accounts[i]
				.inbox
				.iter()
				.zip(&model.deleted)
				.filter(|(_, d)| **d)
				.map(|((uid, _), _)| uid.clone())
				.collect(),
			None => Vec::new(),
		};
		match (model.signed_in, want.is_empty()) {
			(_, true) => assert!(log.removed.is_empty(), "removed what was never deleted"),
			(Some(i), false) => {
				assert_eq!(log.removed, vec![(accounts[i].name.to_string(), want)]);
			}
			(None, false) => unreachable!(),
		}
	}
}

fuzz_target!(|data: &[u8]| run(data));
