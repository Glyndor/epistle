//! What the client knows about the connection: whether it greeted, who it
//! signed in as, and the transaction it built. Every reply is held against
//! it.

use libfuzzer_sys::arbitrary::Unstructured;

use epistle::smtp::session::{Action, Session};

use crate::accounts::{Account, DOMAIN, which};
use crate::client::{self, Step};

/// The mail transaction as the client built it.
#[derive(Default)]
pub struct Transaction {
	pub mail: Option<String>,
	pub recipients: Vec<String>,
	/// The body sent through BDAT so far.
	chunks: Vec<u8>,
}

pub struct Model<'a> {
	accounts: &'a [Account],
	greeted: bool,
	account: Option<usize>,
	pub transaction: Transaction,
	/// The credentials the last client line offered.
	offered: Option<(String, String)>,
	/// The user name of an AUTH LOGIN exchange in progress.
	login_user: Option<String>,
}

/// The account an address names, by its local part without a `+` detail,
/// when it is in the served domain.
fn owner(accounts: &[Account], address: &str) -> Option<usize> {
	let (local, domain) = address.rsplit_once('@')?;
	if !domain.eq_ignore_ascii_case(DOMAIN) {
		return None;
	}
	let base = local.split('+').next().unwrap_or(local);
	accounts
		.iter()
		.position(|a| base.eq_ignore_ascii_case(a.name))
}

/// The path between the angle brackets of a MAIL or RCPT line.
fn path(line: &str) -> &str {
	let open = line.find('<').map_or(0, |i| i + 1);
	let close = line.rfind('>').unwrap_or(line.len()).max(open);
	&line[open..close]
}

/// An address as the session spells it: in lower case, local part and
/// domain alike, whatever case the client wrote it in.
fn spelled(address: &str) -> String {
	address.to_lowercase()
}

impl<'a> Model<'a> {
	/// STARTTLS took effect: the client greets again, and nothing of the
	/// plaintext transaction survives.
	pub fn tls_started(&mut self) {
		self.greeted = false;
		self.transaction = Transaction::default();
	}

	pub fn new(accounts: &'a [Account]) -> Self {
		Model {
			accounts,
			greeted: false,
			account: None,
			transaction: Transaction::default(),
			offered: None,
			login_user: None,
		}
	}

	fn positive(action: &Action) -> bool {
		matches!(action, Action::Continue(r) if r.code() == 250)
	}

	pub fn command(&mut self, step: &Step, action: &Action) {
		self.offered = step.login.clone();
		self.login_user = step.user.clone();
		assert!(
			!matches!(action, Action::Deliver(..)),
			"a command handed over a message"
		);
		let verb = step
			.line
			.split([' ', ':'])
			.next()
			.unwrap_or("")
			.to_ascii_uppercase();
		match verb.as_str() {
			"EHLO" | "HELO" if Self::positive(action) => {
				self.greeted = true;
				self.transaction = Transaction::default();
			}
			"RSET" if Self::positive(action) => self.transaction = Transaction::default(),
			"MAIL" if Self::positive(action) => self.mail(path(&step.line)),
			"RCPT" if Self::positive(action) => self.recipient(path(&step.line)),
			"DATA" if matches!(action, Action::CollectData(_)) => {
				assert!(
					self.transaction.mail.is_some() && !self.transaction.recipients.is_empty(),
					"DATA opened without a sender and a recipient"
				);
			}
			"BDAT" => match action {
				Action::CollectChunk { .. } => assert!(
					self.transaction.mail.is_some() && !self.transaction.recipients.is_empty(),
					"BDAT read without a sender and a recipient"
				),
				// A refused chunk ends the transaction.
				Action::DiscardChunk { .. } => self.transaction = Transaction::default(),
				_ => {}
			},
			_ => {}
		}
	}

	fn mail(&mut self, path: &str) {
		assert!(self.greeted, "MAIL accepted before a greeting");
		assert!(
			self.transaction.mail.is_none(),
			"a second MAIL in one transaction"
		);
		if let Some(me) = self.account {
			assert!(
				owner(self.accounts, path) == Some(me),
				"a signed-in account sent as an address it does not own"
			);
		}
		self.transaction = Transaction {
			mail: Some(path.to_string()),
			..Transaction::default()
		};
	}

	fn recipient(&mut self, path: &str) {
		assert!(
			self.transaction.mail.is_some(),
			"RCPT accepted without MAIL"
		);
		if self.account.is_none() {
			assert!(
				owner(self.accounts, path).is_some(),
				"relayed for a stranger"
			);
		}
		assert!(
			self.transaction.recipients.len() < 4,
			"more recipients than the limit"
		);
		self.transaction.recipients.push(spelled(path));
	}

	/// DATA lines until the lone dot, then the message is checked against
	/// what was sent.
	pub fn data(&mut self, u: &mut Unstructured, session: &mut Session) -> Action {
		let mut body = Vec::new();
		let mut size = 0usize;
		loop {
			let line = if u.is_empty() {
				b".".to_vec()
			} else {
				client::data_line(u)
			};
			if let Some(action) = session.data_line(&line) {
				assert_eq!(line, b".", "DATA ended before the lone dot");
				self.handed_over(&body, size, &action);
				return action;
			}
			let content = line.strip_prefix(b".").unwrap_or(&line);
			size += content.len() + 2;
			body.extend_from_slice(content);
			body.extend_from_slice(b"\r\n");
		}
	}

	pub fn chunk(&mut self, bytes: &[u8], last: bool, action: &Action) {
		self.transaction.chunks.extend_from_slice(bytes);
		match action {
			Action::Close(_) => {}
			_ if last => {
				let body = std::mem::take(&mut self.transaction.chunks);
				self.handed_over(&body, body.len(), action);
			}
			_ => assert!(
				!matches!(action, Action::Deliver(..)),
				"a message was handed over before its last chunk"
			),
		}
	}

	/// The end of a message: handed over exactly as sent, or refused with
	/// a reason that applies.
	fn handed_over(&mut self, body: &[u8], size: usize, action: &Action) {
		let transaction = std::mem::take(&mut self.transaction);
		match action {
			Action::Deliver(_, message) => {
				assert!(size <= crate::MAX_SIZE, "an oversized message was accepted");
				assert!(
					Some(&message.reverse_path) == transaction.mail.as_ref(),
					"the sender handed over is not the one accepted"
				);
				assert!(
					message.recipients == transaction.recipients,
					"the recipients handed over are not the ones accepted"
				);
				assert!(
					message.data == body,
					"the body handed over is not the one sent"
				);
				if let Some(me) = self.account {
					// Only the header section names the author: a From line
					// after the first empty line is body text.
					let other = &self.accounts[1 - me];
					let forged = format!("\r\nFrom: {}@{DOMAIN}\r\n", other.name);
					let mut header = b"\r\n".to_vec();
					let end = match body.starts_with(b"\r\n") {
						true => 0,
						false => body
							.windows(4)
							.position(|w| w == b"\r\n\r\n")
							.map_or(body.len(), |at| at + 2),
					};
					header.extend_from_slice(&body[..end]);
					assert!(
						!header.windows(forged.len()).any(|w| w == forged.as_bytes()),
						"a signed-in account sent mail from the other's address"
					);
				}
			}
			// Unsigned mail within the size limit has nothing left to fail.
			_ if self.account.is_none() && size <= crate::MAX_SIZE => {
				panic!("a valid message was refused")
			}
			_ => {}
		}
	}

	/// A line answering a 334 challenge.
	pub fn auth_reply(&mut self, u: &mut Unstructured, session: &mut Session) -> Action {
		let (line, login, half) = client::auth_reply(u, self.accounts);
		self.offered = login.or_else(|| match (self.login_user.take(), half) {
			(Some(user), Some(pass)) => Some((user, pass)),
			(None, half) => {
				self.login_user = half;
				None
			}
			_ => None,
		});
		session.auth_line(&line)
	}

	/// Signing in is the one transition, and only a matching password makes
	/// it, as the account the password belongs to.
	pub fn signed_in(&mut self, session: &Session) {
		let now = session.authenticated().map(str::to_string);
		match (self.account, now) {
			(Some(me), now) => assert!(
				now.as_deref() == Some(self.accounts[me].name),
				"the session changed who it is signed in as"
			),
			(None, Some(name)) => {
				let me = self.offered.as_ref().and_then(|l| which(self.accounts, l));
				assert!(me.is_some(), "signed in without a matching password");
				assert!(
					self.accounts[me.unwrap_or(0)].name == name,
					"signed in as someone else"
				);
				self.account = me;
			}
			(None, None) => {}
		}
		self.offered = None;
	}
}
