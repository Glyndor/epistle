//! What the client sends next: a well-formed command most of the time, with
//! names, sets and flags biased toward the ones that exist, and raw bytes the
//! rest.

use libfuzzer_sys::arbitrary::Unstructured;

use crate::accounts::{Account, DOMAIN, base64, hex};

/// Where a command may run, as far as the checks care.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
	/// Valid in every state and touches no mailbox.
	AnyState,
	/// LOGIN or AUTHENTICATE.
	SignIn,
	/// Needs a signed-in account; before that it must be refused.
	Mailbox,
	/// Bytes the generator did not shape: no expectation but the framing.
	Raw,
}

pub struct Step {
	pub line: String,
	pub tag: Option<String>,
	pub kind: Kind,
	/// The user name and password this line offers, when it offers both.
	pub login: Option<(String, String)>,
	/// The literal an APPEND announces, sent when the session asks for it.
	pub literal: Option<Vec<u8>>,
}

/// Bytes from the input as one line: the connection splits at CRLF, so a
/// line the session sees never holds CR or LF.
fn text(u: &mut Unstructured, max: usize) -> String {
	let len = u.int_in_range(0..=max).unwrap_or(0);
	String::from_utf8_lossy(u.bytes(len).unwrap_or(&[])).replace(['\r', '\n'], " ")
}

fn pick<'a>(u: &mut Unstructured, from: &[&'a str]) -> &'a str {
	from[u.choose_index(from.len()).unwrap_or(0)]
}

/// A user name: an account, its address, a neighbour's, or noise.
pub fn name(u: &mut Unstructured, accounts: &[Account]) -> String {
	let account = &accounts[usize::from(u.arbitrary::<bool>().unwrap_or(false))];
	match u.int_in_range(0..=7).unwrap_or(0) {
		0..=4 => account.name.to_string(),
		5 => format!("{}@{DOMAIN}", account.name),
		6 => "nobody".to_string(),
		_ => text(u, 8),
	}
}

pub fn secret(u: &mut Unstructured, accounts: &[Account]) -> String {
	match u.int_in_range(0..=3).unwrap_or(0) {
		0 => accounts[0].secret.clone(),
		1 => accounts[1].secret.clone(),
		2 => text(u, 16),
		_ => hex(u, 8),
	}
}

/// A mailbox name: one that exists, one that could, one that belongs to the
/// neighbour, or one that tries to leave the account.
fn mailbox(u: &mut Unstructured, accounts: &[Account]) -> String {
	match u.int_in_range(0..=10).unwrap_or(0) {
		0..=2 => "INBOX".to_string(),
		3 => format!("{}-Box", accounts[0].marker),
		4 => format!("{}-Box", accounts[1].marker),
		5 => pick(u, &["Work", "Work/Sub", "Trash", "Sent"]).to_string(),
		6 => format!("../{}/INBOX", accounts[1].name),
		7 => format!("Other Users/{}/INBOX", accounts[1].name),
		8 => pick(u, &["..", ".", "/", "INBOX/..", "~", "%", "*"]).to_string(),
		_ => text(u, 12),
	}
}

fn quoted(name: &str) -> String {
	format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
}

fn set(u: &mut Unstructured) -> String {
	let a = u.int_in_range(1..=6).unwrap_or(1);
	match u.int_in_range(0..=5).unwrap_or(0) {
		0 | 1 => a.to_string(),
		2 => format!("{a}:*"),
		3 => "1:*".to_string(),
		4 => format!("{a},{}", u.int_in_range(1..=6).unwrap_or(1)),
		_ => "$".to_string(),
	}
}

fn flags(u: &mut Unstructured) -> String {
	const ALL: [&str; 7] = [
		"\\Seen",
		"\\Deleted",
		"\\Flagged",
		"\\Answered",
		"\\Draft",
		"$Junk",
		"Kw1",
	];
	let count = u.int_in_range(0..=3).unwrap_or(0);
	let picked: Vec<&str> = (0..count).map(|_| pick(u, &ALL)).collect();
	format!("({})", picked.join(" "))
}

fn fetch_items(u: &mut Unstructured) -> &'static str {
	pick(
		u,
		&[
			"FLAGS",
			"(UID FLAGS RFC822.SIZE)",
			"BODY[]",
			"BODY.PEEK[]",
			"BODY.PEEK[HEADER.FIELDS (SUBJECT)]",
			"(ENVELOPE BODYSTRUCTURE INTERNALDATE)",
			"RFC822",
			"BINARY.PEEK[1]",
			"(FLAGS MODSEQ)",
		],
	)
}

fn message(u: &mut Unstructured) -> Vec<u8> {
	let mut body = match u.int_in_range(0..=2).unwrap_or(0) {
		0 => b"Subject: appended\r\n\r\n".to_vec(),
		1 => b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nx\r\n--b--\r\n".to_vec(),
		_ => Vec::new(),
	};
	let extra = u.int_in_range(0..=64).unwrap_or(0);
	body.extend_from_slice(u.bytes(extra).unwrap_or(&[]));
	body
}

/// What `command` builds: the command line, its kind, and the two optional
/// parts the checks need.
type Built = (String, Kind, Option<(String, String)>, Option<Vec<u8>>);

/// The verb and arguments of a command, with what the checks need to know.
fn command(u: &mut Unstructured, accounts: &[Account]) -> Built {
	use Kind::{AnyState, Mailbox, SignIn};
	let mb = |u: &mut Unstructured| quoted(&mailbox(u, accounts));
	let uid = |u: &mut Unstructured| {
		if u.arbitrary::<bool>().unwrap_or(false) {
			"UID "
		} else {
			""
		}
	};
	let (verb, kind) = match u.int_in_range(0..=42).unwrap_or(0) {
		0 | 1 => {
			let (n, p) = (name(u, accounts), secret(u, accounts));
			let line = format!("LOGIN {} {}", quoted(&n), quoted(&p));
			return (line, SignIn, Some((n, p)), None);
		}
		2 => {
			let (n, p) = (name(u, accounts), secret(u, accounts));
			// An authorization identity other than the user is refused, so
			// such a line offers nothing that can sign in.
			let foreign = u.int_in_range(0..=5).unwrap_or(0) == 0;
			let authz = if foreign { "nobody" } else { "" };
			let ir = base64(format!("{authz}\0{n}\0{p}").as_bytes());
			let login = (!foreign).then_some((n, p));
			return (format!("AUTHENTICATE PLAIN {ir}"), SignIn, login, None);
		}
		3 => (
			format!(
				"AUTHENTICATE {}",
				pick(
					u,
					&["PLAIN", "LOGIN", "SCRAM-SHA-256", "EXTERNAL", "XOAUTH2"]
				)
			),
			SignIn,
		),
		4 => (
			pick(
				u,
				&[
					"CAPABILITY",
					"NOOP",
					"ID NIL",
					"STARTTLS",
					"COMPRESS DEFLATE",
				],
			)
			.to_string(),
			AnyState,
		),
		5 => ("LOGOUT".to_string(), AnyState),
		6 | 7 => (format!("SELECT {}", mb(u)), Mailbox),
		8 => (format!("EXAMINE {}", mb(u)), Mailbox),
		9 => (format!("CREATE {}", mb(u)), Mailbox),
		10 => (format!("DELETE {}", mb(u)), Mailbox),
		11 => (format!("RENAME {} {}", mb(u), mb(u)), Mailbox),
		12 => (
			format!(
				"LIST \"\" {}",
				quoted(pick(u, &["*", "%", "INBOX*", "Other Users/*"]))
			),
			Mailbox,
		),
		13 => (
			format!("STATUS {} (MESSAGES UIDNEXT UNSEEN SIZE)", mb(u)),
			Mailbox,
		),
		14 | 15 => {
			let body = message(u);
			let sync = if u.arbitrary::<bool>().unwrap_or(false) {
				"+"
			} else {
				""
			};
			let line = format!("APPEND {} {} {{{}{sync}}}", mb(u), flags(u), body.len());
			return (line, Mailbox, None, Some(body));
		}
		16 | 17 | 39 | 40 => (
			format!("{}FETCH {} {}", uid(u), set(u), fetch_items(u)),
			Mailbox,
		),
		18 | 19 => {
			let mode = pick(u, &["+FLAGS", "-FLAGS", "FLAGS", "+FLAGS.SILENT"]);
			(
				format!("{}STORE {} {mode} {}", uid(u), set(u), flags(u)),
				Mailbox,
			)
		}
		20 => (format!("{}COPY {} {}", uid(u), set(u), mb(u)), Mailbox),
		21 => (format!("{}MOVE {} {}", uid(u), set(u), mb(u)), Mailbox),
		22 => (
			pick(u, &["EXPUNGE", "CLOSE", "UNSELECT", "CHECK"]).to_string(),
			Mailbox,
		),
		23 => (format!("UID EXPUNGE {}", set(u)), Mailbox),
		24 => {
			let key = pick(
				u,
				&[
					"ALL",
					"UNSEEN",
					"DELETED",
					"TEXT Mark",
					"RETURN (SAVE) ALL",
					"RETURN (MIN MAX COUNT) ALL",
				],
			);
			(format!("{}SEARCH {key}", uid(u)), Mailbox)
		}
		25 => (
			pick(
				u,
				&[
					"SORT (DATE) UTF-8 ALL",
					"THREAD REFERENCES UTF-8 ALL",
					"THREAD ORDEREDSUBJECT UTF-8 ALL",
				],
			)
			.to_string(),
			Mailbox,
		),
		26 => (
			format!("{} {}", pick(u, &["SUBSCRIBE", "UNSUBSCRIBE"]), mb(u)),
			Mailbox,
		),
		27 => ("LSUB \"\" \"*\"".to_string(), Mailbox),
		28 => (
			format!("{} {}", pick(u, &["GETACL", "MYRIGHTS"]), mb(u)),
			Mailbox,
		),
		29 => {
			let who = pick(u, &[accounts[0].name, accounts[1].name, "anyone"]);
			(
				format!(
					"SETACL {} {who} {}",
					mb(u),
					pick(u, &["lrs", "+w", "-l", "lrswipkxtea"])
				),
				Mailbox,
			)
		}
		30 => (format!("DELETEACL {} {}", mb(u), accounts[1].name), Mailbox),
		31 => (
			format!(
				"GETMETADATA {} {}",
				mb(u),
				pick(
					u,
					&[
						"/private/comment",
						"/shared/comment",
						"(/private/comment /shared/comment)"
					]
				)
			),
			Mailbox,
		),
		32 => (
			format!(
				"SETMETADATA {} (/private/comment {})",
				mb(u),
				quoted(&text(u, 12))
			),
			Mailbox,
		),
		33 => (
			pick(u, &["GETQUOTAROOT INBOX", "GETQUOTA \"\"", "NAMESPACE"]).to_string(),
			Mailbox,
		),
		34 => (
			format!(
				"ENABLE {}",
				pick(
					u,
					&[
						"CONDSTORE",
						"QRESYNC",
						"UIDONLY",
						"IMAP4rev2",
						"UTF8=ACCEPT"
					]
				)
			),
			Mailbox,
		),
		35 => ("IDLE".to_string(), Mailbox),
		36 => (
			format!("ESEARCH IN (personal) {}", pick(u, &["ALL", "TEXT Mark"])),
			Mailbox,
		),
		37 => (
			"NOTIFY SET (selected (MessageNew MessageExpunge))".to_string(),
			Mailbox,
		),
		41 => (text(u, 24), Kind::Raw),
		_ => (format!("{}FETCH 1:* BODY.PEEK[]", uid(u)), Mailbox),
	};
	(verb, kind, None, None)
}

pub fn next(u: &mut Unstructured, accounts: &[Account], counter: usize) -> Step {
	if u.int_in_range(0..=15).unwrap_or(0) == 0 {
		return Step {
			line: text(u, 48),
			tag: None,
			kind: Kind::Raw,
			login: None,
			literal: None,
		};
	}
	let tag = format!("t{counter}");
	let (rest, kind, login, literal) = command(u, accounts);
	Step {
		line: format!("{tag} {rest}"),
		tag: Some(tag),
		kind,
		login,
		literal,
	}
}

/// A line sent in answer to a SASL continuation: credentials for PLAIN, one
/// half of them for LOGIN, a cancel, or noise. Returns the user name or the
/// password it carries, so the model can follow a LOGIN exchange.
pub fn sasl_reply(
	u: &mut Unstructured,
	accounts: &[Account],
) -> (String, Option<(String, String)>, Option<String>) {
	match u.int_in_range(0..=4).unwrap_or(0) {
		0 | 1 => {
			let (n, p) = (name(u, accounts), secret(u, accounts));
			let line = base64(format!("\0{n}\0{p}").as_bytes());
			(line, Some((n, p)), None)
		}
		2 => {
			let half = if u.arbitrary::<bool>().unwrap_or(false) {
				name(u, accounts)
			} else {
				secret(u, accounts)
			};
			(base64(half.as_bytes()), None, Some(half))
		}
		3 => ("*".to_string(), None, None),
		_ => (text(u, 24), None, None),
	}
}

/// The first lines of a run. Signing in by chance costs the fuzzer most of
/// its time, so most runs start signed in, through the same LOGIN a client
/// sends and under the same checks, and many with a mailbox selected, the
/// neighbour's names among the candidates.
pub fn prelude(u: &mut Unstructured, accounts: &[Account]) -> Vec<Step> {
	let choice = u.int_in_range(0..=5).unwrap_or(0);
	if choice == 0 {
		return Vec::new();
	}
	let account = &accounts[usize::from(choice % 2 == 0)];
	let login = (account.name.to_string(), account.secret.clone());
	let mut steps = vec![Step {
		line: format!("p0 LOGIN {} {}", quoted(&login.0), quoted(&login.1)),
		tag: Some("p0".to_string()),
		kind: Kind::SignIn,
		login: Some(login),
		literal: None,
	}];
	if choice > 2 {
		let verb = if choice == 5 { "EXAMINE" } else { "SELECT" };
		let target = match u.arbitrary::<bool>().unwrap_or(true) {
			true => "INBOX".to_string(),
			false => quoted(&mailbox(u, accounts)),
		};
		steps.push(Step {
			line: format!("p1 {verb} {target}"),
			tag: Some("p1".to_string()),
			kind: Kind::Mailbox,
			login: None,
			literal: None,
		});
	}
	steps
}
