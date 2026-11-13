//! What the client sends next: SMTP commands with addresses and sizes biased
//! toward the ones the checks care about, data lines that need
//! dot-unstuffing, BDAT chunks, and raw bytes.

use libfuzzer_sys::arbitrary::Unstructured;

use crate::accounts::{Account, DOMAIN, base64, hex};

/// One line the client sends, and what the model needs to know about it.
pub struct Step {
	pub line: String,
	/// The user name and password this line offers, when it offers both.
	pub login: Option<(String, String)>,
	/// The user name an AUTH LOGIN line carries, whose password follows.
	pub user: Option<String>,
}

fn text(u: &mut Unstructured, max: usize) -> String {
	let len = u.int_in_range(0..=max).unwrap_or(0);
	String::from_utf8_lossy(u.bytes(len).unwrap_or(&[])).replace(['\r', '\n'], " ")
}

fn pick<'a>(u: &mut Unstructured, from: &[&'a str]) -> &'a str {
	from[u.choose_index(from.len()).unwrap_or(0)]
}

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

/// An address: a local account (plain, sub-addressed or in another case), a
/// local user that does not exist, or a domain this server does not serve.
pub fn address(u: &mut Unstructured, accounts: &[Account]) -> String {
	let local = match u.int_in_range(0..=6).unwrap_or(0) {
		0 | 1 => accounts[0].name.to_string(),
		2 | 3 => accounts[1].name.to_string(),
		4 => format!(
			"{}+tag",
			accounts[usize::from(u.arbitrary::<bool>().unwrap_or(false))].name
		),
		5 => "nobody".to_string(),
		_ => text(u, 8),
	};
	let domain = pick(
		u,
		&[
			DOMAIN,
			DOMAIN,
			"EXAMPLE.org",
			"other.test",
			"example.org.evil.test",
		],
	);
	format!("{local}@{domain}")
}

/// A command line. Returns the line and the credentials it offers.
pub fn command(u: &mut Unstructured, accounts: &[Account]) -> Step {
	let line = match u.int_in_range(0..=27).unwrap_or(0) {
		0 | 1 => format!("EHLO {}", pick(u, &["client.test", "[192.0.2.1]", "x"])),
		2 => "HELO client.test".to_string(),
		3..=5 => {
			let path = match u.int_in_range(0..=5).unwrap_or(0) {
				0 => String::new(),
				_ => address(u, accounts),
			};
			let params = pick(
				u,
				&[
					"",
					" SIZE=100",
					" SIZE=99999999",
					" REQUIRETLS",
					" BODY=8BITMIME",
				],
			);
			format!("MAIL FROM:<{path}>{params}")
		}
		6..=9 => {
			let params = pick(u, &["", "", " NOTIFY=NEVER", " NOTIFY=SUCCESS,FAILURE"]);
			format!("RCPT TO:<{}>{params}", address(u, accounts))
		}
		10 | 11 => "DATA".to_string(),
		12 | 13 => {
			let size = u.int_in_range(0..=48).unwrap_or(0);
			let last = if u.arbitrary::<bool>().unwrap_or(true) {
				" LAST"
			} else {
				""
			};
			format!("BDAT {size}{last}")
		}
		14 => "RSET".to_string(),
		15 => pick(u, &["NOOP", "VRFY acct-a", "STARTTLS", "HELP"]).to_string(),
		16 => "QUIT".to_string(),
		17..=19 => {
			let (n, p) = (name(u, accounts), secret(u, accounts));
			let ir = base64(format!("\0{n}\0{p}").as_bytes());
			return Step {
				line: format!("AUTH PLAIN {ir}"),
				login: Some((n, p)),
				user: None,
			};
		}
		20 => pick(
			u,
			&[
				"AUTH PLAIN",
				"AUTH LOGIN",
				"AUTH SCRAM-SHA-256",
				"AUTH CRAM-MD5",
			],
		)
		.to_string(),
		21 => {
			let user = name(u, accounts);
			// An empty user name travels as `=` (RFC 4954): the base64 of
			// nothing leaves a bare `AUTH LOGIN`, where the server asks for
			// the name and the model would already hold it.
			let initial = match user.is_empty() {
				true => "=".to_string(),
				false => base64(user.as_bytes()),
			};
			return Step {
				line: format!("AUTH LOGIN {initial}"),
				login: None,
				user: Some(user),
			};
		}
		_ => text(u, 32),
	};
	Step {
		line,
		login: None,
		user: None,
	}
}

/// A line answering a 334 challenge: PLAIN credentials, one half of LOGIN,
/// a cancel, or noise. Returns the line, the credentials when it carries
/// both, and the single value when it carries one.
pub fn auth_reply(
	u: &mut Unstructured,
	accounts: &[Account],
) -> (String, Option<(String, String)>, Option<String>) {
	match u.int_in_range(0..=4).unwrap_or(0) {
		0 | 1 => {
			let (n, p) = (name(u, accounts), secret(u, accounts));
			(base64(format!("\0{n}\0{p}").as_bytes()), Some((n, p)), None)
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

/// A line of message data, as it travels: a line that starts with a dot
/// carries an extra one, and a lone dot ends the message.
pub fn data_line(u: &mut Unstructured) -> Vec<u8> {
	match u.int_in_range(0..=9).unwrap_or(0) {
		0 => b".".to_vec(),
		1 => b"..".to_vec(),
		2 => b"..hidden".to_vec(),
		3 => b"Subject: fuzz".to_vec(),
		// The author of the message, which a signed-in sender must own.
		4 if u.arbitrary::<bool>().unwrap_or(false) => {
			format!("From: {}@{DOMAIN}", crate::accounts::NAMES[0]).into_bytes()
		}
		4 => format!("From: {}@{DOMAIN}", crate::accounts::NAMES[1]).into_bytes(),
		5 => Vec::new(),
		_ => {
			let len = u.int_in_range(0..=40).unwrap_or(0);
			let mut line = u.bytes(len).map(<[u8]>::to_vec).unwrap_or_default();
			line.retain(|b| *b != b'\r' && *b != b'\n');
			line
		}
	}
}

/// The bytes of a BDAT chunk of `size` octets: CRLF-framed lines most of
/// the time, since a chunk that breaks the framing closes the connection,
/// and raw input the rest.
pub fn chunk(u: &mut Unstructured, size: usize) -> Vec<u8> {
	if u.int_in_range(0..=7).unwrap_or(0) == 0 {
		let mut raw = u
			.bytes(size.min(u.len()))
			.map(<[u8]>::to_vec)
			.unwrap_or_default();
		raw.resize(size, b'x');
		return raw;
	}
	let mut out: Vec<u8> = b"Subject: chunk\r\n"
		.iter()
		.copied()
		.cycle()
		.take(size)
		.collect();
	if size >= 2 {
		out[size - 2..].copy_from_slice(b"\r\n");
	}
	out
}

fn step(line: String) -> Step {
	Step {
		line,
		login: None,
		user: None,
	}
}

/// The first lines of a run. Reaching a message by chance takes a greeting,
/// a sender, a recipient and a body in order, which a short input rarely
/// spells, so most runs start part of the way there, through the same
/// commands and under the same checks.
pub fn prelude(u: &mut Unstructured, accounts: &[Account]) -> Vec<Step> {
	let choice = u.int_in_range(0..=5).unwrap_or(0);
	if choice == 0 {
		return Vec::new();
	}
	let mut steps = vec![step("EHLO client.test".to_string())];
	let signed = matches!(choice, 2 | 3 | 5).then(|| &accounts[usize::from(choice == 3)]);
	if let Some(account) = signed {
		let login = (account.name.to_string(), account.secret.clone());
		let ir = base64(format!("\0{}\0{}", login.0, login.1).as_bytes());
		steps.push(Step {
			line: format!("AUTH PLAIN {ir}"),
			login: Some(login),
			user: None,
		});
	}
	if choice >= 4 {
		let from = match signed {
			Some(account) => format!("{}@{DOMAIN}", account.name),
			None => address(u, accounts),
		};
		steps.push(step(format!("MAIL FROM:<{from}>")));
		steps.push(step(format!("RCPT TO:<{}>", address(u, accounts))));
	}
	steps
}
