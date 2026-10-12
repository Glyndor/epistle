//! UTF-8 mailbox names for clients that asked for them.
//!
//! Folders are stored under their modified UTF-7 spelling (see
//! [`crate::util::mutf7`]). A client that enabled `UTF8=ACCEPT` (RFC 6855)
//! or IMAP4rev2 (whose mailbox names are Net-Unicode, RFC 9051 §5.1) sends
//! and receives the decoded names instead: its arguments are encoded on the
//! way in, and every name the server echoes is decoded on the way out. Any
//! other client keeps the stored spelling in both directions.

use std::borrow::Cow;

use super::super::command::{Command, SearchScope};
use super::Session;
use crate::util::mutf7;

impl Session {
	/// Whether mailbox names cross the wire as UTF-8 on this connection.
	pub(super) fn utf8_names(&self) -> bool {
		self.utf8_accept || self.imap4rev2
	}

	/// How a stored mailbox name is spelled on this connection.
	pub(super) fn wire_name<'a>(&self, stored: &'a str) -> Cow<'a, str> {
		if self.utf8_names()
			&& let Some(decoded) = mutf7::decode(stored)
		{
			return Cow::Owned(decoded);
		}
		Cow::Borrowed(stored)
	}

	/// A stored mailbox name as the astring a response carries: spelled
	/// for this connection by [`Self::wire_name`], then quoted.
	pub(super) fn mailbox_astring(&self, stored: &str) -> String {
		astring(&self.wire_name(stored), self.utf8_names())
	}
}

/// `value` as an IMAP string (RFC 9051 §4.3): quoted, with `"` and `\`
/// escaped, unless it holds a character a quoted string cannot carry (CR,
/// LF, or 8-bit without UTF-8 on the connection), which needs a literal.
pub(super) fn astring(value: &str, utf8: bool) -> String {
	let quotable = value
		.chars()
		.all(|c| !matches!(c, '\r' | '\n') && (utf8 || c.is_ascii()));
	if !quotable {
		return format!("{{{}}}\r\n{value}", value.len());
	}
	let mut quoted = String::with_capacity(value.len() + 2);
	quoted.push('"');
	for c in value.chars() {
		if matches!(c, '"' | '\\') {
			quoted.push('\\');
		}
		quoted.push(c);
	}
	quoted.push('"');
	quoted
}

/// Rewrite the UTF-8 mailbox names in a command into their stored spelling.
/// List patterns are encoded too: the wildcards are ASCII and survive as is.
pub(super) fn to_stored_names(command: &mut Command) {
	fn encode(name: &mut String) {
		*name = mutf7::encode(name);
	}
	match command {
		Command::List {
			reference, pattern, ..
		}
		| Command::Lsub { reference, pattern } => {
			encode(reference);
			encode(pattern);
		}
		Command::Rename { from, to } => {
			encode(from);
			encode(to);
		}
		Command::Select { mailbox, .. }
		| Command::Examine { mailbox, .. }
		| Command::GetQuotaRoot { mailbox }
		| Command::Create { mailbox }
		| Command::Delete { mailbox }
		| Command::Append { mailbox, .. }
		| Command::Replace { mailbox, .. }
		| Command::Copy { mailbox, .. }
		| Command::Status { mailbox, .. }
		| Command::Subscribe { mailbox }
		| Command::Unsubscribe { mailbox }
		| Command::SetAcl { mailbox, .. }
		| Command::DeleteAcl { mailbox, .. }
		| Command::GetAcl { mailbox }
		| Command::ListRights { mailbox, .. }
		| Command::MyRights { mailbox }
		| Command::GetMetadata { mailbox, .. }
		| Command::SetMetadata { mailbox, .. } => encode(mailbox),
		Command::Esearch { sources, .. } => {
			for scope in sources {
				if let SearchScope::Subtree(names)
				| SearchScope::SubtreeOne(names)
				| SearchScope::Mailboxes(names) = scope
				{
					names.iter_mut().for_each(encode);
				}
			}
		}
		_ => {}
	}
}
