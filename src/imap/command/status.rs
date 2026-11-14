//! The STATUS command and the mailbox counters it asks for (RFC 9051
//! §6.3.10), also reported inline by LIST-STATUS (RFC 5819).

use super::parse::parse_astring;
use super::{Command, ParseError};

/// Items that can be requested in a STATUS command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusItem {
	/// Total number of messages in the mailbox.
	Messages,
	/// Number of messages with the `\Recent` flag.
	Recent,
	/// The next UID to be assigned.
	Uidnext,
	/// The mailbox's UID validity value (RFC 9051 §2.3.1.1).
	Uidvalidity,
	/// Number of messages without the `\Seen` flag.
	Unseen,
	/// `SIZE` (RFC 8438): total octets of all messages in the mailbox.
	Size,
	/// `DELETED`: count of messages flagged `\Deleted` (RFC 9051).
	Deleted,
	/// `MAILBOXID`: the mailbox's stable object id (OBJECTID, RFC 8474).
	MailboxId,
	/// `HIGHESTMODSEQ`: the mailbox's highest mod-sequence (RFC 7162 §3.1.6).
	HighestModseq,
	/// `APPENDLIMIT` (RFC 7889 §4): the largest message, in octets, an
	/// APPEND to the mailbox may carry.
	AppendLimit,
}

/// Parse `STATUS <mailbox> (<items>...)`: the mailbox-level counters.
pub(super) fn parse_status(tag: &str, args: &str) -> Result<Command, ParseError> {
	let bad = || ParseError::BadArguments(tag.to_string());
	let (mailbox, rest) = parse_astring(args).ok_or_else(bad)?;
	if mailbox.is_empty() {
		return Err(bad());
	}
	let rest = rest.trim();
	let inner = rest
		.strip_prefix('(')
		.and_then(|t| t.strip_suffix(')'))
		.ok_or_else(bad)?;
	let items = parse_status_items(inner).ok_or_else(bad)?;
	Ok(Command::Status { mailbox, items })
}

/// Parse a non-empty space-separated STATUS item list (without parentheses).
pub(super) fn parse_status_items(inner: &str) -> Option<Vec<StatusItem>> {
	let mut items = Vec::new();
	for word in inner.split_whitespace() {
		items.push(match word.to_ascii_uppercase().as_str() {
			"MESSAGES" => StatusItem::Messages,
			"RECENT" => StatusItem::Recent,
			"UIDNEXT" => StatusItem::Uidnext,
			"UIDVALIDITY" => StatusItem::Uidvalidity,
			"UNSEEN" => StatusItem::Unseen,
			"SIZE" => StatusItem::Size,
			"DELETED" => StatusItem::Deleted,
			"MAILBOXID" => StatusItem::MailboxId,
			"HIGHESTMODSEQ" => StatusItem::HighestModseq,
			"APPENDLIMIT" => StatusItem::AppendLimit,
			_ => return None,
		});
	}
	(!items.is_empty()).then_some(items)
}
