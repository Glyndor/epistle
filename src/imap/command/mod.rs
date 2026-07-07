//! IMAP command parsing (RFC 9051 section 6), strict subset.

/// Maximum command line length accepted.
pub const MAX_COMMAND_LINE: usize = 8192;

/// A parsed client command with its tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tagged {
	pub tag: String,
	pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
	Capability,
	Noop,
	Logout,
	/// `NAMESPACE` (RFC 2342).
	Namespace,
	/// `ID` (RFC 2971); the client's parameter list is accepted and ignored.
	Id,
	StartTls,
	Login {
		username: String,
		password: String,
	},
	/// `AUTHENTICATE <mechanism> [initial-response]` (RFC 9051).
	Authenticate {
		mechanism: String,
		initial: Option<String>,
	},
	List {
		reference: String,
		pattern: String,
		/// `RETURN (STATUS (...))` items to report inline (LIST-STATUS, RFC 5819).
		return_status: Vec<StatusItem>,
		/// `(SUBSCRIBED)` selection: list only subscribed mailboxes (RFC 5258).
		select_subscribed: bool,
	},
	Select {
		mailbox: String,
		/// `(QRESYNC (uidvalidity modseq ...))`: resync from this point (RFC 7162).
		qresync: Option<(u32, u64)>,
	},
	Examine {
		mailbox: String,
		qresync: Option<(u32, u64)>,
	},
	Close,
	/// `UNSELECT` (RFC 3691): leave the selected mailbox without expunging.
	Unselect,
	/// `ENABLE <capability>...` (RFC 5161).
	Enable {
		capabilities: Vec<String>,
	},
	/// `GETQUOTAROOT <mailbox>` (RFC 9208).
	GetQuotaRoot {
		mailbox: String,
	},
	/// `GETQUOTA <quota-root>` (RFC 9208).
	GetQuota {
		root: String,
	},
	Create {
		mailbox: String,
	},
	Delete {
		mailbox: String,
	},
	Rename {
		from: String,
		to: String,
	},
	Expunge,
	/// `UID EXPUNGE <set>` (RFC 4315): expunge only \Deleted messages in the set.
	UidExpunge {
		sequence: SequenceSet,
	},
	Idle,
	/// `APPEND <mailbox> [(flags)] {size}` — the literal body follows.
	Append {
		mailbox: String,
		flags: Vec<String>,
		size: usize,
	},
	/// `REPLACE <seq> <mailbox> [(flags)] {literal}` (RFC 8508): append a new
	/// message to `mailbox`, then expunge message `sequence` from the selected
	/// mailbox. `uid` selects `UID REPLACE`.
	Replace {
		sequence: u32,
		mailbox: String,
		flags: Vec<String>,
		size: usize,
		uid: bool,
	},
	Fetch {
		sequence: SequenceSet,
		items: Vec<FetchItem>,
		uid: bool,
		/// CONDSTORE `CHANGEDSINCE n`: only messages with a greater mod-seq.
		changed_since: Option<u64>,
		/// QRESYNC `VANISHED`: also report UIDs expunged since `changed_since`.
		vanished: bool,
	},
	Store {
		sequence: SequenceSet,
		mode: StoreMode,
		flags: Vec<String>,
		silent: bool,
		uid: bool,
		/// CONDSTORE `UNCHANGEDSINCE n`: skip messages whose mod-seq exceeds it.
		unchanged_since: Option<u64>,
	},
	Copy {
		sequence: SequenceSet,
		mailbox: String,
		uid: bool,
		/// MOVE removes the source messages after copying.
		remove_source: bool,
	},
	Search {
		criteria: Vec<SearchKey>,
		uid: bool,
		/// `RETURN (...)` options (RFC 4731 ESEARCH). `None` is the legacy
		/// `* SEARCH` reply; `Some` selects the `* ESEARCH` reply.
		return_opts: Option<Vec<ReturnOpt>>,
	},
	/// `ESEARCH [IN (sources)] [RETURN (...)] criteria` (RFC 7377
	/// MULTISEARCH). Searches one or more mailboxes, always reporting UIDs.
	Esearch {
		sources: Vec<SearchScope>,
		criteria: Vec<SearchKey>,
		return_opts: Vec<ReturnOpt>,
	},
	/// `SORT (<keys>) <charset> <search-criteria>` (RFC 5256).
	Sort {
		keys: Vec<(bool, SortKey)>,
		criteria: Vec<SearchKey>,
		uid: bool,
	},
	/// `THREAD ORDEREDSUBJECT <charset> <search-criteria>` (RFC 5256).
	Thread {
		criteria: Vec<SearchKey>,
		uid: bool,
	},
	Status {
		mailbox: String,
		items: Vec<StatusItem>,
	},
	Subscribe {
		mailbox: String,
	},
	Unsubscribe {
		mailbox: String,
	},
	Lsub {
		reference: String,
		pattern: String,
	},
	/// `SETACL <mailbox> <identifier> <rights>` (RFC 4314).
	SetAcl {
		mailbox: String,
		identifier: String,
		rights: String,
	},
	/// `DELETEACL <mailbox> <identifier>` (RFC 4314).
	DeleteAcl {
		mailbox: String,
		identifier: String,
	},
	/// `GETACL <mailbox>` (RFC 4314).
	GetAcl {
		mailbox: String,
	},
	/// `LISTRIGHTS <mailbox> <identifier>` (RFC 4314).
	ListRights {
		mailbox: String,
		identifier: String,
	},
	/// `MYRIGHTS <mailbox>` (RFC 4314).
	MyRights {
		mailbox: String,
	},
	/// `GETMETADATA [(options)] <mailbox> <entries>` (RFC 5464). An empty
	/// mailbox name addresses server-level annotations.
	GetMetadata {
		mailbox: String,
		entries: Vec<String>,
	},
	/// `SETMETADATA <mailbox> (entry value ...)` (RFC 5464). A `None` value
	/// deletes the entry.
	SetMetadata {
		mailbox: String,
		items: Vec<(String, Option<String>)>,
	},
	/// `NOTIFY SET [STATUS] (<event-group> ...)` / `NOTIFY NONE` (RFC 5465).
	Notify(NotifyRequest),
}

/// A parsed `NOTIFY` request (RFC 5465 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyRequest {
	/// `NOTIFY NONE`: disable all unsolicited event notifications.
	None,
	/// `NOTIFY SET [STATUS] (...)`: enable notifications. `status` records the
	/// `STATUS` return modifier. `selected` holds the events requested for the
	/// `selected` mailbox specifier (the only specifier fully supported); other
	/// specifiers are accepted and ignored.
	Set {
		status: bool,
		selected: Vec<NotifyEvent>,
	},
}

/// A NOTIFY message event (RFC 5465 §6). Only the events the server can deliver
/// for the selected mailbox are modelled; unknown events are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyEvent {
	/// `MessageNew`: a message was added to the mailbox.
	MessageNew,
	/// `MessageExpunge`: a message was removed from the mailbox.
	MessageExpunge,
	/// `FlagChange`: a message's flags changed.
	FlagChange,
	/// `AnnotationChange`: a message annotation changed.
	AnnotationChange,
}

/// Items that can be requested in a STATUS command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusItem {
	Messages,
	Recent,
	Uidnext,
	Uidvalidity,
	Unseen,
	/// `SIZE` (RFC 8438): total octets of all messages in the mailbox.
	Size,
	/// `DELETED`: count of messages flagged `\Deleted` (RFC 9051).
	Deleted,
	/// `MAILBOXID`: the mailbox's stable object id (OBJECTID, RFC 8474).
	MailboxId,
}

/// An ESEARCH `RETURN` option (RFC 4731).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnOpt {
	Min,
	Max,
	Count,
	All,
}

/// A MULTISEARCH source scope (RFC 7377 §2.2 `scope-option`). Selects which
/// mailboxes an `ESEARCH` command searches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchScope {
	/// The currently selected mailbox (the default when no `IN` is given).
	Selected,
	/// Mailboxes that receive new messages — here, just INBOX.
	Inboxes,
	/// Every mailbox in the user's personal namespace.
	Personal,
	/// Every subscribed mailbox.
	Subscribed,
	/// The named mailboxes and all their descendants.
	Subtree(Vec<String>),
	/// The named mailboxes and their immediate children only.
	SubtreeOne(Vec<String>),
	/// Exactly the named mailboxes.
	Mailboxes(Vec<String>),
}

/// A SORT key (RFC 5256), optionally preceded by REVERSE in the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
	Arrival,
	Cc,
	Date,
	From,
	Size,
	Subject,
	To,
}

/// A single SEARCH criterion; multiple keys AND together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchKey {
	All,
	/// Flag present (true) or absent (false).
	FlagIs(super::mailbox::Flag, bool),
	/// Header substring: (header name lowercased, needle lowercased).
	Header(String, String),
	/// Substring anywhere in the message (headers + body).
	Text(String),
	/// Explicit message sequence set.
	Sequence(SequenceSet),
	/// Explicit UID set (`UID <set>`).
	UidSet(SequenceSet),
	/// Logical OR of two criteria.
	Or(Box<SearchKey>, Box<SearchKey>),
	/// Logical NOT of one criterion.
	Not(Box<SearchKey>),
	/// Parenthesized group: implicitly AND'd (RFC 3501 §6.4.4 search-key).
	And(Vec<SearchKey>),
	/// INTERNALDATE strictly before midnight UTC of this date (year, month, day).
	Before(u32, u8, u8),
	/// INTERNALDATE on or after midnight UTC of this date.
	Since(u32, u8, u8),
	/// INTERNALDATE falls within this date (midnight to midnight UTC).
	On(u32, u8, u8),
	/// RFC 2822 size strictly greater than n octets.
	Larger(u32),
	/// RFC 2822 size strictly less than n octets.
	Smaller(u32),
	/// CONDSTORE `MODSEQ n`: mod-sequence at or above n (RFC 7162).
	ModSeq(u64),
}

/// How STORE changes the flag set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreMode {
	Set,
	Add,
	Remove,
}

/// What FETCH must return per message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchItem {
	Flags,
	Rfc822Size,
	Uid,
	/// `BODY[]` / `RFC822`: the full raw message.
	Body,
	/// `BINARY[]`: the body decoded per its Content-Transfer-Encoding (RFC 3516).
	Binary,
	/// `BINARY.SIZE[]`: the decoded body's size in octets (RFC 3516).
	BinarySize,
	InternalDate,
	/// `MODSEQ`: the message's mod-sequence (CONDSTORE, RFC 7162).
	ModSeq,
	/// `EMAILID`: the message's stable object id (RFC 8474).
	EmailId,
	/// `THREADID`: the message's thread id (RFC 8474); singleton == EMAILID.
	ThreadId,
	/// `SAVEDATE`: when the message was saved to the mailbox (RFC 8514).
	SaveDate,
	/// `PREVIEW`: a short text snippet of the message (RFC 8970).
	Preview,
}

/// A `1`, `1:5`, `1:*`, `*` style sequence set (comma-separated ranges).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceSet {
	pub ranges: Vec<(u32, Option<u32>)>,
}

impl SequenceSet {
	/// Whether `value` (a sequence number or UID) is included, given the
	/// maximum existing value for `*`.
	pub fn contains(&self, value: u32, max: u32) -> bool {
		self.ranges.iter().any(|(start, end)| {
			let start = *start;
			let end = end.unwrap_or(start);
			let (low, high) = if start == 0 {
				(max, end.min(max).max(max))
			} else if end == 0 {
				(start.min(max), max)
			} else if start <= end {
				(start, end)
			} else {
				(end, start)
			};
			value >= low && value <= high
		})
	}
}

/// Why a line failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
	/// No tag or malformed structure: answered with `* BAD`.
	Malformed,
	/// Valid tag but unknown/unsupported command: tagged `BAD`.
	Unknown(String),
	/// Valid tag, known command, bad arguments: tagged `BAD`.
	BadArguments(String),
}

/// Parse `1`, `1:5`, `1:*`, `*`, comma-separated. `0` encodes `*` here.
fn parse_sequence_set(text: &str) -> Option<SequenceSet> {
	let mut ranges = Vec::new();
	for part in text.split(',') {
		let (start, end) = match part.split_once(':') {
			Some((start, end)) => (parse_seq_number(start)?, Some(parse_seq_number(end)?)),
			None => (parse_seq_number(part)?, None),
		};
		ranges.push((start, end));
	}
	if ranges.is_empty() {
		return None;
	}
	Some(SequenceSet { ranges })
}

fn parse_seq_number(text: &str) -> Option<u32> {
	if text == "*" {
		return Some(0);
	}
	let value: u32 = text.parse().ok()?;
	if value == 0 { None } else { Some(value) }
}

/// Parse an IMAP date-text (`1-Jan-2023` or `01-Jan-2023`).
/// Returns `(year, month, day)` on success.
fn parse_imap_date(s: &str) -> Option<(u32, u8, u8)> {
	let mut parts = s.splitn(3, '-');
	let day: u8 = parts.next()?.parse().ok()?;
	let month: u8 = match parts.next()?.to_ascii_uppercase().as_str() {
		"JAN" => 1,
		"FEB" => 2,
		"MAR" => 3,
		"APR" => 4,
		"MAY" => 5,
		"JUN" => 6,
		"JUL" => 7,
		"AUG" => 8,
		"SEP" => 9,
		"OCT" => 10,
		"NOV" => 11,
		"DEC" => 12,
		_ => return None,
	};
	let year: u32 = parts.next()?.parse().ok()?;
	if day == 0 || day > 31 || month == 0 || month > 12 {
		return None;
	}
	Some((year, month, day))
}

mod acl;
mod literal;
mod metadata;
mod notify;
mod parse;
mod search;
mod select_params;

pub use parse::parse;

#[cfg(test)]
#[path = "command_tests.rs"]
mod tests;
