//! IMAP command parsing (RFC 9051 section 6), strict subset.

/// Maximum command line length accepted.
pub const MAX_COMMAND_LINE: usize = 8192;

/// A parsed client command with its tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tagged {
	/// Client-supplied tag (alphanumeric, non-empty) used to correlate the
	/// server's response with the request.
	pub tag: String,
	/// The parsed command body.
	pub command: Command,
}

/// An IMAP command, parsed from a single client line. Variants correspond
/// one-to-one with the commands RFC 9051 and its extensions (CONDSTORE,
/// QRESYNC, LIST-EXTENDED, ACL, METADATA, NOTIFY, etc.) accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
	/// `CAPABILITY`: list the server's capabilities.
	Capability,
	/// `NOOP`: a no-op the server answers with any pending updates.
	Noop,
	/// `LOGOUT`: graceful shutdown of the connection.
	Logout,
	/// `NAMESPACE` (RFC 2342).
	Namespace,
	/// `ID` (RFC 2971); the client's parameter list is accepted and ignored.
	Id,
	/// `STARTTLS`: upgrade the plaintext connection to TLS.
	StartTls,
	/// `COMPRESS <algorithm>` (RFC 4978). The algorithm is carried verbatim so
	/// the session can answer `BAD` for one it does not implement rather than
	/// the parser rejecting the command outright.
	Compress {
		/// The requested algorithm, uppercased. Only `DEFLATE` is implemented.
		algorithm: String,
	},
	/// `LOGIN <user> <pass>`: cleartext authentication. Only accepted before
	/// TLS is negotiated.
	Login {
		/// The user (authcid), without the surrounding domain.
		username: String,
		/// The password.
		password: String,
	},
	/// `AUTHENTICATE <mechanism> [initial-response]` (RFC 9051).
	Authenticate {
		/// SASL mechanism name (e.g. `SCRAM-SHA-256`, `PLAIN`).
		mechanism: String,
		/// Optional initial response, base64-encoded per RFC 4959.
		initial: Option<String>,
	},
	/// `LIST <reference> <pattern>`: list mailboxes. `RETURN (STATUS (...))`
	/// items are returned inline (LIST-STATUS, RFC 5819); `(SUBSCRIBED)`
	/// narrows the result to subscribed mailboxes (RFC 5258).
	List {
		/// Reference name (often `""` or `"INBOX"`); defines the hierarchy
		/// context for `pattern`.
		reference: String,
		/// Pattern with optional wildcards (`%` for one level, `*` for any).
		pattern: String,
		/// `RETURN (STATUS (...))` items to report inline (LIST-STATUS, RFC 5819).
		return_status: Vec<StatusItem>,
		/// `(SUBSCRIBED)` selection: list only subscribed mailboxes (RFC 5258).
		select_subscribed: bool,
	},
	/// `SELECT <mailbox>`: open the mailbox read-write. `(QRESYNC (...))`
	/// resyncs from a previous session (RFC 7162).
	Select {
		/// Mailbox name to open.
		mailbox: String,
		/// `(QRESYNC (uidvalidity modseq ...))`: resync from this point (RFC 7162).
		qresync: Option<(u32, u64)>,
	},
	/// `EXAMINE <mailbox>`: like `SELECT` but read-only.
	Examine {
		/// Mailbox name to open read-only.
		mailbox: String,
		/// `(QRESYNC (uidvalidity modseq ...))` (RFC 7162).
		qresync: Option<(u32, u64)>,
	},
	/// `CLOSE`: leave the selected mailbox, expunging `\Deleted` messages.
	Close,
	/// `UNSELECT` (RFC 3691): leave the selected mailbox without expunging.
	Unselect,
	/// `ENABLE <capability>...` (RFC 5161).
	Enable {
		/// Capability names the client wants to enable for this session.
		capabilities: Vec<String>,
	},
	/// `GETQUOTAROOT <mailbox>` (RFC 9208).
	GetQuotaRoot {
		/// Mailbox whose quota roots are queried.
		mailbox: String,
	},
	/// `GETQUOTA <quota-root>` (RFC 9208).
	GetQuota {
		/// Quota root identifier (typically the mailbox name).
		root: String,
	},
	/// `CREATE <mailbox>`.
	Create {
		/// Mailbox name to create (UTF-8, INBOX-safe escaping).
		mailbox: String,
	},
	/// `DELETE <mailbox>`.
	Delete {
		/// Mailbox name to remove (fails for INBOX and mailboxes with
		/// children unless the special `\\` sentinel is used).
		mailbox: String,
	},
	/// `RENAME <from> <to>`.
	Rename {
		/// Source mailbox name.
		from: String,
		/// Destination mailbox name.
		to: String,
	},
	/// `EXPUNGE`: remove all `\Deleted` messages from the selected mailbox.
	Expunge,
	/// `UID EXPUNGE <set>` (RFC 4315): expunge only \Deleted messages in the set.
	UidExpunge {
		/// Sequence set (interpreted as UIDs because the command is `UID EXPUNGE`).
		sequence: SequenceSet,
	},
	/// `IDLE`: enter the IDLE state, receiving unsolicited updates until DONE.
	Idle,
	/// `APPEND <mailbox> [(flags)] {size}` — the literal body follows.
	Append {
		/// Destination mailbox.
		mailbox: String,
		/// Initial flags for the appended message (may be empty).
		flags: Vec<String>,
		/// Size of the literal body in octets.
		size: usize,
	},
	/// `REPLACE <seq> <mailbox> [(flags)] {literal}` (RFC 8508): append a new
	/// message to `mailbox`, then expunge message `sequence` from the selected
	/// mailbox. `uid` selects `UID REPLACE`.
	Replace {
		/// Sequence number (or UID, with `uid`) of the message to remove
		/// after the append succeeds.
		sequence: u32,
		/// Destination mailbox for the new message.
		mailbox: String,
		/// Initial flags for the appended message.
		flags: Vec<String>,
		/// Size of the literal body in octets.
		size: usize,
		/// Whether `sequence` is a UID (`UID REPLACE`) instead of a
		/// sequence number.
		uid: bool,
	},
	/// `FETCH <sequence> (<items>...)`: return data for messages in the set.
	Fetch {
		/// Messages to fetch.
		sequence: SequenceSet,
		/// Items to return per message (FLAGS, BODY[], UID, …).
		items: Vec<FetchItem>,
		/// Whether the sequence set is UIDs (`UID FETCH`) rather than
		/// sequence numbers.
		uid: bool,
		/// CONDSTORE `CHANGEDSINCE n`: only messages with a greater mod-seq.
		changed_since: Option<u64>,
		/// QRESYNC `VANISHED`: also report UIDs expunged since `changed_since`.
		vanished: bool,
	},
	/// `STORE <sequence> (<mode> <flags>)`: modify the flag set.
	Store {
		/// Messages to update.
		sequence: SequenceSet,
		/// How to apply the new flags (set, add, or remove).
		mode: StoreMode,
		/// Flags to apply.
		flags: Vec<String>,
		/// `(.SILENT)`: do not return the new flag values.
		silent: bool,
		/// Whether the sequence set is UIDs (`UID STORE`) rather than
		/// sequence numbers.
		uid: bool,
		/// CONDSTORE `UNCHANGEDSINCE n`: skip messages whose mod-seq exceeds it.
		unchanged_since: Option<u64>,
	},
	/// `COPY <sequence> <mailbox>` (or `MOVE` when `remove_source` is set).
	Copy {
		/// Messages to copy.
		sequence: SequenceSet,
		/// Destination mailbox.
		mailbox: String,
		/// Whether the sequence set is UIDs (`UID COPY`) rather than
		/// sequence numbers.
		uid: bool,
		/// MOVE removes the source messages after copying.
		remove_source: bool,
	},
	/// `SEARCH <criteria>`: return matching sequence numbers (or UIDs).
	Search {
		/// Criteria to AND together.
		criteria: Vec<SearchKey>,
		/// Whether to return UIDs (`UID SEARCH`) rather than sequence numbers.
		uid: bool,
		/// `RETURN (...)` options (RFC 4731 ESEARCH). `None` is the legacy
		/// `* SEARCH` reply; `Some` selects the `* ESEARCH` reply.
		return_opts: Option<Vec<ReturnOpt>>,
	},
	/// `ESEARCH [IN (sources)] [RETURN (...)] criteria` (RFC 7377
	/// MULTISEARCH). Searches one or more mailboxes, always reporting UIDs.
	Esearch {
		/// Mailboxes or scopes to search.
		sources: Vec<SearchScope>,
		/// Criteria to AND together.
		criteria: Vec<SearchKey>,
		/// RETURN options (RFC 4731). ESEARCH always emits them.
		return_opts: Vec<ReturnOpt>,
	},
	/// `SORT (<keys>) <charset> <search-criteria>` (RFC 5256).
	Sort {
		/// `(reverse, key)` pairs, in priority order.
		keys: Vec<(bool, SortKey)>,
		/// Criteria to AND together.
		criteria: Vec<SearchKey>,
		/// Whether to return UIDs (`UID SORT`) rather than sequence numbers.
		uid: bool,
	},
	/// `THREAD ORDEREDSUBJECT <charset> <search-criteria>` (RFC 5256).
	Thread {
		/// Criteria to AND together.
		criteria: Vec<SearchKey>,
		/// Whether to return UIDs (`UID THREAD`) rather than sequence numbers.
		uid: bool,
	},
	/// `STATUS <mailbox> (<items>...)`: mailbox-level counters.
	Status {
		/// Mailbox name to query.
		mailbox: String,
		/// Items to include in the STATUS response.
		items: Vec<StatusItem>,
	},
	/// `SUBSCRIBE <mailbox>`: mark the mailbox as active.
	Subscribe {
		/// Mailbox name to subscribe to.
		mailbox: String,
	},
	/// `UNSUBSCRIBE <mailbox>`: drop the active subscription.
	Unsubscribe {
		/// Mailbox name to unsubscribe from.
		mailbox: String,
	},
	/// `LSUB <reference> <pattern>`: list subscribed mailboxes.
	Lsub {
		/// Reference name defining the hierarchy context.
		reference: String,
		/// Pattern with wildcards (`%`, `*`).
		pattern: String,
	},
	/// `SETACL <mailbox> <identifier> <rights>` (RFC 4314).
	SetAcl {
		/// Mailbox whose ACL is being set.
		mailbox: String,
		/// Identifier (authcid, anyone, …) being granted rights.
		identifier: String,
		/// Right string (e.g. `"lrswipkxtea"`).
		rights: String,
	},
	/// `DELETEACL <mailbox> <identifier>` (RFC 4314).
	DeleteAcl {
		/// Mailbox whose ACL is being modified.
		mailbox: String,
		/// Identifier whose rights are being revoked (rights omitted).
		identifier: String,
	},
	/// `GETACL <mailbox>` (RFC 4314).
	GetAcl {
		/// Mailbox whose ACL is being queried.
		mailbox: String,
	},
	/// `LISTRIGHTS <mailbox> <identifier>` (RFC 4314).
	ListRights {
		/// Mailbox whose rights are being listed.
		mailbox: String,
		/// Identifier whose available rights are being listed.
		identifier: String,
	},
	/// `MYRIGHTS <mailbox>` (RFC 4314).
	MyRights {
		/// Mailbox whose rights for the current user are being queried.
		mailbox: String,
	},
	/// `GETMETADATA [(options)] <mailbox> <entries>` (RFC 5464). An empty
	/// mailbox name addresses server-level annotations.
	GetMetadata {
		/// Mailbox name (empty string addresses server-level entries).
		mailbox: String,
		/// Annotation entry names to look up.
		entries: Vec<String>,
	},
	/// `SETMETADATA <mailbox> (entry value ...)` (RFC 5464). A `None` value
	/// deletes the entry.
	SetMetadata {
		/// Mailbox name (empty string addresses server-level entries).
		mailbox: String,
		/// `(entry, value)` pairs; a `None` value deletes the entry.
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
		/// Whether the request carried the `STATUS` return modifier: when
		/// set, status responses for newly selected mailboxes are emitted.
		status: bool,
		/// Events requested for the `selected` mailbox specifier.
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
}

/// An ESEARCH `RETURN` option (RFC 4731).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnOpt {
	/// Return the lowest matching sequence number / UID.
	Min,
	/// Return the highest matching sequence number / UID.
	Max,
	/// Return the count of matches.
	Count,
	/// Return every matching sequence number / UID.
	All,
	/// SEARCHRES (RFC 5182): save the result set so the client can reference
	/// it via `$` in a subsequent command.
	Save,
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
	/// Internal date (delivery time).
	Arrival,
	/// Cc header.
	Cc,
	/// Date header.
	Date,
	/// From header.
	From,
	/// RFC 5322 size in octets.
	Size,
	/// Subject header.
	Subject,
	/// To header.
	To,
}

/// A single SEARCH criterion; multiple keys AND together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchKey {
	/// `ALL`: match every message in the mailbox.
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
	/// WITHIN `YOUNGER n` (RFC 5032): internal date within the last `n`
	/// seconds.
	Younger(u32),
	/// WITHIN `OLDER n` (RFC 5032): internal date strictly more than `n`
	/// seconds ago.
	Older(u32),
}

/// How STORE changes the flag set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreMode {
	/// `FLAGS`: replace the flag set.
	Set,
	/// `+FLAGS`: add the listed flags.
	Add,
	/// `-FLAGS`: remove the listed flags.
	Remove,
}

/// What FETCH must return per message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchItem {
	/// `FLAGS`: the message's flag list.
	Flags,
	/// `RFC822.SIZE`: the RFC 5322 size in octets.
	Rfc822Size,
	/// `UID`: the message's UID.
	Uid,
	/// `BODY[]` / `RFC822`: the full raw message.
	Body,
	/// `BINARY[]`: the body decoded per its Content-Transfer-Encoding (RFC 3516).
	Binary,
	/// `BINARY.SIZE[]`: the decoded body's size in octets (RFC 3516).
	BinarySize,
	/// `INTERNALDATE`: the message's internal date.
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

/// A `1`, `1:5`, `1:*`, `*` style sequence set (comma-separated ranges), or
/// the SEARCHRES `$` placeholder for the most recent saved result set
/// (RFC 5182).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceSet {
	/// Inclusive ranges as `(start, end)` pairs. `end = None` denotes a
	/// single value rather than a range. `0` is the internal encoding for
	/// `*` (the maximum existing value); see [`Self::contains`] for the
	/// resolution rules.
	pub ranges: Vec<(u32, Option<u32>)>,
	/// `true` when the source was `$`. `ranges` is then ignored and the
	/// session's most recent SEARCHRES-saved result set supplies the values.
	pub saved: bool,
}

impl SequenceSet {
	/// A sequence set that resolves to the SEARCHRES `$` placeholder.
	pub const SAVED: SequenceSet = SequenceSet {
		ranges: Vec::new(),
		saved: true,
	};

	/// Whether `value` (a sequence number or UID) is included, given the
	/// maximum existing value for `*` and the SEARCHRES `$` set when
	/// `self.saved == true`. When `saved` is empty and `self.saved == true`
	/// (no recent SAVE), nothing matches.
	pub fn contains(&self, value: u32, max: u32, saved: &[u32]) -> bool {
		if self.saved {
			return saved.contains(&value);
		}
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

/// Parse `1`, `1:5`, `1:*`, `*`, comma-separated, or the SEARCHRES `$`
/// placeholder (RFC 5182). `0` encodes `*` here.
fn parse_sequence_set(text: &str) -> Option<SequenceSet> {
	let trimmed = text.trim();
	// RFC 5182: the SEARCHRES shortcut is the whole sequence-set, not part of
	// a range. We accept any leading/trailing whitespace but reject mixed
	// forms like `1,$` or `$,5`: those would require resolving $ against an
	// arbitrary other range, which RFC 5182 does not specify. Returning the
	// SAVED placeholder is still useful — the consumer checks emptiness.
	if trimmed == "$" {
		return Some(SequenceSet::SAVED);
	}
	let mut ranges = Vec::new();
	for part in trimmed.split(',') {
		let (start, end) = match part.split_once(':') {
			Some((start, end)) => (parse_seq_number(start)?, Some(parse_seq_number(end)?)),
			None => (parse_seq_number(part)?, None),
		};
		ranges.push((start, end));
	}
	if ranges.is_empty() {
		return None;
	}
	Some(SequenceSet {
		ranges,
		saved: false,
	})
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
