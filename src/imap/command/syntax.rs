//! The command syntax the server accepts: the [`Command`] enum, one variant
//! per command it answers, with the arguments it parsed. The parsers that
//! build it live in the sibling modules.

use super::fetch::FetchItem;
use super::list::ListCommand;
use super::notify::NotifyRequest;
use super::search::{ReturnOpt, SearchScope, SortKey, ThreadAlgorithm};
use super::search_key::SearchKey;
use super::sequence_set::SequenceSet;
use super::status::StatusItem;
use super::store::StoreMode;

/// An IMAP command, parsed from a single client line. Variants correspond
/// one-to-one with the commands RFC 9051 and its extensions (CONDSTORE,
/// QRESYNC, LIST-EXTENDED, ACL, METADATA, NOTIFY, etc.) accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
	/// `CAPABILITY`: list the server's capabilities.
	Capability,
	/// `NOOP`: a no-op the server answers with any pending updates.
	Noop,
	/// `CHECK`: selected-state checkpoint, currently a no-op.
	Check,
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
	/// `LIST [(<selection>)] <reference> <pattern or (patterns)> [RETURN
	/// (...)]`: list mailboxes (RFC 9051 §6.3.9, LIST-EXTENDED RFC 5258,
	/// LIST-STATUS RFC 5819).
	List(ListCommand),
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
		/// The INTERNALDATE the client asked for, if any.
		date: Option<crate::imap::internal_date::InternalDate>,
		/// Size of the literal body in octets.
		size: usize,
		/// `false` for the non-synchronizing `{n+}` form (RFC 7888), where
		/// the client already sent the bytes; the server must consume or
		/// discard them when it rejects the command.
		synchronizing: bool,
		/// The message came as `UTF8 (~{n})` (RFC 6855 §4): it may carry
		/// UTF-8 header fields, and a `)` follows the literal.
		utf8: bool,
		/// The message came as a literal8 `~{n}` (RFC 3516 §4.4), so its
		/// binary parts may hold any octet.
		binary: bool,
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
		/// The INTERNALDATE the client asked for, if any.
		date: Option<crate::imap::internal_date::InternalDate>,
		/// Size of the literal body in octets.
		size: usize,
		/// Whether `sequence` is a UID (`UID REPLACE`) instead of a
		/// sequence number.
		uid: bool,
		/// `false` for the non-synchronizing `{n+}` form (RFC 7888), where
		/// the client already sent the bytes; the server must consume or
		/// discard them when it rejects the command.
		synchronizing: bool,
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
	/// `THREAD <algorithm> <charset> <search-criteria>` (RFC 5256).
	Thread {
		/// The threading algorithm the client asked for
		/// (`ORDEREDSUBJECT` or `REFERENCES`). Both are accepted; the
		/// capability list tells the client which ones are wired up.
		algorithm: ThreadAlgorithm,
		/// Criteria to AND together.
		criteria: Vec<SearchKey>,
		/// Whether to return UIDs (`UID THREAD`) rather than sequence
		/// numbers.
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

/// A parsed client command with its tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tagged {
	/// Client-supplied tag (alphanumeric, non-empty) used to correlate the
	/// server's response with the request.
	pub tag: String,
	/// The parsed command body.
	pub command: Command,
}
