//! Size and recipient limits a session enforces, with the bounds the
//! configuration may move them within.

/// Maximum accepted message size in bytes. The historical default and
/// the upper bound for the configurable `[server] max_message_size`;
/// raise it on operators who know what they are doing, lower it on
/// operators who want to be conservative.
pub const MAX_MESSAGE_SIZE: usize = 25 * 1024 * 1024;

/// Recipients per transaction a server accepts unless `max_recipients` says
/// otherwise. RFC 5321 §4.5.3.1.8 makes 100 the least a server may offer.
pub const DEFAULT_MAX_RECIPIENTS: usize = 100;

/// The least `max_message_size` may allow: RFC 5321 §4.5.3.1.7 says a server
/// MUST accept message content of at least 64K octets.
pub const MIN_MESSAGE_SIZE: usize = 64 * 1024;

/// Why [`MIN_MESSAGE_SIZE`] cannot be crossed, as `max_message_size` and
/// `epistle limits set max-message-size` word the refusal.
pub const MIN_MESSAGE_SIZE_REASON: &str =
	"RFC 5321 §4.5.3.1.7 requires accepting messages of at least 64K octets";

/// The fewest recipients per transaction `max_recipients` may allow: RFC 5321
/// §4.5.3.1.8 says a server MUST accept at least 100.
pub const MIN_MAX_RECIPIENTS: usize = 100;

/// Why [`MIN_MAX_RECIPIENTS`] cannot be crossed, as `max_recipients` and
/// `epistle limits set max-recipients` word the refusal.
pub const MIN_MAX_RECIPIENTS_REASON: &str =
	"RFC 5321 §4.5.3.1.8 requires accepting at least 100 recipients";

/// The most recipients per transaction `max_recipients` may allow. Every
/// recipient costs a directory lookup, a spool entry and a delivery, so the
/// cap keeps one message from asking for unbounded work.
pub const MAX_MAX_RECIPIENTS: usize = 10_000;
