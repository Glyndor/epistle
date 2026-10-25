//! What one POP3 session may hold in memory: an index of the inbox and, at
//! any moment, the bytes of one message.

/// Messages one session lists; the oldest come first and the rest are not
/// shown until the earlier ones are deleted and the client signs in again.
pub const MAX_SESSION_MESSAGES: usize = 100_000;

/// Octets of one message a session reads for a client. A larger message is
/// listed but refused when it is retrieved.
pub const MAX_MESSAGE_OCTETS: usize = 64 * 1024 * 1024;
