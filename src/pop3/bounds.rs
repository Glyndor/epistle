//! What one POP3 session may hold in memory.
//!
//! A session holds an index of at most [`MAX_SESSION_MESSAGES`] entries (a
//! name and a size each, about 100 octets with their allocation, so under
//! 10 MiB), the bytes of the one message a command is answering (at most
//! [`MAX_MESSAGE_OCTETS`]), and, while it is written, one piece of at most
//! [`super::wire::WIRE_CHUNK`] octets of its dot-stuffed encoding. A
//! retrieval therefore costs the message once plus 64 KiB, not a copy for
//! each stage of the encoding. Reading the directory keeps only the names of
//! the newest [`MAX_SESSION_MESSAGES`] files at a time.

/// Messages one session lists. When the inbox holds more, the newest are
/// listed and the oldest are left out until the client deletes some and
/// signs in again.
pub const MAX_SESSION_MESSAGES: usize = 100_000;

/// Octets of one message a session reads for a client. A larger message is
/// not listed.
pub const MAX_MESSAGE_OCTETS: usize = 64 * 1024 * 1024;
