//! What one IMAP session may hold in memory while it answers a FETCH.

/// Octets of FETCH data a session builds before it stops and answers
/// `NO [LIMIT]`. The check runs between messages, so one answer holds at
/// most this much plus the one message being added (the message is held
/// once for its bytes and once for the item built from it). A message
/// larger than the cap is still sent when it is the first of the answer, so
/// a client can always fetch it alone.
pub const MAX_FETCH_RESPONSE_OCTETS: usize = 32 * 1024 * 1024;
