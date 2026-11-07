//! Command handling that reads or writes messages: the reply-code builders,
//! the command families that search, sort, copy or append, and the literal
//! (APPEND/REPLACE) exchange.

pub(in crate::imap::session) mod codes;
pub(in crate::imap::session) mod copy;
pub(in crate::imap::session) mod idle;
pub(in crate::imap::session) mod literal;
pub(in crate::imap::session) mod literal_store;
pub(in crate::imap::session) mod search;
pub(in crate::imap::session) mod sort;
pub(in crate::imap::session) mod thread;
pub(in crate::imap::session) mod utf8;
