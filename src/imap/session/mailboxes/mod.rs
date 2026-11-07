//! The commands that act on a mailbox: selecting it, expunging from it,
//! listing it, reading its quota, its access rights or its annotations,
//! subscribing to it, and the untagged updates that keep the client's view
//! of the SELECTed mailbox current.

pub(in crate::imap::session) mod acl;
pub(in crate::imap::session) mod expunge;
pub(in crate::imap::session) mod lsub;
pub(in crate::imap::session) mod metadata;
pub(in crate::imap::session) mod notify;
pub(in crate::imap::session) mod quota;
pub(in crate::imap::session) mod select;
pub(in crate::imap::session) mod sync;
