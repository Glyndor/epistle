//! Raw-wire attacks against an isolated production IMAP listener.
//! No external services or environment switches are required.

#[path = "hostile_imap/abuse.rs"]
mod abuse;
#[path = "hostile_imap/auth_tls.rs"]
mod auth_tls;
#[path = "hostile_imap/framing.rs"]
mod framing;
#[path = "hostile_imap/harness.rs"]
mod harness;
#[path = "hostile_imap/mailboxes.rs"]
mod mailboxes;
#[path = "hostile_imap/search.rs"]
mod search;
