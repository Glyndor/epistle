//! Raw-wire attacks against an isolated production IMAP listener.
//! No external services or environment switches are required.

#[path = "hostile_imap/abuse.rs"]
mod abuse;
#[path = "hostile_imap/auth_tls.rs"]
mod auth_tls;
#[path = "hostile_imap/authenticate.rs"]
mod authenticate;
#[path = "hostile_imap/compress.rs"]
mod compress;
#[path = "hostile_imap/compress_support.rs"]
mod compress_support;
#[path = "hostile_imap/framing.rs"]
mod framing;
#[path = "hostile_imap/harness.rs"]
mod harness;
#[path = "hostile_imap/keywords.rs"]
mod keywords;
#[path = "hostile_imap/mailboxes.rs"]
mod mailboxes;
#[path = "hostile_imap/metadata.rs"]
mod metadata;
#[path = "hostile_imap/search.rs"]
mod search;
#[path = "hostile_imap/shared_ban.rs"]
mod shared_ban;
