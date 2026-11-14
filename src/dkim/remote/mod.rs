//! DKIM signing across a Unix socket: the key holder in one process, the
//! code that reads the message in another.
//!
//! [`SignerServer`] wraps a [`KeyHolder`](super::KeyHolder) and answers
//! signing requests on a socket; [`RemoteSigner`] is the client the reading
//! side calls. What crosses the socket is the [`HeaderBlock`](super::HeaderBlock)
//! and the `d=` domain, never the body, and what comes back is the
//! `DKIM-Signature` fields or a refusal, never key material. The wire
//! format is in [`frame`]: a version byte, an operation byte and
//! length-prefixed fields, each with a cap, one request and one answer per
//! connection, under a deadline on the whole exchange.
//!
//! The server trusts nothing the socket brings: it decodes the frame
//! itself, checks that `d=` is a host name, runs
//! [`HeaderBlock::check`](super::HeaderBlock::check) on the block, and only
//! then hands it to the key holder. The client trusts nothing the socket
//! brings back either, and an answer it cannot read counts as no answer.
//!
//! A signer that cannot be reached is [`RemoteError::Unavailable`], which
//! is not the in-process "not signed" outcome: the caller must not send the
//! message without the signature on that error. Nothing in `epistle serve`
//! runs this yet (`docs/operations/serve-split.md`, step 3 of the order).

mod client;
pub mod frame;
mod server;

pub use client::{DEFAULT_DEADLINE, RemoteError, RemoteSigner};
pub use frame::Reason;
pub(crate) use server::admit;
pub use server::{MAX_CONNECTIONS, SERVER_DEADLINE, SignerServer, bind};

#[cfg(test)]
mod tests;
