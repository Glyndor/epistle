//! Attachment inspection: what each attachment of a message really is, and
//! whether it is dressed up as something else.
//!
//! epistle never opens or runs an attachment; the risk is the recipient's
//! client. The inspection reads the MIME structure ([`walk`]) and identifies
//! every attachment from its magic bytes ([`sniff`]).

pub mod sniff;
pub mod walk;

/// Deepest MIME nesting inspected.
pub const MAX_DEPTH: usize = 10;
/// Most MIME parts inspected in one message.
pub const MAX_PARTS: usize = 1000;

#[cfg(test)]
#[path = "corpus.rs"]
pub(crate) mod corpus;
