//! IMAP command parsing (RFC 9051 section 6), strict subset.
//!
//! The module holds the vocabulary of the protocol and the parsers that
//! build it: the [`Command`] enum and the tag that carries it in `syntax`,
//! the line parser in `parse`, the reason a line failed in `error`, the
//! sequence sets in `sequence_set`, the search keys in `search_key`, the
//! SEARCH family in `search`, the NOTIFY request in `notify`, the STATUS
//! command and its items in `status`, the STORE command in `store`, the LIST
//! attributes in `list` and the literal count in `literal`. The credentials
//! that must not reach a [`Command`] have their own module, `credentials`.

mod acl;
mod credentials;
mod date_time;
mod error;
mod fetch;
mod fetch_section;
mod list;
mod literal;
mod metadata;
mod notify;
mod parse;
mod search;
mod search_key;
mod select_params;
mod sequence_set;
mod status;
mod store;
mod syntax;

pub use credentials::{AuthenticateRequest, Line, LoginRequest, Secret, parse_line};
pub use error::ParseError;
pub use fetch::FetchItem;
pub use fetch_section::{FetchSection, SectionKind};
pub use list::{ListAttribute, ListCommand};
pub use literal::LiteralAnnouncement;
pub use notify::{NotifyEvent, NotifyGroup, NotifyMailboxes, NotifyRequest};
pub use parse::{DEFAULT_APPEND_LIMIT, MAX_COMMAND_LINE, parse};
pub use search::{ReturnOpt, SearchScope, SortKey, ThreadAlgorithm};
pub use search_key::SearchKey;
pub use sequence_set::SequenceSet;
pub use status::StatusItem;
pub use store::StoreMode;
pub use syntax::{Command, Tagged};

pub(crate) use date_time::parse as parse_date_time;
pub(crate) use literal::{literal_announcement_in_line, literal_announcement_in_tail};
pub(crate) use search_key::MAX_SEARCH_DEPTH;

// The two shared parsers the sibling modules and the tests reach through
// this module.
use date_time::parse_imap_date;
use sequence_set::parse_sequence_set;

#[cfg(test)]
mod tests;
