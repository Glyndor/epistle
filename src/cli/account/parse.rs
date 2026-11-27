//! Parsers for the account command line values: quota sizes, protocol
//! lists and on/off switches.

use super::*;

pub(in crate::cli) use crate::util::quota_size::parse_quota_size;

/// Parse a protocol-list argument (`imap,smtp`, `all`). Unknown
/// protocol names are rejected with a list of the accepted ones so a
/// typo never reaches the store. `all` (case-insensitive) returns
/// `Ok(None)` to clear the restriction. Implementation lives in
/// `actions`; the umbrella keeps only the re-export so
/// the Subcommand enum stays close to the call site.
pub(in crate::cli) fn parse_protocol_list(raw: &str) -> Result<Option<Vec<Protocol>>, String> {
	actions::parse_protocol_list_inner(raw)
}

/// Parse the `on`/`off` switch the `save_sent` and quota
/// subcommands accept. The CLI keeps the accepted set narrow so a
/// typo never lands on disk: `on` and `off` are the only valid
/// spellings. Implementation lives in `actions`.
pub(in crate::cli) fn parse_on_off(raw: &str) -> Result<bool, String> {
	actions::parse_on_off(raw)
}
