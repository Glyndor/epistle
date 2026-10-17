//! Sieve mail filtering language (RFC 5228). The lexer feeds a parser and
//! interpreter that run a user's filter against a delivered message.

/// The Sieve extensions the interpreter honors at delivery time, as the
/// space-separated list ManageSieve advertises in `SIEVE` and JMAP in
/// `sieveExtensions`: fileinto/envelope (RFC 5228), vacation (RFC 5230),
/// imap4flags (RFC 5232), relational (RFC 5231), variables (RFC 5229),
/// reject/ereject (RFC 5429), copy (RFC 3894), body (RFC 5173), date
/// (RFC 5260), mailbox (RFC 5490), subaddress (RFC 5233) and the `i;octet`,
/// `i;ascii-casemap` and `i;ascii-numeric` comparators (RFC 4790). A script
/// may `require` only these.
pub const EXTENSIONS: &str = "fileinto envelope vacation imap4flags relational \
variables reject ereject copy body date mailbox subaddress comparator-i;octet \
comparator-i;ascii-casemap comparator-i;ascii-numeric";

/// [`EXTENSIONS`], one name at a time.
pub fn extensions() -> impl Iterator<Item = &'static str> {
	EXTENSIONS.split_whitespace()
}

#[cfg(test)]
mod alloc_probe;
pub mod analysis;
pub mod ast;
mod compare;
pub(crate) use compare::{MAX_PATTERN_CHARS, MAX_WILDCARDS};
mod date;
mod env;
mod eval;
pub mod interp;
pub mod lexer;
pub mod message;
pub mod parser;
pub mod vacation;
mod vars;

#[cfg(test)]
mod extensions_tests;
#[cfg(test)]
mod interp_tests;
#[cfg(test)]
#[path = "interp_tests_fileinto.rs"]
mod interp_tests_fileinto;
#[cfg(test)]
#[path = "interp_tests_headers.rs"]
mod interp_tests_headers;
#[cfg(test)]
#[path = "interp_tests_limits.rs"]
mod interp_tests_limits;
#[cfg(test)]
#[path = "interp_tests_mailbox.rs"]
mod interp_tests_mailbox;
#[cfg(test)]
#[path = "interp_tests_redirects.rs"]
mod interp_tests_redirects;
#[cfg(test)]
#[path = "interp_tests_sender.rs"]
mod interp_tests_sender;
#[cfg(test)]
#[path = "interp_tests_window.rs"]
mod interp_tests_window;
#[cfg(test)]
mod memory_tests;
#[cfg(test)]
mod parser_tests;
