//! Sieve mail filtering language (RFC 5228). The lexer feeds a parser and
//! interpreter that run a user's filter against a delivered message.

pub mod ast;
mod date;
pub mod interp;
pub mod lexer;
mod message;
pub mod parser;
pub mod vacation;
mod vars;

#[cfg(test)]
mod interp_tests;
#[cfg(test)]
mod parser_tests;
