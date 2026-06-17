//! Sieve mail filtering language (RFC 5228). The lexer feeds a parser and
//! interpreter that run a user's filter against a delivered message.

pub mod ast;
pub mod lexer;
pub mod parser;

#[cfg(test)]
mod parser_tests;
