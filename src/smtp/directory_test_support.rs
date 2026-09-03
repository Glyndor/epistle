//! Shared test helpers for the SMTP directory test modules.
//!
//! Kept here so multiple `#[path = "..."] mod xxx_tests;` declarations in
//! `directory.rs` can pull the same function in without duplicating it.
//! `#[cfg(test)]` gates the file so it never reaches the production build.

use super::Resolution;

/// The variant name of a `Resolution`, for assertion messages that must not
/// print what the variant carries. `Account(String)` carries an account
/// name and `Alias(Vec<String>)` carries member lists, and printing those
/// via `{:?}` is the `rust/cleartext-logging` dataflow: the panic message
/// flows into the test harness output, which an operator reading the logs
/// would see. Naming only the variant preserves the diagnostic ("you got
/// the wrong shape") without leaking the data.
///
/// The match is exhaustive on purpose: a new variant added to
/// `Resolution` breaks this file at compile time, so the next caller cannot
/// accidentally fall through and print the variant's contents.
pub(super) fn variant_name(resolution: &Resolution) -> &'static str {
	match resolution {
		Resolution::NotLocal => "NotLocal",
		Resolution::UnknownUser => "UnknownUser",
		Resolution::Account(_) => "Account",
		Resolution::Alias(_) => "Alias",
	}
}
