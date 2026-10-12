//! The exit codes every resource action shares.
//!
//! * 0: the action did what was asked.
//! * 1: the operation failed (a file could not be read or written, the
//!   database was unreachable).
//! * 2: usage error or refusal: an unknown name, input the command rejects
//!   before changing anything, a static account a dynamic-only action
//!   cannot touch, or a destructive action without `--yes`.
//!
//! A script can then tell "fix the command" (2) from "retry later" (1).

use std::process::ExitCode;

use crate::directory_store::StoreError;

/// The exit code for a usage error or a refusal.
pub(crate) const REFUSED: u8 = 2;

/// Print `message` as an error and return [`REFUSED`].
pub(crate) fn refused(message: impl std::fmt::Display) -> ExitCode {
	super::style::error(message);
	ExitCode::from(REFUSED)
}

/// The exit code for a store error: the store refusing the request (an
/// unknown name, a duplicate, invalid input, a limit) is a refusal; an I/O
/// or database failure is an operation failure.
pub(crate) fn for_store_error(error: &StoreError) -> ExitCode {
	match error {
		StoreError::NotFound(_)
		| StoreError::Duplicate(_)
		| StoreError::Invalid(_)
		| StoreError::LimitReached { .. } => ExitCode::from(REFUSED),
		_ => ExitCode::FAILURE,
	}
}

/// The exit code for an I/O error from a flat-file store: `NotFound`,
/// `AlreadyExists` and `InvalidInput` are the store refusing the request,
/// anything else is an operation failure.
pub(crate) fn for_io_error(error: &std::io::Error) -> ExitCode {
	match error.kind() {
		std::io::ErrorKind::NotFound
		| std::io::ErrorKind::AlreadyExists
		| std::io::ErrorKind::InvalidInput => ExitCode::from(REFUSED),
		_ => ExitCode::FAILURE,
	}
}

#[cfg(test)]
#[path = "exit_tests.rs"]
mod tests;
