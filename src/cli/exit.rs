//! The exit codes every resource action shares.
//!
//! * 0: the action did what was asked.
//! * 1: the operation failed (a file could not be read or written, the
//!   database was unreachable).
//! * 2: usage error or not found: an unknown name, input the command
//!   rejects before changing anything, or a destructive action without
//!   `--yes`.
//! * 3: refused by policy: the command is well formed and its target
//!   exists, but a rule of the server refuses the change (a static
//!   account that only the configuration file may change, a limit that
//!   is reached, a setting the change depends on that is missing).
//!
//! A script can then tell "fix the command" (2) from "retry later" (1)
//! from "the server will not do this" (3). Policy refusals exited 2 until
//! the `--json` work split them out.

use std::process::ExitCode;

use crate::directory_store::StoreError;

/// The exit code for a usage error or a refusal.
pub(crate) const REFUSED: u8 = 2;

/// The exit code for a refusal by policy.
pub(crate) const POLICY: u8 = 3;

/// Print `message` as an error and return [`REFUSED`].
pub(crate) fn refused(message: impl std::fmt::Display) -> ExitCode {
	super::style::error(message);
	ExitCode::from(REFUSED)
}

/// Print `message` as an error and return [`POLICY`].
pub(crate) fn policy(message: impl std::fmt::Display) -> ExitCode {
	super::style::error(message);
	ExitCode::from(POLICY)
}

/// The exit code for a store error: the store refusing the request (an
/// unknown name, a duplicate, invalid input) is a refusal, a reached limit
/// is a refusal by policy; an I/O or database failure is an operation
/// failure.
pub(crate) fn for_store_error(error: &StoreError) -> ExitCode {
	match error {
		StoreError::LimitReached { .. } => ExitCode::from(POLICY),
		StoreError::NotFound(_) | StoreError::Duplicate(_) | StoreError::Invalid(_) => {
			ExitCode::from(REFUSED)
		}
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
