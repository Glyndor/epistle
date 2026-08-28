//! The `epistle` binary.
//!
//! Everything lives in the library crate: this parses the command line and
//! returns the exit code the chosen subcommand produced. Keeping it this thin
//! is what lets the integration tests drive the same code paths the binary
//! does, rather than a shell invoking a process.

// Every public item carries a doc comment as of #753, and this keeps it that
// way. Declared here rather than as a CI flag so it fails at the desk, in the
// same compile that introduced the gap, instead of ten minutes later in a job
// the author has stopped watching.
#![deny(missing_docs)]

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
	epistle::cli::Cli::parse().run()
}
