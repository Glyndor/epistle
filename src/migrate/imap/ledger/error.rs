//! The refusals of the ledger: a file that cannot be read, one that is too
//! large, a batch that does not rise and a file another run is writing.

use std::io;
use std::path::Path;

use super::format::MAX_LEDGER_BYTES;

/// A ledger that cannot be read stops the run where it is: the message names
/// the file, what the run had already imported, and how to start over.
pub(super) fn corrupt(path: &Path, detail: &str) -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidData,
		format!(
			"the migration ledger {} cannot be read, {detail}; the messages imported up to this point stay imported and nothing is removed: delete that file to copy this folder again",
			path.display()
		),
	)
}

/// A ledger past its size bound: the same refusal, with the bound named.
pub(super) fn too_large(path: &Path) -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidData,
		format!(
			"the migration ledger {} holds more than {MAX_LEDGER_BYTES} bytes of confirmed messages; the messages imported up to this point stay imported and nothing is removed: delete that file to copy this folder again",
			path.display()
		),
	)
}

/// A batch whose UIDs do not rise, refused before anything is written: the
/// scan that reads the file would not find them afterwards.
pub(super) fn out_of_order(path: &Path) -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidData,
		format!(
			"the migration ledger {} was handed records that do not rise in UID order; nothing was written and nothing is removed: delete that file to copy this folder again",
			path.display()
		),
	)
}

/// A file that no longer holds what this run read from it, so another run is
/// appending to it: refuse before overwriting what is there.
pub(super) fn rewritten(path: &Path) -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidData,
		format!(
			"the migration ledger {} no longer holds what this run read from it, so another run is writing it; nothing was written and nothing is removed: wait for that run to finish and run one migration of this account at a time",
			path.display()
		),
	)
}
