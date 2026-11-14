//! What one remote folder has already handed over, kept next to the progress
//! file so a rerun does not download it again.
//!
//! `<digest>.ledger` holds the UIDVALIDITY its records belong to and one fixed
//! record per confirmed message: its UID, the fingerprint of the identity the
//! deduplication index uses, and a checksum over the two. Records are appended
//! in UID order, so a lookup for a UID of a listing window binary searches for
//! the record at or after it and nothing is held in memory beyond one record. A
//! file whose records do not rise in UID order is refused when it is opened:
//! nothing but this code appends them, and it only appends them in that order.
//!
//! A run appends the messages of a batch once they are stored and
//! synchronized, and before the checkpoint that confirms that batch, so the
//! file can only be ahead of the progress file and never behind it. A record is
//! therefore never written for a message that is not in the local mailbox.
//!
//! Nothing is written for a source that announces no UIDVALIDITY, because its
//! UIDs carry no identity: those folders are matched against the local mailbox
//! on every run, as before. A source that changes UIDVALIDITY has its ledger
//! discarded with a warning, and the folder is read again from the start.

mod error;
mod file;
mod format;
mod opening;
mod reading;

use super::state_files;
use super::{ClientError, durability, metadata::Budget};

pub(super) use file::Ledger;
pub(super) use format::Fingerprint;
pub(super) use opening::{charge, open};

#[cfg(test)]
use std::io;

#[cfg(test)]
use std::os::unix::fs::FileExt;

#[cfg(test)]
use format::{HEADER, MAX_LEDGER_BYTES, RECORD, checksum, header};

#[cfg(test)]
use reading::READS;

#[cfg(test)]
mod tests;
