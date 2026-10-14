//! Per-sender vacation reply tracking (RFC 5230 section 4.2, RFC 8621
//! section 8): at most one auto-reply to one sender per period, kept on disk
//! so a restart does not reset it. One empty marker file per sender, named
//! by the SHA-256 of the lowercased address, under `<account>/.vacation/`;
//! its modification time is the last reply. The Sieve `vacation` action and
//! the JMAP `VacationResponse` share these markers.
//!
//! Every inbound message can create a marker, and the reverse-path is
//! whatever the sending client claimed, so the store is bounded and every
//! failure answers "do not reply": a reply that cannot be recorded would be
//! repeated for each message, which is the amplification this exists to
//! stop.

use std::fs;
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::util::path_component::AccountName;
use crate::util::path_containment::contained_child;

/// Most reply markers one account keeps. A sender past this while every
/// marker is still inside its period gets no reply.
pub(crate) const MAX_MARKERS: usize = 4096;

/// Shortest period honoured. Sieve allows `:days 0`, which would otherwise
/// answer every message.
const MIN_DAYS: u64 = 1;

/// Longest period honoured, so a marker never outlives a year.
const MAX_DAYS: u64 = 365;

/// Deliveries run on several threads; the check and the record must be one
/// step or two concurrent messages from one sender both get a reply.
static CLAIM: Mutex<()> = Mutex::new(());

/// Whether a reply to `sender` is due (none within `days`), recording it
/// when it is. `false` on any error.
pub(crate) fn claim(data_dir: &Path, account: &str, sender: &str, days: u64) -> bool {
	let period = Duration::from_secs(days.clamp(MIN_DAYS, MAX_DAYS) * 86_400);
	let Ok(account) = AccountName::new(account) else {
		return false;
	};
	let Ok(dir) = account
		.root(data_dir)
		.and_then(|root| root.file(".vacation"))
	else {
		return false;
	};
	let Ok(marker) = contained_child(&dir, &marker_name(sender)) else {
		return false;
	};
	let _guard = CLAIM.lock().unwrap_or_else(PoisonError::into_inner);
	let known = match fs::symlink_metadata(&marker) {
		Ok(meta) if !meta.is_file() => return false,
		Ok(meta) => {
			if meta
				.modified()
				.ok()
				.and_then(|at| at.elapsed().ok())
				.is_none_or(|age| age < period)
			{
				return false;
			}
			true
		}
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
		Err(_) => return false,
	};
	if fs::create_dir_all(&dir).is_err() || (!known && !make_room(&dir, period)) {
		return false;
	}
	fs::write(&marker, b"").is_ok()
}

/// Lowercase hex SHA-256 of the lowercased sender.
fn marker_name(sender: &str) -> String {
	let digest = ring::digest::digest(
		&ring::digest::SHA256,
		sender.to_ascii_lowercase().as_bytes(),
	);
	digest
		.as_ref()
		.iter()
		.fold(String::new(), |mut name, byte| {
			use std::fmt::Write;
			let _ = write!(name, "{byte:02x}");
			name
		})
}

/// Whether one more marker fits, removing markers older than `period` when
/// the store is full. A marker whose age cannot be read counts as recent.
fn make_room(dir: &Path, period: Duration) -> bool {
	let Ok(entries) = fs::read_dir(dir) else {
		return false;
	};
	let entries: Vec<_> = entries.flatten().collect();
	if entries.len() < MAX_MARKERS {
		return true;
	}
	let mut remaining = entries.len();
	for entry in entries {
		let expired = entry
			.metadata()
			.ok()
			.filter(fs::Metadata::is_file)
			.and_then(|meta| meta.modified().ok())
			.and_then(|at| at.elapsed().ok())
			.is_some_and(|age| age >= period);
		if expired && fs::remove_file(entry.path()).is_ok() {
			remaining -= 1;
		}
	}
	remaining < MAX_MARKERS
}
