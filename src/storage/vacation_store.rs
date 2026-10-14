//! Per-account vacation autoresponse setting (RFC 8621 §8): the JMAP
//! `VacationResponse` object is the source of truth for an account's
//! vacation. The setting is stored in `<account>/.vacation.json` (an
//! account-local file that is never shared with another tenant and cannot
//! traverse outside it).
//!
//! Read returns the persisted singleton or the disabled default when the
//! file does not exist; write serialises the chosen setting through a
//! crash-safe write-temporary-then-rename dance. The reply sender reads
//! it for every inbound message, so reads are frequent and writes rare:
//! keeping the schema compact and parse-friendly is what costs.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::util::path_component::{AccountName, AccountRoot};

/// Maximum octets allowed for the `textBody` and `htmlBody` properties
/// (RFC 8621 §8.1: "a fixed maximum size chosen by the server"). 64 KiB is
/// far above a normal vacation reply and small enough to keep a single
/// message file bounded.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Every property a `VacationResponse` has (RFC 8621 §8.1). `id` is server
/// set; the rest mirror the JMAP surface one-for-one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VacationSetting {
	/// Whether the vacation is active at all.
	pub is_enabled: bool,
	/// Inclusive lower bound on the response window (RFC 8621 §8.1). `None`
	/// means "no start bound".
	pub from_date: Option<String>,
	/// Inclusive upper bound on the response window (RFC 8621 §8.1). `None`
	/// means "no end bound". Both unset means "always on when enabled".
	pub to_date: Option<String>,
	/// The reply subject. `None` falls back to `Auto: <original subject>`,
	/// matching the Sieve vacation's behaviour.
	pub subject: Option<String>,
	/// The reply body as plain text. Required by §8.1 when `isEnabled = true`.
	pub text_body: Option<String>,
	/// The reply body as HTML. Optional; the server stores it as given and
	/// never renders it.
	pub html_body: Option<String>,
}

impl VacationSetting {
	/// The disabled default: no reply is sent, no bounds are checked.
	pub const fn disabled() -> Self {
		Self {
			is_enabled: false,
			from_date: None,
			to_date: None,
			subject: None,
			text_body: None,
			html_body: None,
		}
	}

	/// Whether the window defined by `from_date` and `to_date` covers
	/// `now_unix_secs`. Both unset means "always". A single bound is honoured
	/// independently. A bound that fails to parse is treated as "always", so a
	/// corrupted clock skew does not strand an account.
	pub fn is_within_window(&self, now_unix_secs: u64) -> bool {
		if let Some(secs) = utc_date_to_unix_secs(self.from_date.as_deref())
			&& now_unix_secs < secs
		{
			return false;
		}
		if let Some(end) = self.to_date.as_deref()
			&& let Some(end_secs) = utc_date_to_unix_secs(Some(end))
			&& now_unix_secs > end_secs
		{
			return false;
		}
		true
	}
}

/// The on-disk path of an account's vacation JSON file.
pub fn vacation_file(data_dir: &Path, account: &str) -> io::Result<PathBuf> {
	let root: AccountRoot = AccountName::new(account)?.root(data_dir)?;
	root.file(".vacation.json")
}

/// Read the account's stored setting, or the disabled default when the file
/// is missing. A parse error is propagated so an unreadable file does not
/// silently disable the user's auto-responder.
pub fn read(data_dir: &Path, account: &str) -> io::Result<VacationSetting> {
	let path = vacation_file(data_dir, account)?;
	match fs::read(&path) {
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(VacationSetting::disabled()),
		Err(error) => Err(error),
		Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
	}
}

/// Persist `setting` for `account`, owner-only, through a uniquely named
/// sibling temporary file renamed into place, so a crash leaves either the
/// old file or the new one, never a half-written one a concurrent reader
/// could parse as JSON and trust.
pub fn write(data_dir: &Path, account: &str, setting: &VacationSetting) -> io::Result<()> {
	let path = vacation_file(data_dir, account)?;
	if let Some(parent) = path.parent() {
		fs::create_dir_all(parent)?;
	}
	let bytes = serde_json::to_vec(setting).map_err(io::Error::other)?;
	super::write_secret(&path, &bytes)
}

/// Wipe the stored setting (revert to the disabled default).
pub fn clear(data_dir: &Path, account: &str) -> io::Result<()> {
	let path = vacation_file(data_dir, account)?;
	match fs::remove_file(&path) {
		Ok(()) => Ok(()),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
		Err(error) => Err(error),
	}
}

/// Parse a UTCDate (`YYYY-MM-DDThh:mm:ss[.fraction]Z`, RFC 8620 §1.4) to
/// Unix seconds. A malformed value yields `None`, which callers map to
/// "ignore this bound".
pub(crate) fn utc_date_to_unix_secs(value: Option<&str>) -> Option<u64> {
	let text = value?;
	let body = text.strip_suffix('Z')?;
	let (clock, fraction) = body.split_once('.').unwrap_or((body, ""));
	if fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
		return None;
	}
	let bytes = clock.as_bytes();
	if bytes.len() != 19 || !clock.is_ascii() {
		return None;
	}
	for &(at, sep) in &[(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')] {
		if bytes[at] != sep {
			return None;
		}
	}
	let digits = |part: &str| part.parse::<u32>().ok();
	let (Some(y), Some(m), Some(d), Some(h), Some(min), Some(s)) = (
		digits(&clock[0..4]),
		digits(&clock[5..7]),
		digits(&clock[8..10]),
		digits(&clock[11..13]),
		digits(&clock[14..16]),
		digits(&clock[17..19]),
	) else {
		return None;
	};
	if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || min > 59 || s > 59 {
		return None;
	}
	// A day past the end of the month (`2030-02-30`) rolls into the next
	// month on the way through days-since-epoch; the round trip catches it
	// without us having to enumerate month lengths.
	let days = crate::webdav::rrule::days_from_civil(y as i64, m as i64, d as i64);
	if crate::webdav::rrule::civil_from_secs(days * 86_400) != (y as i64, m as i64, d as i64) {
		return None;
	}
	let day_secs = days.checked_mul(86_400)?;
	let secs = day_secs
		.checked_add((h as i64) * 3600)?
		.checked_add((min as i64) * 60)?
		.checked_add(s as i64)?;
	let frac_secs: u64 = if fraction.is_empty() {
		0
	} else {
		// Pad the parsed fraction to nanoseconds.
		let nanos: u64 = fraction.parse().ok()?;
		let pad = 9 - fraction.len() as u32;
		nanos.saturating_mul(10u64.pow(pad))
	};
	let total = (secs as u64).saturating_add(frac_secs / 1_000_000_000);
	if total == u64::MAX {
		return None;
	}
	Some(total)
}

#[cfg(test)]
#[path = "vacation_store_tests.rs"]
mod tests;
