//! The DANE half of the `tls` check: does the TLSA record published at
//! `_25._tcp.<hostname>` match the certificate in use?

use super::report::{Item, Level};
use crate::dane::policy::DaneOutcome;
use crate::dane::rrset::TlsaRrset;
use crate::spf::DnsLookup;

/// Compare the TLSA RRset of the mail host with `chain` (DER, leaf first).
/// `None` when no secure RRset exists: DANE does not apply then. A record
/// that matches nothing fails, because DANE senders then refuse to deliver.
pub(super) async fn tlsa_item(
	hostname: &str,
	chain: &[Vec<u8>],
	dns: &dyn DnsLookup,
) -> Option<Item> {
	let name = format!("_25._tcp.{hostname}");
	let records = match dns.tlsa(&name).await {
		Ok(TlsaRrset::Absent) => return None,
		Ok(rrset) => rrset.records().to_vec(),
		Err(_) => {
			return Some(Item::new(
				"tlsa",
				Level::Warn,
				format!("{name} TLSA could not be looked up"),
			));
		}
	};
	if crate::dane::verify::verify_chain(&records, chain) == DaneOutcome::Authenticated {
		return Some(Item::new(
			"tlsa",
			Level::Ok,
			format!("{name} TLSA matches the certificate in use"),
		));
	}
	let wanted = chain
		.first()
		.map(|leaf| {
			let digest = ring::digest::digest(&ring::digest::SHA256, leaf);
			let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
			format!("3 0 1 {hex}")
		})
		.unwrap_or_default();
	Some(Item::new(
		"tlsa",
		Level::Fail,
		format!(
			"{name} TLSA does not match the certificate in use, so DANE senders refuse mail; publish {wanted}"
		),
	))
}

/// The TLSA publication the server owes the zone, when a DNS failure left
/// one: since when, how many attempts failed, why, and that it is retried.
/// `None` when nothing is owed.
pub(super) fn pending_item(data_dir: &std::path::Path, hostname: &str, now: i64) -> Option<Item> {
	let pending = crate::dns::tlsa::State::load(data_dir, hostname).pending?;
	let since = i64::try_from(pending.since).unwrap_or(i64::MAX);
	let hours = (now - since).max(0) / 3600;
	let wait = i64::try_from(pending.next_attempt).unwrap_or(i64::MAX) - now;
	let retry = if wait > 0 {
		format!("the next attempt is in {wait} s")
	} else {
		"the next attempt is due".to_string()
	};
	Some(Item::new(
		"tlsa-pending",
		Level::Warn,
		format!(
			"the TLSA record for _25._tcp.{hostname} is not published since {hours} h; {} attempts failed ({}); {retry}; the value is {}",
			pending.attempts,
			crate::cli::term::sanitize(&pending.reason),
			pending.value,
		),
	))
}
