//! The records a configuration needs, as `epistle dns-records --json` and
//! `GET /api/v1/dns/records` list them.
//!
//! The set itself is [`crate::dns::desired`]; this module is the part that
//! both callers share on top of it: the row they print and, for a caller
//! that sees only some domains, the cut that leaves out what belongs to the
//! mail host and to every tenant at once.

use serde::Serialize;

use crate::config::Config;
use crate::dns::desired::{self, Desired};
use crate::dns::provider::RecordKind;
use crate::dns::records::PublishRecord;
use crate::dns::skip::SkippedGroup;

/// One record as the JSON lists it: the name, the TTL, the type and the
/// value, a TXT value unsplit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
	/// The fully qualified name.
	pub name: String,
	/// The TTL in seconds.
	pub ttl: u32,
	/// The record type.
	#[serde(rename = "type")]
	pub kind: String,
	/// The value, in presentation form.
	pub value: String,
}

impl Row {
	/// The row of one record.
	pub fn of(entry: &PublishRecord) -> Self {
		let record = &entry.record;
		Row {
			name: record.name.clone(),
			ttl: record.ttl,
			kind: record.kind.as_str().to_string(),
			value: record.value.clone(),
		}
	}
}

/// The rows of `records`, in their order.
pub fn rows(records: &[PublishRecord]) -> Vec<Row> {
	records.iter().map(Row::of).collect()
}

/// Whether `entry` is a record of the mail host, shared by every domain it
/// serves, and not of one domain: the address records of the hostname and
/// the TLSA record of its port 25.
pub fn is_host_record(entry: &PublishRecord, hostname: &str) -> bool {
	let record = &entry.record;
	let host = hostname.to_ascii_lowercase();
	let name = record.name.to_ascii_lowercase();
	match record.kind {
		RecordKind::A | RecordKind::Aaaa => name == host,
		RecordKind::Tlsa => name == format!("_25._tcp.{host}"),
		_ => false,
	}
}

/// A group the configuration skips, and how many records it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
	/// The name the configuration writes for the group.
	pub group: &'static str,
	/// The records of the group that are not published.
	pub records: usize,
}

/// The records of some domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
	/// The records to publish.
	pub records: Vec<PublishRecord>,
	/// The groups the configuration skips.
	pub skipped: Vec<Skipped>,
	/// Whether every input could be read. A set that is not complete may
	/// lack a record the configuration needs.
	pub complete: bool,
	/// What could not be read, for the log. It names files, so it is not
	/// sent to a caller.
	pub warnings: Vec<String>,
}

/// The records `config` needs for `domains`, a subset of its hosted domains.
/// With `with_host` the records of the mail host are included, as they are
/// in the full set; without it only the records of the domains remain.
pub fn of_domains(
	config: &Config,
	domains: &[String],
	with_host: bool,
) -> Result<Listing, Vec<String>> {
	let Desired {
		records,
		warnings,
		skipped,
	} = desired::for_domains(config, domains)?;
	let keep = |entry: &PublishRecord| with_host || !is_host_record(entry, &config.hostname);
	Ok(Listing {
		records: records.into_iter().filter(|entry| keep(entry)).collect(),
		skipped: skipped_rows(&skipped, keep),
		complete: warnings.is_empty(),
		warnings,
	})
}

/// How many records each skipped group holds among those `keep` admits, the
/// groups left with none dropped. A group holding only the mail host's
/// record is not told to a caller that does not see the host.
fn skipped_rows(groups: &[SkippedGroup], keep: impl Fn(&PublishRecord) -> bool) -> Vec<Skipped> {
	groups
		.iter()
		.map(|group| Skipped {
			group: group.group.name(),
			records: group.records.iter().filter(|entry| keep(entry)).count(),
		})
		.filter(|group| group.records > 0)
		.collect()
}

#[cfg(test)]
mod tests;
