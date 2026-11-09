//! Which group a record, or a checked record, belongs to.
//!
//! The classification is by the record itself: the type, and the label the
//! name carries. A record in no group is a core record (MX, SPF, DKIM,
//! DMARC or the addresses of the mail host) and is never skipped.

use crate::dns::names::canonical_name;
use crate::dns::provider::{DnsRecord, RecordKind};

use super::SkipGroup;

/// The group a record belongs to, `None` when it is in no group.
pub fn group_of_record(record: &DnsRecord) -> Option<SkipGroup> {
	match record.kind {
		// Every SRV record epistle publishes is a client locator.
		RecordKind::Srv => Some(SkipGroup::ClientLocators),
		RecordKind::Tlsa => Some(SkipGroup::Tlsa),
		RecordKind::Caa => Some(SkipGroup::Caa),
		RecordKind::Txt => txt_group(&canonical_name(&record.name)),
		RecordKind::Cname => cname_group(&canonical_name(&record.name)),
		_ => None,
	}
}

/// The group of a TXT record: the MTA-STS discovery record or the TLS-RPT
/// record. The DKIM, SPF and DMARC records are in no group.
fn txt_group(name: &str) -> Option<SkipGroup> {
	if name.starts_with("_mta-sts.") {
		Some(SkipGroup::MtaSts)
	} else if name.starts_with("_smtp._tls.") {
		Some(SkipGroup::TlsRpt)
	} else {
		None
	}
}

/// The group of a CNAME record: the name the MTA-STS policy is fetched
/// from, or one of the two names that reach the client setup documents.
fn cname_group(name: &str) -> Option<SkipGroup> {
	match name.split('.').next().unwrap_or_default() {
		"mta-sts" => Some(SkipGroup::MtaSts),
		"autoconfig" | "autodiscover" => Some(SkipGroup::ClientLocators),
		_ => None,
	}
}

/// The group a checked record belongs to. The label is the one the check
/// carries (`MTA-STS`), the name the one it looked up. Only the checks that
/// exist today are covered: the record set the checks look at is the core
/// one, and the MTA-STS record is the only record of a group in it.
pub fn group_of_check(kind: &str, name: &str) -> Option<SkipGroup> {
	match kind {
		"MTA-STS" if canonical_name(name).starts_with("_mta-sts.") => Some(SkipGroup::MtaSts),
		_ => None,
	}
}
