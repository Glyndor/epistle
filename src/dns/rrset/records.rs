//! The comparable form of the value of a record, and the equality of the
//! records a provider publishes.
//!
//! The value of a record is not always the text a provider lists: the
//! target of an MX, an SRV or a CNAME is a name, and two providers spell
//! the same record differently (case, the trailing root dot, the quoting
//! of a TXT). [`canonical_value`] puts a value in the comparable form of
//! its own type, and [`same_typed_record`] compares two records in every
//! attribute a provider publishes.

use crate::dns::names::{canonical_name, mx_parts, mx_target};
use crate::dns::provider::{DnsRecord, RecordKind};

/// Whether an MX value is the null MX (RFC 7505: preference 0, target `.`).
/// A bare `.` (a listing without the preference) counts too.
pub fn is_null_mx(value: &str) -> bool {
	matches!(mx_parts(value), Some((None | Some(0), "." | "")))
}

/// Whether two records are the same record: same name, same kind and the
/// same value. TXT values compare by their logical text (quoting and
/// 255-octet splitting do not count), MX by preference and target, so a
/// provider that lists `0 .` as a bare `.` still matches.
pub fn same_record(a: &DnsRecord, b: &DnsRecord) -> bool {
	if a.kind != b.kind || canonical_name(&a.name) != canonical_name(&b.name) {
		return false;
	}
	match a.kind {
		RecordKind::Txt => crate::dns::txt::same_txt_value(&a.value, &b.value),
		RecordKind::Mx => {
			(is_null_mx(&a.value) && is_null_mx(&b.value))
				|| (mx_preference(&a.value) == mx_preference(&b.value)
					&& mx_target(&a.value) == mx_target(&b.value))
		}
		_ => a.value.trim() == b.value.trim(),
	}
}

fn mx_preference(value: &str) -> Option<u16> {
	mx_parts(value)?.0
}

/// The comparable form of the value of a record of `kind`: the text two
/// providers may spell differently for the same record.
///
/// A TXT compares by its logical text (quoting and 255-octet splitting do
/// not count), an MX by preference and canonical target, an SRV by
/// priority, weight, port and canonical target, and a CNAME by its
/// canonical target. Every other value compares as the text it is, with
/// the surrounding whitespace removed.
pub fn canonical_value(kind: &RecordKind, value: &str) -> String {
	match kind {
		RecordKind::Txt => crate::dns::txt::txt_logical(value),
		RecordKind::Mx => canonical_mx(value),
		RecordKind::Srv => canonical_srv(value),
		RecordKind::Cname => canonical_target(value.trim()),
		_ => value.trim().to_string(),
	}
}

/// The comparable form of an MX value: the preference and the canonical
/// target. A value that is not an MX at all compares as its own text.
fn canonical_mx(value: &str) -> String {
	match mx_parts(value) {
		Some((Some(preference), target)) => format!("{preference} {}", canonical_target(target)),
		Some((None, target)) => canonical_target(target),
		None => value.trim().to_string(),
	}
}

/// The comparable form of an SRV value: priority, weight, port and the
/// canonical target. A value that is not an SRV at all compares as its own
/// text.
fn canonical_srv(value: &str) -> String {
	match crate::dns::provider::parse_srv(value) {
		Some((priority, weight, port, target)) => {
			format!("{priority} {weight} {port} {}", canonical_target(&target))
		}
		None => value.trim().to_string(),
	}
}

/// The comparable form of a target: the root stays the root, and every
/// other name loses its trailing dot and its case.
fn canonical_target(target: &str) -> String {
	if matches!(target, "." | "") {
		".".to_string()
	} else {
		canonical_name(target)
	}
}

/// Whether two records are the same in every attribute a provider
/// publishes: the same name, the same kind, the same value in the
/// comparable form of that kind, the same TTL and the same proxy state.
///
/// The proxy state is compared as it is: a provider that does not proxy
/// leaves it unset, and an unset state is never read as "not proxied".
pub fn same_typed_record(a: &DnsRecord, b: &DnsRecord) -> bool {
	a.kind == b.kind
		&& canonical_name(&a.name) == canonical_name(&b.name)
		&& canonical_value(&a.kind, &a.value) == canonical_value(&b.kind, &b.value)
		&& a.ttl == b.ttl
		&& a.proxied == b.proxied
}
