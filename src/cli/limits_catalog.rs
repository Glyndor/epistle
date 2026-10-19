//! The catalog that `epistle limits show` enumerates.
//!
//! Every operational limit on the server has one row here: the keys the
//! operator may set through `epistle limits set`, plus the standards the
//! RFC makes mandatory and the server cannot relax. The catalog is the
//! single source of truth for `show` (text and `--json`), the MUST/SHOULD
//! checks in `set`, and the docs page
//! (`docs/limits.md`, asserted by a test).

use super::Key;

/// What the operator may do with a limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
	/// Operator may change the value; the server takes whatever it can
	/// pass the `validate()` floors of [`Config`].
	Adjustable,
	/// The standard recommends a floor (or ceiling) but lets the server
	/// cross it; `limits set` accepts the value and prints a one-line
	/// warning naming the RFC recommendation.
	Recommended,
	/// The standard forbids the limit being crossed (MUST); the value is
	/// hard-coded in the server. `limits show` lists it so the operator
	/// sees what the server enforces, but `limits set` rejects any
	/// attempt to override it.
	#[allow(dead_code)] // Reserved for MUST-grade keys; today every
	// adjustable entry is either adjustable (no
	// standard mandate) or recommended (operator may
	// set it with a warning). Reachable through `match`
	// on `kind` in the snapshot helper.
	Fixed,
}

/// A bound the RFC puts on a limit: either a floor (`AtLeast`) the value
/// must stay above, or a ceiling (`AtMost`) it must stay below. The
/// `text` is the human-readable bound (e.g. "100") and `rfc_reason` is
/// the section that requires it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // AtMost is reserved for future ceiling-style limits; only the doc test exercises it.
pub(super) enum Bound {
	/// The value must be at least this high; below it is forbidden or
	/// advised against.
	AtLeast(u64),
	/// The value must be at most this high; above it is forbidden or
	/// advised against.
	AtMost(u64),
}

/// One row of the catalog: a key the operator can adjust through
/// `epistle limits set`. The metadata drives `show`, `set` and the
/// JSON output.
#[derive(Clone, Copy, Debug)]
pub(super) struct Adjustable {
	pub(super) key: Key,
	pub(super) kind: Kind,
	pub(super) bound: Option<Bound>,
	pub(super) reference: &'static str,
}

/// One row of the catalog for a limit the operator cannot change: the
/// server enforces it because the RFC makes it mandatory (MUST). The
/// `fixed` form is listed read-only so the limits page reflects what
/// the server actually enforces, not just what is configurable.
#[derive(Clone, Copy, Debug)]
pub(super) struct FixedEntry {
	pub(super) name: &'static str,
	pub(super) value: &'static str,
	pub(super) unit: &'static str,
	pub(super) reference: &'static str,
}

/// Every adjustable key, in the order `show` prints them.
pub(super) const ADJUSTABLE: &[Adjustable] = &[
	Adjustable {
		key: Key::Quota,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::SubmissionRate,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::NewRecipientsPerDay,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::QueueGiveUp,
		kind: Kind::Recommended,
		bound: Some(Bound::AtLeast(crate::queue::schedule::SHOULD_GIVE_UP_SECS)),
		reference: "RFC 5321 §4.5.4.1 (4-5 days recommended)",
	},
	Adjustable {
		key: Key::QueueRetryBase,
		kind: Kind::Recommended,
		bound: Some(Bound::AtLeast(
			crate::queue::schedule::SHOULD_RETRY_BASE_SECS,
		)),
		reference: "RFC 5321 §4.5.4.1 (30 minutes recommended)",
	},
	Adjustable {
		key: Key::QueueRetryCap,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::QueueDelayWarning,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::InboundRatePerIp,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::InboundRatePerSender,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::MaxConnectionsPerListener,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::MaxConnectionsPerIp,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::MaskedAddressesMax,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::FirstTimeSenderDelay,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::GreylistDelay,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::QueueConcurrency,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::QueuePerDomainConcurrency,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::QueueBackoff,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::MaxMessageSize,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::MaxRecipients,
		kind: Kind::Recommended,
		bound: Some(Bound::AtLeast(
			crate::smtp::session::MIN_MAX_RECIPIENTS as u64,
		)),
		reference: "RFC 5321 §4.5.3.1.8 (at least 100)",
	},
	Adjustable {
		key: Key::MessageMemoryBudget,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::MinDataRate,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::DataRateGrace,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::JunkCommandLimit,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::MaxSessionTime,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::PreauthTimeout,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::MaxMailboxConnectionsPerIp,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::MaxHttpConnections,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::MaxHttpConnectionsPerIp,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
];

/// The standards the server enforces because the RFC requires it. Listed
/// read-only: `limits show` includes them so the operator sees what is
/// in force, but `limits set` has no path to override them.
pub(super) const FIXED: &[FixedEntry] = &[
	FixedEntry {
		name: "smtp-line-length",
		value: "998",
		unit: "octets",
		reference: "RFC 5321 §4.5.3.1.6 (998 octets excl. CRLF; 1000 incl. CRLF)",
	},
	FixedEntry {
		name: "smtp-command-minimum-timeout",
		value: "300",
		unit: "seconds",
		reference: "RFC 5321 §4.5.3.2 (5 minute minimum)",
	},
	FixedEntry {
		name: "smtp-never-bounce-a-bounce",
		value: "true",
		unit: "boolean",
		reference: "RFC 5321 §5.3.3 (no bounce of a bounce)",
	},
	FixedEntry {
		name: "spf-max-dns-lookups",
		value: "10",
		unit: "count",
		reference: "RFC 7208 §4.6.4 (max 10 DNS-querying terms)",
	},
	FixedEntry {
		name: "spf-max-void-lookups",
		value: "2",
		unit: "count",
		reference: "RFC 7208 §4.6.4 (max 2 void lookups)",
	},
	FixedEntry {
		name: "tls-minimum-version",
		value: "1.2",
		unit: "version",
		reference: "RFC 8996 (TLS 1.0/1.1 prohibited)",
	},
];

/// The default value of every adjustable key. The docs page uses this to
/// print the same numbers the server reports.
#[allow(dead_code)] // The docs page is hand-maintained today and reuses Key::default_value directly.
pub(super) fn adjustable_default(entry: &Adjustable) -> Option<u64> {
	entry.key.default_value()
}

/// One row of the catalog exposed for the integration test that keeps
/// `docs/limits.md` in lockstep with the in-process catalog. The struct
/// lives in `pub` so a closed-over copy in `tests/limits_docs.rs` can
/// read it without depending on the catalog's internal types; every
/// other consumer goes through `show` / `show_json`, which carry the
/// same data through the CLI surface the operator already uses.
#[doc(hidden)]
#[allow(dead_code)]
pub struct DocsRow {
	pub name: &'static str,
	pub kind: &'static str,
	pub unit: &'static str,
	pub reference: &'static str,
	pub default: Option<&'static str>,
	pub bounds: Option<&'static str>,
	pub value: Option<&'static str>,
}

/// Every catalog row as a `Vec` of `DocsRow`. Hidden from the public docs
/// but reachable from integration tests through the `#[doc(hidden)]`
/// declaration on `DocsRow`. The order matches the printed catalog.
#[doc(hidden)]
#[allow(dead_code)]
pub fn docs_snapshot() -> Vec<DocsRow> {
	let mut rows = Vec::with_capacity(ADJUSTABLE.len() + FIXED.len());
	for entry in ADJUSTABLE {
		rows.push(DocsRow {
			name: entry.key.name(),
			kind: kind_label(entry.kind),
			unit: unit_label(entry.key.unit()),
			reference: entry.reference,
			default: entry.key.default_value().map(value_label),
			bounds: entry.bound.map(bound_label),
			value: None,
		});
	}
	for fixed in FIXED {
		rows.push(DocsRow {
			name: fixed.name,
			kind: "fixed",
			unit: fixed.unit,
			reference: fixed.reference,
			default: None,
			bounds: None,
			value: Some(fixed.value),
		});
	}
	rows
}

#[doc(hidden)]
#[allow(dead_code)]
fn kind_label(kind: Kind) -> &'static str {
	match kind {
		Kind::Adjustable => "adjustable",
		Kind::Recommended => "recommended",
		Kind::Fixed => "fixed",
	}
}

#[doc(hidden)]
#[allow(dead_code)]
fn unit_label(unit: super::values::Unit) -> &'static str {
	match unit {
		super::values::Unit::Size => "bytes",
		super::values::Unit::Rate => "bytes-per-second",
		super::values::Unit::Duration => "seconds",
		super::values::Unit::Count => "count",
	}
}

#[doc(hidden)]
#[allow(dead_code)]
fn value_label(value: u64) -> &'static str {
	// The `default_value` of every adjustable key fits in `u64`; the
	// box is opaque to the operator so a plain decimal form is enough.
	// We leak a small `String` per unique value to obtain a
	// `'static str`; the snapshot is built once per test process and
	// never mutated, so the leak is bounded.
	let rendered = value.to_string();
	Box::leak(rendered.into_boxed_str())
}

#[doc(hidden)]
#[allow(dead_code)]
fn bound_label(bound: Bound) -> &'static str {
	let rendered = match bound {
		Bound::AtLeast(value) => format!("at-least {value}"),
		Bound::AtMost(value) => format!("at-most {value}"),
	};
	Box::leak(rendered.into_boxed_str())
}
