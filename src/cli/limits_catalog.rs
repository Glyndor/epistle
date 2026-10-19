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
		kind: Kind::Fixed,
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
		reference: "RFC 5321 §4.5.3.1.4 (998 octets incl. CRLF)",
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
