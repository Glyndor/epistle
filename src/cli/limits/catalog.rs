//! The catalog that `epistle limits show` enumerates.
//!
//! Every operational limit on the server has one row here: the keys the
//! operator may set through `epistle limits set`, plus the protocol limits
//! a client can run into that the server hard-codes (`protocol.rs`).
//! The catalog is the
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
	/// The standard recommends a floor (SHOULD) but lets the server cross
	/// it; `limits set` accepts the value and prints a one-line warning
	/// naming the RFC recommendation.
	Recommended,
	/// The standard makes a floor mandatory (MUST): the operator may raise
	/// the value but `limits set` refuses anything below the RFC minimum.
	Must,
	/// The value is hard-coded in the server. `limits show` lists it so the
	/// operator sees what the server enforces, but `limits set` has no
	/// path to change it.
	Fixed,
}

/// How strongly a limit is tied to a standard: a MUST, a SHOULD, or a
/// bound epistle picked itself (no standard mandates it, or the standard
/// leaves the number to the implementation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
	Must,
	Should,
	Own,
}

impl Class {
	pub(super) fn label(self) -> &'static str {
		match self {
			Self::Must => "must",
			Self::Should => "should",
			Self::Own => "own",
		}
	}
}

impl Kind {
	/// The class an adjustable row belongs to, from how `set` treats it.
	pub(super) fn class(self) -> Class {
		match self {
			Self::Adjustable | Self::Fixed => Class::Own,
			Self::Recommended => Class::Should,
			Self::Must => Class::Must,
		}
	}
}

/// A floor the RFC puts on a limit: the value must stay at or above it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Bound {
	/// The value must be at least this high; below it is forbidden (MUST)
	/// or advised against (SHOULD).
	AtLeast(u64),
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

/// The value of a limit the operator cannot change. A number is read
/// from the constant the server enforces, so the catalog cannot say one
/// thing while the code does another. `Text` is a rule that is not a
/// number in the code (the null reverse path never gets a bounce).
#[derive(Clone, Copy, Debug)]
pub(super) enum FixedValue {
	Number(u64),
	Text(&'static str),
	/// The oldest TLS version a listener negotiates, read from the list
	/// every acceptor is built with.
	TlsMinimum,
}

impl FixedValue {
	pub(super) fn render(self) -> String {
		match self {
			Self::Number(value) => value.to_string(),
			Self::Text(text) => text.to_string(),
			Self::TlsMinimum => tls_minimum(),
		}
	}
}

/// The oldest of [`crate::tls::PROTOCOL_VERSIONS`] as `1.2` or `1.3`.
fn tls_minimum() -> String {
	let oldest = crate::tls::PROTOCOL_VERSIONS
		.iter()
		.map(|version| u16::from(version.version))
		.min()
		.unwrap_or(0);
	match oldest {
		0x0303 => "1.2".into(),
		0x0304 => "1.3".into(),
		other => format!("{other:#06x}"),
	}
}

/// One row of the catalog for a limit the operator cannot change: the
/// server enforces it as a MUST, a SHOULD or a bound of its own, and
/// `class` says which. The row is listed read-only so the limits page
/// reflects what the server actually enforces, not just what is
/// configurable.
#[derive(Clone, Copy, Debug)]
pub(super) struct FixedEntry {
	pub(super) name: &'static str,
	pub(super) value: FixedValue,
	pub(super) unit: &'static str,
	pub(super) class: Class,
	pub(super) reference: &'static str,
	/// The path of the constant the value is read from, as written in
	/// `protocol.rs`; empty for a rule that is not a constant.
	#[allow(dead_code)] // Read by the tests that tie each row to its constant.
	pub(super) source: &'static str,
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
		key: Key::MaxConnectionsPerAccountPerIp,
		kind: Kind::Adjustable,
		bound: None,
		reference: "no standard mandate",
	},
	Adjustable {
		key: Key::MaxConnectionsPerAccountTotal,
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
		kind: Kind::Must,
		bound: Some(Bound::AtLeast(
			crate::smtp::session::MIN_MESSAGE_SIZE as u64,
		)),
		reference: "RFC 5321 §4.5.3.1.7 (at least 64K octets)",
	},
	Adjustable {
		key: Key::MaxRecipients,
		kind: Kind::Must,
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
		key: Key::KnownNetworkWindow,
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

pub(super) use super::protocol::FIXED;

/// The default value of every adjustable key. The docs page uses this to
/// print the same numbers the server reports.
#[allow(dead_code)] // The docs page is hand-maintained today and reuses Key::default_value directly.
pub(super) fn adjustable_default(entry: &Adjustable) -> Option<u64> {
	entry.key.default_value()
}

/// One row of the catalog exposed for the integration test that keeps
/// `docs/limits.md` in lockstep with the in-process catalog. The struct
/// lives in `pub` so a closed-over copy in `tests/contracts/limits_docs.rs` can
/// read it without depending on the catalog's internal types; every
/// other consumer goes through `show` / `show_json`, which carry the
/// same data through the CLI surface the operator already uses.
#[doc(hidden)]
#[allow(dead_code)]
pub struct DocsRow {
	pub name: &'static str,
	pub kind: &'static str,
	pub unit: &'static str,
	pub class: &'static str,
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
			class: entry.kind.class().label(),
			reference: entry.reference,
			default: entry.key.default_value().map(value_label),
			bounds: entry.bound.map(bound_label),
			value: None,
		});
	}
	for fixed in FIXED {
		rows.push(DocsRow {
			name: fixed.name,
			kind: kind_label(Kind::Fixed),
			unit: fixed.unit,
			class: fixed.class.label(),
			reference: fixed.reference,
			default: None,
			bounds: None,
			value: Some(value_text(fixed.value)),
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
		Kind::Must => "must",
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
fn value_text(value: FixedValue) -> &'static str {
	Box::leak(value.render().into_boxed_str())
}

#[doc(hidden)]
#[allow(dead_code)]
fn bound_label(bound: Bound) -> &'static str {
	let rendered = match bound {
		Bound::AtLeast(value) => format!("at-least {value}"),
	};
	Box::leak(rendered.into_boxed_str())
}
